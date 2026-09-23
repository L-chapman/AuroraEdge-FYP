from typing import Dict, Set, Tuple, List, Optional
import re
import socket
import ssl
import logging
import http.client
import ipaddress
import threading
import time
import base64
import binascii
from contextvars import ContextVar
from urllib.parse import urlsplit

# Configure module logger
logger = logging.getLogger("northflux.scanner")

# Import optional external dependencies safely so tests can run even when
# the environment doesn't have all packages installed.
try:
    import dns.resolver
except Exception:
    dns = None

try:
    import requests
except Exception:
    requests = None

RESOLVER_TIMEOUT = 3.0
HTTP_TIMEOUT = 5.0
SMTP_TIMEOUT = 10.0
SCAN_TIMEOUT = 30.0
MAX_SPF_RECURSION = 10
MAX_SPF_FETCHES = 50
_SCAN_ERRORS = ContextVar("northflux_scan_errors", default=None)
_SCAN_DEADLINE = ContextVar("northflux_scan_deadline", default=None)


def _scan_error(message: str) -> None:
    errors = _SCAN_ERRORS.get()
    if errors is not None and message not in errors:
        errors.append(message)


def _remaining_timeout(requested: float) -> float:
    deadline = _SCAN_DEADLINE.get()
    remaining = requested if deadline is None else min(requested, deadline - time.monotonic())
    if remaining <= 0:
        _scan_error("Scan time limit reached; some checks could not be completed")
        raise TimeoutError("Scan time limit reached")
    return remaining


def _fresh_resolver() -> "dns.resolver.Resolver":
    """Use bounded public DNS resolution with a private per-call cache.

    Cloudflare (1.1.1.1) and Google (8.8.8.8) may still return cached answers;
    a fresh local resolver does not guarantee immediate DNS propagation.
    """
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.lifetime = _remaining_timeout(RESOLVER_TIMEOUT)
    r.timeout = r.lifetime
    r.cache = dns.resolver.Cache()  # private cache, no sharing
    return r

# STARTTLS grade thresholds
STARTTLS_GRADES = {
    "A+": "TLS 1.3 with strong cipher",
    "A": "TLS 1.2/1.3 with secure cipher",
    "B": "TLS 1.2 with acceptable cipher",
    "C": "TLS 1.1 or weak cipher",
    "D": "TLS 1.0 or deprecated cipher",
    "F": "No STARTTLS or connection failed",
}

SELECTOR_CANDIDATES: List[str] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "mail",
    "smtp",
    "mandrill",
    "sendgrid",
    "zoho",
    "amazonses",
    "mailgun",
    "mg",
    "postfix",
    "sparkpost",
    "mailchimp",
    "klaviyo",
    "dkim",
    "protonmail",
    "fm1",
    "fm2",
    "fm3",
    "mxvault",
    "everlytickey1",
    "everlytickey2",
    "cm",
    "turbo-smtp",
]


# Simple domain format regex (RFC 1035 labels, no scheme/path)
# TLD must contain at least one letter (rejects bare IPs like 127.0.0.1)
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.(?!-)[A-Za-z][A-Za-z0-9-]{0,62}(?<!-)$"
)


def is_valid_domain(domain: str) -> bool:
    """Check if a string looks like a valid domain name."""
    return isinstance(domain, str) and len(domain) <= 253 and bool(_DOMAIN_RE.fullmatch(domain))


def _public_addresses(host: str) -> List[str]:
    """Resolve once with bounded DNS queries; reject private/mixed destinations."""
    if dns is None or not is_valid_domain(host):
        raise ValueError("A valid public hostname is required")
    addresses = []
    resolver = _fresh_resolver()
    for kind in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, kind, lifetime=_remaining_timeout(RESOLVER_TIMEOUT))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        for record in answer:
            address = ipaddress.ip_address(str(record))
            if (not address.is_global or address.is_multicast or address.is_reserved
                    or (address.version == 6 and address.ipv4_mapped is not None)):
                raise ValueError("Private or special-purpose network destinations are not scanned")
            addresses.append(str(address))
    if not addresses:
        raise ValueError("No public address found")
    return list(dict.fromkeys(addresses))[:4]


def _connect_public(host: str, port: int, timeout: float):
    """Connect to an already-vetted numeric address, preventing DNS rebinding."""
    address = _public_addresses(host)[0]
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    try:
        connection.settimeout(_remaining_timeout(timeout))
        connection.connect((address, port))
        return connection
    except Exception:
        connection.close()
        raise


def _socket_deadline(connection, seconds: float):
    """Stop slow-drip peers as well as peers that send nothing at all."""
    def expire():
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    timer = threading.Timer(_remaining_timeout(seconds), expire)
    timer.daemon = True
    timer.start()
    return timer


def _smtp_reply(connection) -> Tuple[int, List[str]]:
    """Read one bounded SMTP reply, including fragmented/multiline replies."""
    pending = b""
    lines = []
    code = None
    received = 0
    while True:
        if b"\r\n" not in pending:
            chunk = connection.recv(4096)
            if not chunk:
                raise ValueError("SMTP connection closed before a complete reply")
            pending += chunk
            received += len(chunk)
            if received > 16_384:
                raise ValueError("SMTP reply exceeds the scan limit")
            continue
        line, pending = pending.split(b"\r\n", 1)
        if not re.fullmatch(rb"[2-5][0-9]{2}(?:[ -][^\r\n]*)?", line):
            raise ValueError("Malformed SMTP reply")
        current = int(line[:3])
        if code is not None and current != code:
            raise ValueError("Inconsistent SMTP multiline reply codes")
        code = current
        lines.append(line[4:].decode("ascii", errors="replace"))
        if len(line) == 3 or line[3:4] == b" ":
            if pending:
                raise ValueError("Unexpected data after SMTP reply")
            return code, lines


def _starttls_check(mx_host: str, port: int = 25) -> Tuple[str, str, str]:
    """
    Attempt STARTTLS handshake with MX server and grade the connection.
    Returns: (grade, tls_version, cipher_info)
    """
    try:
        # Connect to SMTP server
        sock = _connect_public(mx_host, port, SMTP_TIMEOUT)
        deadline = None
        try:
            deadline = _socket_deadline(sock, SMTP_TIMEOUT)
            sock.settimeout(_remaining_timeout(SMTP_TIMEOUT))

            # Read banner
            banner_code, _ = _smtp_reply(sock)
            if banner_code != 220:
                return ("F", "", "No valid SMTP banner")

            # Send EHLO
            sock.sendall(b"EHLO northflux.local\r\n")
            ehlo_code, ehlo_lines = _smtp_reply(sock)

            # Check for STARTTLS support
            if ehlo_code != 250 or not any(line.upper() == "STARTTLS" for line in ehlo_lines):
                return ("F", "", "STARTTLS not advertised")

            # Send STARTTLS command
            sock.sendall(b"STARTTLS\r\n")
            starttls_code, _ = _smtp_reply(sock)

            if starttls_code != 220:
                return ("F", "", "STARTTLS rejected")

            # Create SSL context and wrap socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We're testing capability, not cert validity

            sock.settimeout(_remaining_timeout(SMTP_TIMEOUT))
            ssl_sock = context.wrap_socket(sock, server_hostname=mx_host)

            # Get TLS version and cipher
            tls_version = ssl_sock.version()
            cipher = ssl_sock.cipher()
            cipher_name = cipher[0] if cipher else "unknown"
            cipher_bits = cipher[2] if cipher and len(cipher) > 2 else 0

            ssl_sock.close()
            sock = None  # ssl_sock.close() also closes underlying socket

            # Grade the connection
            grade = "F"
            if tls_version == "TLSv1.3":
                grade = "A+" if cipher_bits >= 256 else "A"
            elif tls_version == "TLSv1.2":
                if cipher_bits >= 256:
                    grade = "A"
                elif cipher_bits >= 128:
                    grade = "B"
                else:
                    grade = "C"
            elif tls_version == "TLSv1.1":
                grade = "C"
            elif tls_version == "TLSv1":
                grade = "D"

            return (grade, tls_version or "", f"{cipher_name} ({cipher_bits}-bit)")
        finally:
            if deadline is not None:
                deadline.cancel()
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    except socket.timeout:
        _scan_error(f"STARTTLS check could not be completed for {mx_host}: connection timeout")
        return ("F", "", "Connection timeout")
    except ConnectionRefusedError:
        _scan_error(f"STARTTLS check could not be completed for {mx_host}: connection refused")
        return ("F", "", "Connection refused")
    except Exception as e:
        _scan_error(f"STARTTLS check could not be completed for {mx_host}: connection or TLS error")
        logger.debug("STARTTLS check failed for %s: %s", mx_host, e)
        return ("F", "", f"Error: {str(e)[:50]}")


def _check_mx_starttls(domain: str, mx_hosts: List[str]) -> Tuple[str, str, List[Dict]]:
    """
    Check STARTTLS on all MX hosts and return aggregate grade.
    Returns: (best_grade, worst_grade, details_list)
    """
    if not mx_hosts:
        return ("F", "F", [])

    details = []
    grades = []

    for mx in mx_hosts[:3]:  # Check up to 3 MX servers
        grade, tls_ver, cipher_info = _starttls_check(mx)
        grades.append(grade)
        details.append(
            {
                "host": mx,
                "grade": grade,
                "tls_version": tls_ver,
                "cipher": cipher_info,
            }
        )

    # Grade ordering for comparison
    grade_order = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
    sorted_grades = sorted(grades, key=lambda g: grade_order.get(g, 0), reverse=True)

    best = sorted_grades[0] if sorted_grades else "F"
    worst = sorted_grades[-1] if sorted_grades else "F"

    return (best, worst, details)


def _txt(name: str) -> List[str]:
    if dns is None:
        return []
    try:
        ans = _fresh_resolver().resolve(name, "TXT")
        return ["".join([(b.decode("utf-8") if isinstance(b, bytes) else b) for b in r.strings]) for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        _scan_error(f"DNS TXT lookup could not be completed for {name}")
        return []


def _mx(name: str) -> List[str]:
    if dns is None:
        return []
    try:
        ans = _fresh_resolver().resolve(name, "MX")
        records = sorted(ans, key=lambda record: getattr(record, "preference", 0))
        hosts = [str(record.exchange).rstrip(".") or "." for record in records]
        if "." in hosts and (len(hosts) != 1 or getattr(records[0], "preference", 0) != 0):
            _scan_error("Null MX must be the sole MX record with preference zero; review mail routing")
        return hosts
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        _scan_error(f"DNS MX lookup could not be completed for {name}")
        return []


def _spf_fetch(domain: str) -> Optional[str]:
    records = [record for record in _txt(domain) if re.match(r"^v=spf1(?:\s|$)", record, re.IGNORECASE)]
    if len(records) > 1:
        _scan_error("Multiple SPF records require manual review; none was selected")
    return records[0] if len(records) == 1 else None


def _spf_count(domain: str) -> Tuple[int, str]:
    """Estimate evaluated lookup terms; not a sender-specific SPF verifier.

    Cache DNS reads, but count each include evaluation separately. A path-local
    cycle guard avoids treating a repeated (non-cyclic) branch as free.
    """
    root = _spf_fetch(domain)
    if not root:
        return 0, ""
    cache = {domain.lower(): root}
    evaluations = 0
    cap_hit = False

    def count_record(target: str, path: Set[str]) -> int:
        nonlocal evaluations, cap_hit
        target = target.lower().rstrip(".")
        if target in path:
            _scan_error("SPF include/redirect cycle detected; lookup estimate is incomplete")
            return 0
        if len(path) >= MAX_SPF_RECURSION or evaluations >= MAX_SPF_FETCHES:
            cap_hit = True
            _scan_error("SPF analysis limit reached; lookup estimate is incomplete")
            return 0
        if not target or "%" in target:
            _scan_error("SPF macro target requires sender-specific evaluation; estimate is incomplete")
            return 0
        evaluations += 1
        if target not in cache:
            cache[target] = _spf_fetch(target)
        record = cache[target]
        if not record:
            _scan_error("SPF include/redirect target has no usable SPF record; review it manually")
            return 0
        tokens = [token.lower().lstrip("+-~?") for token in record.split()[1:]]
        has_all = "all" in tokens
        total = 0
        redirects = []
        for token in tokens:
            if token == "all":
                break
            if token.startswith("include:"):
                total += 1 + count_record(token.split(":", 1)[1], path | {target})
            elif re.match(r"^(?:a|mx)(?::|/|$)", token) or re.match(r"^ptr(?::|$)", token) or token.startswith("exists:"):
                total += 1
            elif token.startswith("redirect="):
                redirects.append(token.split("=", 1)[1])
            # exp= is explicitly outside the ten-lookup limit (RFC 7208).
        if not has_all:
            if len(redirects) > 1:
                _scan_error("Multiple SPF redirect modifiers are invalid; review the record")
            elif redirects:
                total += 1 + count_record(redirects[0], path | {target})
        return total

    count = count_record(domain, set())
    return count, "spf_fetch_cap_hit" if cap_hit else ""


def _parse_tags(record: str) -> Optional[Dict[str, str]]:
    """Parse a semicolon tag list without silently accepting duplicate fields."""
    tags = {}
    for field in record.split(";"):
        if not field.strip():
            continue
        key, separator, value = field.partition("=")
        key = key.strip().lower()
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_-]*", key) or key in tags:
            return None
        tags[key] = value.strip()
    return tags


def _dkim_discover(domain: str) -> Tuple[List[str], List[str], List[str]]:
    found: List[str] = []
    algos: Set[str] = set()
    notes: List[str] = []
    for sel in SELECTOR_CANDIDATES:
        name = f"{sel}._domainkey.{domain}"
        records = _txt(name)
        candidates = [t for t in records if re.search(r"(?:^|;)\s*(?:v|p)\s*=", t, re.IGNORECASE)]
        if len(candidates) > 1:
            notes.append(f"{sel}:ambiguous-key-records")
            _scan_error(f"DKIM selector {sel} has multiple key records; review it manually")
            continue
        for record in candidates:
            tags = _parse_tags(record)
            if (not tags or ("v" in tags and (tags["v"] != "DKIM1" or next(iter(tags)) != "v"))
                    or tags.get("k", "rsa") not in {"rsa", "ed25519"}):
                notes.append(f"{sel}:invalid-key-record")
                _scan_error(f"DKIM selector {sel} has invalid key fields; review it manually")
                continue
            if not tags.get("p"):
                notes.append(f"{sel}:empty-or-revoked-key")
                continue
            try:
                base64.b64decode(re.sub(r"[ \t\r\n]", "", tags["p"]), validate=True)
            except (ValueError, binascii.Error):
                notes.append(f"{sel}:invalid-key-encoding")
                _scan_error(f"DKIM selector {sel} has invalid public-key encoding; review it manually")
                continue
            # Discovery checks syntax only, not key strength or message signatures.
            found.append(sel)
            algos.add(tags.get("k", "rsa"))
            if "y" in [flag.strip() for flag in tags.get("t", "").split(":")]:
                notes.append(f"{sel}:test")
    return sorted(set(found)), sorted(algos), notes


def _fetch_mta_sts_policy(host: str) -> str:
    """Fetch a small verified HTTPS policy without redirects or proxy inheritance."""
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(host, timeout=HTTP_TIMEOUT, context=context)
    raw = _connect_public(host, 443, HTTP_TIMEOUT)
    deadline = None
    try:
        deadline = _socket_deadline(raw, HTTP_TIMEOUT)
        raw.settimeout(_remaining_timeout(HTTP_TIMEOUT))
        secure = context.wrap_socket(raw, server_hostname=host)
        deadline.cancel()
        deadline = _socket_deadline(secure, HTTP_TIMEOUT)
        connection.sock = secure  # retain hostname verification/Host while pinning the IP
        connection.request("GET", "/.well-known/mta-sts.txt", headers={"Accept": "text/plain"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("MTA-STS requires HTTP 200; redirects are not followed")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "text/plain":
            raise ValueError("MTA-STS policy must be plain text")
        body = response.read(10_241)
        if len(body) > 10_240:
            raise ValueError("MTA-STS policy exceeds the 10 KiB scan limit")
        return body.decode("utf-8")
    finally:
        if deadline is not None:
            deadline.cancel()
        connection.close()
        raw.close()


def _mta_sts(domain: str) -> Tuple[bool, str, int, str]:
    """Return (present, mode, max_age, raw_first_line).

    MTA-STS requires BOTH a ``_mta-sts.{domain}`` TXT record (RFC 8461 &#167;3.1)
    AND a valid HTTPS policy at ``https://mta-sts.{domain}/.well-known/mta-sts.txt``.
    We check the DNS TXT record first &#8212; if it is missing the protocol is
    incomplete even when a Cloudflare Worker still serves the policy file.
    """
    # Step 1: Check DNS TXT record at _mta-sts.{domain}
    txt_name = f"_mta-sts.{domain}"
    txt_records = _txt(txt_name)
    candidates = [record for record in txt_records if re.match(r"^v=STSv1[ \t]*;", record)]
    if len(candidates) != 1:
        if candidates:
            _scan_error("Multiple MTA-STS records require manual review")
        return (False, "", 0, "")
    tags = {}
    for field in candidates[0].split(";"):
        if not field.strip():
            continue
        key, separator, value = field.strip().partition("=")
        if not separator:
            _scan_error("MTA-STS DNS record is invalid; review it before making changes")
            return (False, "", 0, "")
        tags.setdefault(key, value)
    if not re.fullmatch(r"[A-Za-z0-9]{1,32}", tags.get("id", "")):
        _scan_error("MTA-STS DNS policy ID is invalid; review it before making changes")
        return (False, "", 0, "")
    try:
        body = _fetch_mta_sts_policy(f"mta-sts.{domain}")
        fields = {}
        mx_patterns = []
        for line in body.splitlines():
            key, separator, value = line.partition(":")
            if not separator or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", key):
                _scan_error("MTA-STS HTTPS policy is invalid; review it before making changes")
                return (False, "", 0, "")
            value = value.strip(" \t")
            if key == "mx":
                pattern = value[2:] if value.startswith("*.") else value
                if not is_valid_domain(pattern):
                    _scan_error("MTA-STS HTTPS policy contains an invalid MX pattern")
                    return (False, "", 0, "")
                mx_patterns.append(value)
            else:
                fields.setdefault(key, value)  # RFC 8461: first non-repeated field wins
        mode = fields.get("mode", "")
        age_text = fields.get("max_age", "")
        if (fields.get("version") != "STSv1" or mode not in {"enforce", "testing", "none"}
                or not re.fullmatch(r"[0-9]{1,10}", age_text)
                or int(age_text) > 31_557_600 or (mode != "none" and not mx_patterns)):
            _scan_error("MTA-STS HTTPS policy has missing or invalid required fields")
            return (False, "", 0, "")
        return (True, mode, int(age_text), body.splitlines()[0])
    except Exception:
        _scan_error("MTA-STS policy could not be verified; review it manually before changing DNS")
        return (False, "", 0, "")


def is_valid_tls_report_uri(uri: str) -> bool:
    """Validate supported reporting URI syntax; never visit its destination."""
    if not isinstance(uri, str) or re.search(r"[\s;,\x00-\x1f\x7f]", uri):
        return False
    try:
        parsed = urlsplit(uri)
        if parsed.scheme == "mailto":
            return bool(re.fullmatch(r"[^@/?#]+@[^@/?#]+", parsed.path)) and not parsed.netloc and not parsed.fragment
        if parsed.scheme == "https":
            return bool(parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment
                        and (parsed.port is None or 1 <= parsed.port <= 65535))
    except ValueError:
        pass
    return False


def _tls_rpt(domain: str) -> Tuple[bool, str]:
    """Return (present, rua_csv)."""
    name = f"_smtp._tls.{domain}"
    records = [record for record in _txt(name) if re.match(r"^v=TLSRPTv1[ \t]*;", record)]
    if len(records) != 1:
        if records:
            _scan_error("Multiple TLS-RPT records require manual review")
        return False, ""
    tags = _parse_tags(records[0])
    destinations = [uri.strip() for uri in (tags or {}).get("rua", "").split(",")]
    if not tags or not all(is_valid_tls_report_uri(uri) for uri in destinations):
        _scan_error("TLS-RPT reporting destinations are invalid; review the record manually")
        return False, ""
    return True, ",".join(destinations)


# &#9472;&#9472; BIMI (Brand Indicators for Message Identification) &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
# RFC draft-brand-indicators-for-message-identification
# Record lives at  default._bimi.<domain>  TXT  "v=BIMI1; l=<svg_url>; a=<vmc_url>"

def _bimi(domain: str) -> Tuple[bool, str, str]:
    """Check for BIMI record.  Returns (present, logo_url, authority_url)."""
    name = f"default._bimi.{domain}"
    for t in _txt(name):
        tl = t.lower()
        if tl.startswith("v=bimi1") or " v=bimi1" in tl:
            logo = ""
            authority = ""
            for part in t.split(";"):
                part = part.strip()
                pl = part.lower()
                if pl.startswith("l="):
                    logo = part.split("=", 1)[1].strip()
                elif pl.startswith("a="):
                    authority = part.split("=", 1)[1].strip()
            return (True, logo, authority)
    return (False, "", "")


# &#9472;&#9472; Blacklist / RBL (DNSBL) checking &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
# Query well-known DNS-based blocklists for the IP addresses behind MX hosts.

_DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
]


def _resolve_a(host: str) -> List[str]:
    """Resolve A records for a hostname. Returns list of IP strings."""
    if dns is None:
        _scan_error(f"MX address lookup could not be completed for {host}: DNS resolver unavailable")
        return []
    try:
        ans = _fresh_resolver().resolve(host, "A")
        return [str(r) for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception:
        _scan_error(f"MX address lookup could not be completed for {host}")
        return []


def _check_rbl(ip: str) -> List[str]:
    """Query DNSBL zones for *ip*.  Returns list of zone names that list it."""
    listed_on: List[str] = []
    if dns is None:
        _scan_error("DNSBL checks could not be completed: DNS resolver unavailable")
        return listed_on
    parts = ip.split(".")
    if len(parts) != 4:
        return listed_on
    reversed_ip = ".".join(reversed(parts))
    for zone in _DNSBL_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            answer = _fresh_resolver().resolve(query, "A")
            # Spamhaus 127.255.255.* responses signal blocked/invalid queries,
            # not a reputation listing. DNS wildcard addresses are not listings.
            codes = [ipaddress.IPv4Address(str(record)) for record in answer]
            listing_codes = [code for code in codes if code in ipaddress.IPv4Network("127.0.0.0/24")]
            if listing_codes:
                listed_on.append(zone)
            if len(listing_codes) != len(codes) or not codes:
                _scan_error(f"DNSBL {zone} returned a provider error or unexpected response; reputation is unverified")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            _scan_error(f"DNSBL lookup could not be completed for {zone}")
    return listed_on


def _mx_blacklist_check(mx_hosts: List[str]) -> Tuple[int, List[Dict]]:
    """Check MX host IPs against DNSBL zones.
    Returns (total_listings, details_list).
    """
    details: List[Dict] = []
    total = 0
    checked_ips: Set[str] = set()
    for mx in mx_hosts[:3]:  # Check up to 3 MX hosts
        ips = _resolve_a(mx)
        for ip in ips[:2]:  # Up to 2 IPs per host
            if ip in checked_ips:
                continue
            checked_ips.add(ip)
            listings = _check_rbl(ip)
            if listings:
                total += len(listings)
                details.append({"host": mx, "ip": ip, "listed_on": listings})
    return total, details


def _empty_result(notes: str = "") -> Dict[str, object]:
    """Return a blank scan result dict."""
    return {
        "spf_present": False, "spf_record": "", "spf_lookups": 0,
        "spf_includes": "", "spf_all": "",
        "mx_present": False, "mx_count": 0, "mx_hosts": "", "null_mx": False,
        "dmarc_present": False, "dmarc_policy": "", "dmarc_strength": "",
        "dmarc_sp": "", "dmarc_aspf": "r", "dmarc_adkim": "r",
        "dmarc_pct": 100, "dmarc_rua": "", "dmarc_ruf": "",
        "dkim_present": False, "dkim_selectors": "", "dkim_algos": "",
        "mta_sts_present": False, "mta_sts_mode": "", "mta_sts_max_age": 0,
        "tls_rpt_present": False, "tls_rpt_rua": "",
        "bimi_present": False, "bimi_logo": "", "bimi_authority": "",
        "rbl_listings": 0, "rbl_details": [],
        "starttls_grade": "", "starttls_worst": "",
        "notes": notes,
    }


def _domain_exists(domain: str) -> bool:
    """Quick check using the same helpers the scanner uses so mocks work."""
    if dns is None:
        return True
    if _mx(domain):
        return True
    if _txt(domain):
        return True
    for kind in ("NS", "A", "AAAA"):
        try:
            if _fresh_resolver().resolve(domain, kind):
                return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            continue
        except Exception:
            _scan_error(f"DNS existence check could not be completed for {domain}")
            return False
    return False


def _usable_dmarc(records: List[str]) -> bool:
    """Reject ambiguity and malformed policy fields rather than awarding credit."""
    if len(records) != 1:
        return False
    parsed = _parse_tags(records[0])
    if not parsed or parsed.get("v", "").lower() != "dmarc1" or next(iter(parsed)) != "v":
        return False
    tags = {key: value.lower() for key, value in parsed.items()}
    if tags.get("p") not in {"none", "quarantine", "reject"}:
        return False
    if "sp" in tags and tags["sp"] not in {"none", "quarantine", "reject"}:
        return False
    if any(key in tags and tags[key] not in {"r", "s"} for key in ("adkim", "aspf")):
        return False
    return "pct" not in tags or bool(re.fullmatch(r"[0-9]{1,3}", tags["pct"]) and int(tags["pct"]) <= 100)


def _scan_domain(domain: str, check_starttls: bool = False) -> Dict[str, object]:
    """
    Comprehensive email security scan for a domain.

    Checks:
    - SPF record presence and DNS lookup count
    - MX records presence
    - DMARC policy and strength
    - DKIM selector discovery
    - MTA-STS policy
    - TLS-RPT reporting
    - STARTTLS capability (optional, requires network access to port 25)

    Args:
        domain: The domain to scan
        check_starttls: Whether to perform live STARTTLS checks (default False)

    Returns:
        Dictionary with all scan results
    """
    d = domain.strip().lower()
    if not is_valid_domain(d):
        logger.warning("Invalid domain format: %s", d)
        return _empty_result("Invalid domain format")

    if not _domain_exists(d):
        logger.warning("Domain not found: %s", d)
        return _empty_result("Domain not found &#8212; check for typos and try again")

    notes = []
    logger.info("Scanning domain: %s", d)

    # SPF
    spf = _spf_fetch(d)
    spf_present = spf is not None
    spf_record = spf if spf else ""
    spf_lookups, spf_note = _spf_count(d) if spf_present else (0, "")
    if spf_lookups > 10:
        notes.append("SPF may exceed 10 DNS lookups (approx)")
    if spf_note:
        notes.append(spf_note)
    # MX
    mx = _mx(d)
    null_mx = mx == ["."]
    if "." in mx:
        if not null_mx:
            _scan_error("Null MX is mixed with other mail servers; review mail routing")
        mx = [host for host in mx if host != "."]
    if null_mx:
        notes.append("Null MX: this domain explicitly does not accept incoming email")
    mx_present = len(mx) > 0
    # DMARC
    dmarc_txts = _txt(f"_dmarc.{d}")
    dmarc_recs = [t for t in dmarc_txts if re.match(r"^v[ \t]*=[ \t]*dmarc1[ \t]*(?:;|$)", t, re.IGNORECASE)]
    dmarc_present = _usable_dmarc(dmarc_recs)
    dmarc_tags = _parse_tags(dmarc_recs[0]) if dmarc_present else {}
    if any(tag in dmarc_tags for tag in ("t", "np", "psd")):
        _scan_error("DMARC RFC 9989 t/np/psd semantics are not evaluated by this direct-record scanner; review manually")
    if "pct" in dmarc_tags:
        notes.append("DMARC pct is a legacy RFC 7489 tag, removed by RFC 9989; receivers may ignore it")
    if dmarc_recs and not dmarc_present:
        _scan_error("DMARC has duplicate or invalid policy fields; review the DNS record manually")
    dmarc_policy = ""
    dmarc_strength = ""
    if dmarc_present:
        dmarc_policy = dmarc_tags["p"].lower()
        dmarc_strength = dmarc_policy if dmarc_policy in {"quarantine", "reject", "none"} else ""
    # DKIM
    dkim_selectors, dkim_algos, dkim_notes = _dkim_discover(d)
    dkim_present = len(dkim_selectors) > 0
    if dkim_notes:
        notes.extend(dkim_notes)
    # MTA-STS
    sts_present, sts_mode, sts_max_age, _ = _mta_sts(d) if not null_mx else (False, "", 0, "")
    # TLS-RPT
    tls_present, tls_rua = _tls_rpt(d) if not null_mx else (False, "")
    # BIMI
    bimi_present, bimi_logo, bimi_authority = _bimi(d)
    if bimi_present:
        if not bimi_logo:
            notes.append("BIMI record found but logo URL (l=) is empty")

    # Blacklist / RBL check (uses MX host IPs)
    rbl_listings = 0
    rbl_details: list = []
    if mx:
        rbl_listings, rbl_details = _mx_blacklist_check(mx)
        if rbl_listings:
            names = {e for d_item in rbl_details for e in d_item["listed_on"]}
            notes.append(f"MX IP(s) listed on {rbl_listings} blacklist(s): {', '.join(sorted(names))}")

    # STARTTLS check (optional, may be slow)
    starttls_grade = ""
    starttls_worst = ""
    starttls_details = []
    if check_starttls and mx:
        starttls_grade, starttls_worst, starttls_details = _check_mx_starttls(d, mx)
        if starttls_worst in ("D", "F"):
            notes.append("STARTTLS weak or missing on some MX servers")

    # SPF mechanism analysis for alignment hints
    spf_includes = []
    spf_all_mechanism = ""
    if spf_record:
        tokens = spf_record.lower().split()
        for tok in tokens:
            if tok.startswith("include:"):
                spf_includes.append(tok.split(":", 1)[1])
            if tok in ("all", "-all", "~all", "?all", "+all"):
                spf_all_mechanism = "+all" if tok == "all" else tok
                break  # later mechanisms cannot override the first matching all

    # DMARC subdomain policy (sp=) and alignment modes
    dmarc_sp = ""  # subdomain policy
    dmarc_aspf = "r"  # SPF alignment mode (default relaxed)
    dmarc_adkim = "r"  # DKIM alignment mode (default relaxed)
    dmarc_pct = 100  # percentage
    dmarc_rua = ""  # aggregate report URI
    dmarc_ruf = ""  # forensic report URI

    if dmarc_present:
        dmarc_sp = dmarc_tags.get("sp", "").lower()
        dmarc_aspf = dmarc_tags.get("aspf", "r").lower()
        dmarc_adkim = dmarc_tags.get("adkim", "r").lower()
        dmarc_pct = int(dmarc_tags.get("pct", "100"))
        dmarc_rua = dmarc_tags.get("rua", "")
        dmarc_ruf = dmarc_tags.get("ruf", "")

    # Alignment warnings
    if dmarc_aspf == "s" or dmarc_adkim == "s":
        notes.append("Strict alignment enabled")
    if dmarc_pct < 100:
        notes.append(f"Legacy DMARC pct={dmarc_pct}; not a guaranteed delivery percentage")

    return {
        "spf_present": spf_present,
        "spf_record": spf_record,
        "spf_lookups": spf_lookups,
        "spf_includes": ",".join(spf_includes),
        "spf_all": spf_all_mechanism,
        "mx_present": mx_present,
        "mx_count": len(mx),
        "mx_hosts": ",".join(mx[:5]),  # First 5 MX hosts
        "null_mx": null_mx,
        "dmarc_present": dmarc_present,
        "dmarc_policy": dmarc_policy,
        "dmarc_strength": dmarc_strength,
        "dmarc_sp": dmarc_sp,
        "dmarc_aspf": dmarc_aspf,
        "dmarc_adkim": dmarc_adkim,
        "dmarc_pct": dmarc_pct,
        "dmarc_rua": dmarc_rua,
        "dmarc_ruf": dmarc_ruf,
        "dkim_present": dkim_present,
        "dkim_selectors": ",".join(dkim_selectors),
        "dkim_algos": ",".join(dkim_algos),
        "mta_sts_present": sts_present,
        "mta_sts_mode": sts_mode,
        "mta_sts_max_age": sts_max_age,
        "tls_rpt_present": tls_present,
        "tls_rpt_rua": tls_rua,
        "bimi_present": bimi_present,
        "bimi_logo": bimi_logo,
        "bimi_authority": bimi_authority,
        "rbl_listings": rbl_listings,
        "rbl_details": rbl_details,
        "starttls_grade": starttls_grade,
        "starttls_worst": starttls_worst,
        "notes": "; ".join(notes),
    }


def scan_domain(domain: str, check_starttls: bool = False) -> Dict[str, object]:
    """Scan with per-call diagnostics so DNS failures never authorise blind fixes."""
    errors: List[str] = []
    token = _SCAN_ERRORS.set(errors)
    deadline_token = _SCAN_DEADLINE.set(time.monotonic() + SCAN_TIMEOUT)
    try:
        if dns is None:
            _scan_error("DNS resolver is unavailable; record absence could not be verified")
        result = _scan_domain(domain, check_starttls=check_starttls)
        result["scan_incomplete"] = bool(errors)
        if errors:
            result["notes"] = "; ".join(filter(None, [str(result.get("notes", "")), *errors]))
        return result
    finally:
        _SCAN_ERRORS.reset(token)
        _SCAN_DEADLINE.reset(deadline_token)
