from typing import Dict, Set, Tuple, List, Optional
import re
import socket
import ssl
import logging

# Configure module logger
logger = logging.getLogger("auroraedge.scanner")

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


def _fresh_resolver() -> "dns.resolver.Resolver":
    """Return a resolver that bypasses local DNS cache.

    Uses Cloudflare (1.1.1.1) and Google (8.8.8.8) public DNS servers
    so that recently-changed records are picked up immediately &#8212; critical
    for the auto-fix demo where records are modified via the Cloudflare
    API seconds before a rescan.
    """
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.lifetime = RESOLVER_TIMEOUT
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
    return bool(_DOMAIN_RE.match(domain))


def _starttls_check(mx_host: str, port: int = 25) -> Tuple[str, str, str]:
    """
    Attempt STARTTLS handshake with MX server and grade the connection.
    Returns: (grade, tls_version, cipher_info)
    """
    try:
        # Connect to SMTP server
        sock = socket.create_connection((mx_host, port), timeout=SMTP_TIMEOUT)
        try:
            sock.settimeout(SMTP_TIMEOUT)

            # Read banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            if not banner.startswith("220"):
                return ("F", "", "No valid SMTP banner")

            # Send EHLO
            sock.sendall(b"EHLO auroraedge.local\r\n")
            ehlo_resp = sock.recv(4096).decode("utf-8", errors="ignore")

            # Check for STARTTLS support
            if "STARTTLS" not in ehlo_resp.upper():
                return ("F", "", "STARTTLS not advertised")

            # Send STARTTLS command
            sock.sendall(b"STARTTLS\r\n")
            starttls_resp = sock.recv(1024).decode("utf-8", errors="ignore")

            if not starttls_resp.startswith("220"):
                return ("F", "", "STARTTLS rejected")

            # Create SSL context and wrap socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We're testing capability, not cert validity

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
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    except socket.timeout:
        return ("F", "", "Connection timeout")
    except ConnectionRefusedError:
        return ("F", "", "Connection refused")
    except Exception as e:
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
    except Exception:
        return []


def _mx(name: str) -> List[str]:
    if dns is None:
        return []
    try:
        ans = _fresh_resolver().resolve(name, "MX")
        return [str(r.exchange).rstrip(".") for r in ans]
    except Exception:
        return []


def _spf_fetch(domain: str) -> Optional[str]:
    for t in _txt(domain):
        if t.lower().startswith("v=spf1"):
            return t
    return None


def _spf_count(domain: str) -> Tuple[int, str]:
    visited: Set[str] = set()
    fetches = 0

    def count_for_spf(spf: str, depth: int) -> int:
        nonlocal fetches
        if depth > MAX_SPF_RECURSION:
            return 0
        total = 0
        tokens = spf.split()
        for tok in tokens:
            t = tok.lower()
            if t.startswith("include:"):
                total += 1
                target = t.split(":", 1)[1]
                if target and target not in visited and fetches < MAX_SPF_FETCHES:
                    visited.add(target)
                    fetches += 1
                    child = _spf_fetch(target)
                    if child:
                        total += count_for_spf(child, depth + 1)
            elif t == "a" or t.startswith("a:") or t.startswith("a/"):
                total += 1
            elif t == "mx" or t.startswith("mx:") or t.startswith("mx/"):
                total += 1
            elif t.startswith("ptr"):
                total += 1
            elif t.startswith("exists:"):
                total += 1
            elif t.startswith("redirect="):
                total += 1
                target = t.split("=", 1)[1]
                if target and target not in visited and fetches < MAX_SPF_FETCHES:
                    visited.add(target)
                    fetches += 1
                    child = _spf_fetch(target)
                    if child:
                        total += count_for_spf(child, depth + 1)
            elif t.startswith("exp="):
                pass  # exp= modifier does NOT count per RFC 7208 Section 4.6.4
        return total

    root = _spf_fetch(domain)
    if not root:
        return 0, ""
    visited.add(domain)
    fetches += 1
    count = count_for_spf(root, depth=1)
    note = "spf_fetch_cap_hit" if fetches >= MAX_SPF_FETCHES else ""
    return count, note


def _dkim_discover(domain: str) -> Tuple[List[str], List[str], List[str]]:
    found: List[str] = []
    algos: Set[str] = set()
    notes: List[str] = []
    for sel in SELECTOR_CANDIDATES:
        name = f"{sel}._domainkey.{domain}"
        for t in _txt(name):
            tl = t.lower()
            if tl.startswith("v=dkim1") or " v=dkim1" in tl:
                found.append(sel)
                for part in t.split(";"):
                    part = part.strip()
                    if part.lower().startswith("k="):
                        algos.add(part.split("=", 1)[1].strip().lower())
                    if part.lower().startswith("t="):
                        val = part.split("=", 1)[1].strip().lower()
                        if "y" in val:
                            notes.append(f"{sel}:test")
    return sorted(set(found)), sorted(algos), notes


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
    has_dns = any(t.lower().startswith("v=stsv1") for t in txt_records)

    if not has_dns:
        return (False, "", 0, "")

    # Step 2: Fetch the HTTPS policy file
    if requests is None:
        # DNS record present but cannot verify HTTPS &#8212; still mark present
        return (True, "", 0, "")
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, stream=True)
        if r.status_code != 200:
            return (False, "", 0, "")
        # Limit response size to 10 KB to prevent resource exhaustion
        body = r.content[:10_240].decode("utf-8", errors="ignore")
        r.close()
        mode = ""
        max_age = 0
        first = ""
        for i, line in enumerate(body.splitlines()):
            if i == 0:
                first = line.strip()
            s = line.strip()
            if s.lower().startswith("mode:"):
                mode = s.split(":", 1)[1].strip().lower()
            if s.lower().startswith("max_age:"):
                try:
                    max_age = int(s.split(":", 1)[1].strip())
                except Exception:
                    pass
        return (True, mode, max_age, first)
    except Exception:
        return (False, "", 0, "")


def _tls_rpt(domain: str) -> Tuple[bool, str]:
    """Return (present, rua_csv)."""
    name = f"_smtp._tls.{domain}"
    ruas = []
    for t in _txt(name):
        tl = t.lower()
        if tl.startswith("v=tlsrptv1") or " v=tlsrptv1" in tl:
            # parse rua=mailto:... (, separated)
            parts = [p.strip() for p in t.split(";")]
            for p in parts:
                if p.lower().startswith("rua="):
                    val = p.split("=", 1)[1].strip()
                    ruas.append(val)
    return (len(ruas) > 0, ",".join(sorted(set(ruas))))


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
    "dnsbl.sorbs.net",
    "dnsbl-1.uceprotect.net",
]


def _resolve_a(host: str) -> List[str]:
    """Resolve A records for a hostname. Returns list of IP strings."""
    if dns is None:
        return []
    try:
        ans = _fresh_resolver().resolve(host, "A")
        return [str(r) for r in ans]
    except Exception:
        return []


def _check_rbl(ip: str) -> List[str]:
    """Query DNSBL zones for *ip*.  Returns list of zone names that list it."""
    listed_on: List[str] = []
    parts = ip.split(".")
    if len(parts) != 4:
        return listed_on
    reversed_ip = ".".join(reversed(parts))
    for zone in _DNSBL_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            _fresh_resolver().resolve(query, "A")
            listed_on.append(zone)
        except Exception:
            pass
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
        "mx_present": False, "mx_count": 0, "mx_hosts": "",
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
    try:
        _fresh_resolver().resolve(domain, "NS")
        return True
    except Exception:
        return False


def scan_domain(domain: str, check_starttls: bool = False) -> Dict[str, object]:
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
    mx_present = len(mx) > 0
    # DMARC
    dmarc_txts = _txt(f"_dmarc.{d}")
    dmarc_recs = [t for t in dmarc_txts if t.lower().startswith("v=dmarc1")]
    dmarc_present = len(dmarc_recs) > 0
    dmarc_policy = ""
    dmarc_strength = ""
    if dmarc_present:
        rec = dmarc_recs[0]
        for part in rec.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                dmarc_policy = part.split("=", 1)[1].strip().lower()
                break
        dmarc_strength = dmarc_policy if dmarc_policy in {"quarantine", "reject", "none"} else ""
    # DKIM
    dkim_selectors, dkim_algos, dkim_notes = _dkim_discover(d)
    dkim_present = len(dkim_selectors) > 0
    if dkim_notes:
        notes.extend(dkim_notes)
    # MTA-STS
    sts_present, sts_mode, sts_max_age, _ = _mta_sts(d)
    # TLS-RPT
    tls_present, tls_rua = _tls_rpt(d)
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
            if tok in ("-all", "~all", "?all", "+all"):
                spf_all_mechanism = tok

    # DMARC subdomain policy (sp=) and alignment modes
    dmarc_sp = ""  # subdomain policy
    dmarc_aspf = "r"  # SPF alignment mode (default relaxed)
    dmarc_adkim = "r"  # DKIM alignment mode (default relaxed)
    dmarc_pct = 100  # percentage
    dmarc_rua = ""  # aggregate report URI
    dmarc_ruf = ""  # forensic report URI

    if dmarc_present and dmarc_recs:
        rec = dmarc_recs[0]
        for part in rec.split(";"):
            part = part.strip()
            pl = part.lower()
            if pl.startswith("sp="):
                dmarc_sp = part.split("=", 1)[1].strip().lower()
            elif pl.startswith("aspf="):
                dmarc_aspf = part.split("=", 1)[1].strip().lower()
            elif pl.startswith("adkim="):
                dmarc_adkim = part.split("=", 1)[1].strip().lower()
            elif pl.startswith("pct="):
                try:
                    dmarc_pct = int(part.split("=", 1)[1].strip())
                except ValueError:
                    pass
            elif pl.startswith("rua="):
                dmarc_rua = part.split("=", 1)[1].strip()
            elif pl.startswith("ruf="):
                dmarc_ruf = part.split("=", 1)[1].strip()

    # Alignment warnings
    if dmarc_aspf == "s" or dmarc_adkim == "s":
        notes.append("Strict alignment enabled")
    if dmarc_pct < 100:
        notes.append(f"DMARC pct={dmarc_pct} (not 100%)")

    return {
        "spf_present": spf_present,
        "spf_record": spf_record,
        "spf_lookups": spf_lookups,
        "spf_includes": ",".join(spf_includes),
        "spf_all": spf_all_mechanism,
        "mx_present": mx_present,
        "mx_count": len(mx),
        "mx_hosts": ",".join(mx[:5]),  # First 5 MX hosts
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
