"""Cloudflare-backed DNS fixing and audit logging for NorthFlux Security."""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from logging.handlers import RotatingFileHandler

from app.runtime_paths import LOGS_DIR, PROJECT_ROOT

# Optional requests import for Cloudflare API calls
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Configure logging
logger = logging.getLogger("northflux.dns_fix")

# Cloudflare API configuration
CF_API_BASE = "https://api.cloudflare.com/client/v4"
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_API_KEY = os.environ.get("CF_API_KEY", "")
CF_EMAIL = os.environ.get("CF_EMAIL", "")

# Audit log path (rotated, max 2 MB, 3 backups)
ROOT = PROJECT_ROOT
AUDIT_LOG = LOGS_DIR / "dns_audit.log"
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
_audit_handler = RotatingFileHandler(
    AUDIT_LOG, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
)
_audit_logger = logging.getLogger("northflux.dns_audit")
_audit_logger.addHandler(_audit_handler)
_audit_logger.setLevel(logging.INFO)


class CloudflareDNS:
    """Small Cloudflare client used by the auto-fix workflow."""

    def __init__(self, api_token: str = None, zone_id: str = None):
        """Initialise the Cloudflare client."""
        self.api_token = api_token or CF_API_TOKEN
        self.zone_id = zone_id or CF_ZONE_ID
        self.base_url = f"{CF_API_BASE}/zones/{self.zone_id}/dns_records"
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        # Global API Key + email fallback for operations that need broader perms
        self.api_key = CF_API_KEY
        self.email = CF_EMAIL
        # Cached zone name, filled after validate_connection()
        self.zone_name: Optional[str] = None

        # Ensure logs directory exists
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _extract_error(result: dict) -> str:
        """Safely extract the first error message from a Cloudflare API response."""
        errors = result.get("errors", [])
        if errors and isinstance(errors, list) and len(errors) > 0:
            return errors[0].get("message", str(result))
        return str(result)

    def _log_audit(
        self,
        action: str,
        domain: str,
        record_type: str,
        old_value: str,
        new_value: str,
        success: bool,
        error: str = "",
    ):
        """Log DNS changes for audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "domain": domain,
            "record_type": record_type,
            "old_value": old_value,
            "new_value": new_value,
            "success": success,
            "error": error,
        }

        _audit_logger.info(json.dumps(entry))

        if success:
            logger.info("DNS %s: %s for %s", action, record_type, domain)
        else:
            logger.error("DNS %s failed: %s for %s - %s", action, record_type, domain, error)

    def _request(self, method: str, url: str, data: dict = None) -> Tuple[bool, dict]:
        """Make API request to Cloudflare."""
        if not HAS_REQUESTS:
            return False, {"error": "requests library not installed"}

        if not self.api_token:
            return False, {"error": "Cloudflare API token not configured"}

        try:
            if method == "GET":
                resp = requests.get(url, headers=self.headers, timeout=10)
            elif method == "POST":
                resp = requests.post(url, headers=self.headers, json=data, timeout=10)
            elif method == "PUT":
                resp = requests.put(url, headers=self.headers, json=data, timeout=10)
            elif method == "DELETE":
                resp = requests.delete(url, headers=self.headers, timeout=10)
            else:
                return False, {"error": f"Unknown method: {method}"}

            result = resp.json()
            return result.get("success", False), result

        except Exception as e:
            logger.error(f"Cloudflare API error: {e}")
            return False, {"error": str(e)}

    def validate_connection(self) -> Tuple[bool, str]:
        """
        Validate Cloudflare API connection and permissions.

        Returns:
            Tuple of (success, message)
        """
        if not self.api_token:
            return False, "CF_API_TOKEN environment variable not set"
        if not self.zone_id:
            return False, "CF_ZONE_ID environment variable not set"

        # Test API connectivity
        url = f"{CF_API_BASE}/zones/{self.zone_id}"
        success, result = self._request("GET", url)

        if success:
            self.zone_name = result.get("result", {}).get("name", "unknown")
            return True, f"Connected to zone: {self.zone_name}"
        else:
            error = self._extract_error(result)
            return False, f"API error: {error}"

    def verify_domain_ownership(self, domain: str) -> Tuple[bool, str]:
        """
        Verify that the target domain belongs to (or is a subdomain of) the
        configured Cloudflare zone. This prevents the system from creating
        meaningless DNS records in the wrong zone.

        Args:
            domain: The domain to verify (e.g. "example.com")

        Returns:
            Tuple of (is_owned, message)
        """
        # Must have called validate_connection() first
        if not self.zone_name:
            ok, msg = self.validate_connection()
            if not ok:
                return False, msg

        domain = domain.strip().lower().rstrip(".")
        zone = (self.zone_name or "").strip().lower().rstrip(".")

        if not zone or zone == "unknown":
            return False, "Could not determine Cloudflare zone name."

        # Domain must be the zone itself or a subdomain of it
        if domain == zone or domain.endswith(f".{zone}"):
            return True, f"Domain '{domain}' is within zone '{zone}'."

        return False, (
            f"Domain '{domain}' does not belong to the configured Cloudflare "
            f"zone '{zone}'. You can only auto-fix domains you control. "
            f"Please add Cloudflare credentials for '{domain}' in Settings, "
            f"or scan a domain within '{zone}'."
        )

    def get_txt_records(self, name: str) -> List[Dict]:
        """Get all TXT records for a name without assuming the first is ours."""
        url = f"{self.base_url}?type=TXT&name={name}"
        success, result = self._request("GET", url)
        if success:
            return list(result.get("result") or [])
        return []

    def get_txt_record(self, name: str, content_prefix: str = "") -> Optional[Dict]:
        """Get one TXT record, optionally selecting by protocol prefix."""
        records = self.get_txt_records(name)
        if content_prefix:
            prefix = content_prefix.lower()
            records = [
                record
                for record in records
                if str(record.get("content", "")).strip().lower().startswith(prefix)
            ]
        return records[0] if records else None

    def create_or_update_txt(
        self, name: str, content: str, comment: str = ""
    ) -> Tuple[bool, str]:
        """
        Create or update a TXT record.

        Args:
            name: Full record name (e.g., "_dmarc.example.com")
            content: TXT record content
            comment: Optional comment for the record

        Returns:
            Tuple of (success, message)
        """
        ok, ownership_message = self._ensure_ownership(name)
        if not ok:
            return False, ownership_message

        protocol_prefix = content.split(";", 1)[0].split(" ", 1)[0].strip().lower()
        matching = [
            record
            for record in self.get_txt_records(name)
            if str(record.get("content", "")).strip().lower().startswith(protocol_prefix)
        ]
        if len(matching) > 1:
            return False, (
                f"Refusing to update {name}: multiple {protocol_prefix} TXT records exist. "
                "Resolve the duplicate records manually first."
            )
        existing = matching[0] if matching else None
        old_value = existing.get("content", "") if existing else ""

        data = {
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": 3600,  # 1 hour
            "comment": comment
            or f"Created by NorthFlux Security at {datetime.now(timezone.utc).isoformat()}",
        }

        if existing:
            # Update existing record
            url = f"{self.base_url}/{existing['id']}"
            success, result = self._request("PUT", url, data)
            action = "UPDATE"
        else:
            # Create new record
            success, result = self._request("POST", self.base_url, data)
            action = "CREATE"

        if success:
            self._log_audit(action, name, "TXT", old_value, content, True)
            return True, f"Successfully {action.lower()}d TXT record for {name}"
        else:
            error = self._extract_error(result)
            self._log_audit(action, name, "TXT", old_value, content, False, error)
            return False, f"Failed to {action.lower()} TXT record: {error}"

    def _ensure_ownership(self, domain: str) -> Tuple[bool, str]:
        """Enforce domain ownership before any DNS modification."""
        ok, msg = self.verify_domain_ownership(domain)
        if not ok:
            logger.warning("Ownership check failed for %s: %s", domain, msg)
        return ok, msg

    def fix_spf(
        self, domain: str, includes: List[str] = None, all_mechanism: str = "~all"
    ) -> Tuple[bool, str]:
        """
        Create or fix SPF record for a domain.

        Args:
            domain: The domain name
            includes: List of include mechanisms (e.g., ["_spf.google.com"])
            all_mechanism: The 'all' mechanism (-all, ~all, ?all)

        Returns:
            Tuple of (success, message)

        Example:
            fix_spf("example.com", ["_spf.google.com", "spf.protection.outlook.com"])
        """
        ok, msg = self._ensure_ownership(domain)
        if not ok:
            return False, msg

        includes = includes or []

        # Build SPF record
        spf_parts = ["v=spf1"]
        for inc in includes:
            if not inc.startswith("include:"):
                inc = f"include:{inc}"
            spf_parts.append(inc)
        spf_parts.append(all_mechanism)

        spf_content = " ".join(spf_parts)

        return self.create_or_update_txt(
            domain, spf_content, "SPF record - NorthFlux Security auto-fix"
        )

    def fix_dmarc(
        self,
        domain: str,
        policy: str = "quarantine",
        rua: str = None,
        ruf: str = None,
        pct: int = 100,
        sp: str = None,
    ) -> Tuple[bool, str]:
        """
        Create or fix DMARC record for a domain.

        Args:
            domain: The domain name
            policy: DMARC policy (none, quarantine, reject)
            rua: Aggregate report URI (e.g., "mailto:dmarc@example.com")
            ruf: Forensic report URI
            pct: Percentage of messages to apply policy (default 100)
            sp: Subdomain policy

        Returns:
            Tuple of (success, message)

        Example:
            fix_dmarc("example.com", policy="reject", rua="mailto:dmarc@example.com")
        """
        ok, msg = self._ensure_ownership(domain)
        if not ok:
            return False, msg

        dmarc_name = f"_dmarc.{domain}"
        existing = self.get_txt_record(dmarc_name, "v=dmarc1")
        preserved = {}
        if existing:
            for part in str(existing.get("content", "")).split(";"):
                key, separator, value = part.strip().partition("=")
                if separator and key:
                    preserved[key.lower()] = value.strip()

        # Update requested fields while retaining alignment and reporting tags.
        preserved["v"] = "DMARC1"
        preserved["p"] = policy

        if rua:
            if not rua.startswith("mailto:"):
                rua = f"mailto:{rua}"
            preserved["rua"] = rua

        if ruf:
            if not ruf.startswith("mailto:"):
                ruf = f"mailto:{ruf}"
            preserved["ruf"] = ruf

        if pct < 100 or "pct" in preserved:
            preserved["pct"] = str(pct)

        if sp:
            preserved["sp"] = sp

        preferred_order = ["v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"]
        ordered_keys = [key for key in preferred_order if key in preserved]
        ordered_keys.extend(key for key in preserved if key not in ordered_keys)
        dmarc_content = "; ".join(f"{key}={preserved[key]}" for key in ordered_keys)

        return self.create_or_update_txt(
            dmarc_name, dmarc_content, "DMARC record - NorthFlux Security auto-fix"
        )

    def fix_tls_rpt(self, domain: str, rua: str) -> Tuple[bool, str]:
        """
        Create or fix TLS-RPT record for a domain.

        Args:
            domain: The domain name
            rua: Report URI (e.g., "mailto:tlsrpt@example.com")

        Returns:
            Tuple of (success, message)
        """
        ok, msg = self._ensure_ownership(domain)
        if not ok:
            return False, msg

        if not rua.startswith("mailto:"):
            rua = f"mailto:{rua}"

        tlsrpt_content = f"v=TLSRPTv1; rua={rua}"
        tlsrpt_name = f"_smtp._tls.{domain}"

        return self.create_or_update_txt(
            tlsrpt_name, tlsrpt_content, "TLS-RPT record - NorthFlux Security auto-fix"
        )

    def fix_mta_sts_dns(self, domain: str, policy_id: str = None) -> Tuple[bool, str]:
        """
        Create MTA-STS DNS record (requires separate HTTPS hosting).

        Args:
            domain: The domain name
            policy_id: Policy ID (default: YYYYMMDD format)

        Returns:
            Tuple of (success, message)

        Note: You also need to host /.well-known/mta-sts.txt on mta-sts.{domain}
        """
        ok, msg = self._ensure_ownership(domain)
        if not ok:
            return False, msg

        if not policy_id:
            policy_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        mtasts_content = f"v=STSv1; id={policy_id}"
        mtasts_name = f"_mta-sts.{domain}"

        return self.create_or_update_txt(
            mtasts_name, mtasts_content, "MTA-STS DNS record - NorthFlux Security auto-fix"
        )

    # -----------------------------------------------------------------
    # Email Provider Detection
    # -----------------------------------------------------------------

    # Known email provider signatures in MX hostnames
    EMAIL_PROVIDERS = {
        "microsoft365": {
            "name": "Microsoft 365 (Exchange Online)",
            "mx_patterns": ["mail.protection.outlook.com"],
            "dkim_type": "CNAME",
            "selectors": ["selector1", "selector2"],
        },
        "google": {
            "name": "Google Workspace",
            "mx_patterns": [
                "aspmx.l.google.com",
                "googlemail.com",
                "google.com",
            ],
            "dkim_type": "CNAME",
            "selectors": ["google"],
        },
        "zoho": {
            "name": "Zoho Mail",
            "mx_patterns": ["zoho.com", "zoho.eu", "zoho.in"],
            "dkim_type": "TXT",
            "selectors": ["zmail"],
        },
        "protonmail": {
            "name": "Proton Mail",
            "mx_patterns": ["protonmail.ch", "protonmail.com", "proton.me"],
            "dkim_type": "CNAME",
            "selectors": ["protonmail", "protonmail2", "protonmail3"],
        },
        "mimecast": {
            "name": "Mimecast",
            "mx_patterns": ["mimecast.com"],
            "dkim_type": "TXT",
            "selectors": ["mimecast20190104"],
        },
        "barracuda": {
            "name": "Barracuda",
            "mx_patterns": ["barracudanetworks.com", "barracuda.com"],
            "dkim_type": "TXT",
            "selectors": ["barracuda"],
        },
    }

    @staticmethod
    def detect_email_provider(mx_hosts_str: str) -> Dict:
        """
        Auto-detect the email provider from MX hostnames.

        Args:
            mx_hosts_str: Comma-separated MX hostnames from scan result

        Returns:
            Dict with provider key, name, dkim_type, selectors, and any
            extra metadata needed for auto-fix.
        """
        if not mx_hosts_str:
            return {"provider": "unknown", "name": "Unknown", "dkim_type": "TXT", "selectors": []}

        mx_lower = mx_hosts_str.lower()
        mx_list = [h.strip() for h in mx_lower.split(",") if h.strip()]

        for provider_key, info in CloudflareDNS.EMAIL_PROVIDERS.items():
            for pattern in info["mx_patterns"]:
                for mx in mx_list:
                    if pattern in mx:
                        result = {
                            "provider": provider_key,
                            "name": info["name"],
                            "dkim_type": info["dkim_type"],
                            "selectors": info["selectors"],
                        }
                        # Extract M365-specific metadata
                        if provider_key == "microsoft365":
                            # MX format: <domain-dashes>.mail.protection.outlook.com
                            # Extract domain GUID for CNAME targets
                            parts = mx.split(".mail.protection.outlook.com")[0]
                            result["domain_guid"] = parts
                        # Extract Google-specific metadata
                        elif provider_key == "google":
                            # Google DKIM CNAME target
                            result["cname_suffix"] = "dkim.googlehosted.com"
                        elif provider_key == "protonmail":
                            result["cname_suffix"] = "protonmail.domainkey.protonmail.ch"
                        return result

        return {"provider": "unknown", "name": "Unknown", "dkim_type": "TXT", "selectors": []}

    # -----------------------------------------------------------------
    # CNAME Record Management
    # -----------------------------------------------------------------

    def get_cname_record(self, name: str) -> Optional[Dict]:
        """Get existing CNAME record by name."""
        url = f"{self.base_url}?type=CNAME&name={name}"
        success, result = self._request("GET", url)
        if success and result.get("result"):
            return result["result"][0]
        return None

    def create_or_update_cname(
        self, name: str, target: str, comment: str = "", proxied: bool = False
    ) -> Tuple[bool, str]:
        """
        Create or update a CNAME record.

        Args:
            name: Full record name (e.g., "selector1._domainkey.example.com")
            target: CNAME target hostname
            comment: Optional comment
            proxied: Whether to proxy through Cloudflare (default False)

        Returns:
            Tuple of (success, message)
        """
        ok, ownership_message = self._ensure_ownership(name)
        if not ok:
            return False, ownership_message
        existing = self.get_cname_record(name)
        old_value = existing.get("content", "") if existing else ""

        data = {
            "type": "CNAME",
            "name": name,
            "content": target,
            "ttl": 3600,
            "proxied": proxied,
            "comment": comment
            or f"Created by NorthFlux Security at {datetime.now(timezone.utc).isoformat()}",
        }

        if existing:
            url = f"{self.base_url}/{existing['id']}"
            success, result = self._request("PUT", url, data)
            action = "UPDATE"
        else:
            success, result = self._request("POST", self.base_url, data)
            action = "CREATE"

        if success:
            self._log_audit(action, name, "CNAME", old_value, target, True)
            return True, f"Successfully {action.lower()}d CNAME record for {name}"
        else:
            error = self._extract_error(result)
            self._log_audit(action, name, "CNAME", old_value, target, False, error)
            return False, f"Failed to {action.lower()} CNAME record: {error}"

    # -----------------------------------------------------------------
    # A Record Management (for Worker routing)
    # -----------------------------------------------------------------

    def get_a_record(self, name: str) -> Optional[Dict]:
        """Get existing A record by name."""
        url = f"{self.base_url}?type=A&name={name}"
        success, result = self._request("GET", url)
        if success and result.get("result"):
            return result["result"][0]
        return None

    def create_or_update_a(
        self, name: str, ip: str, proxied: bool = True, comment: str = ""
    ) -> Tuple[bool, str]:
        """
        Create or update an A record.

        Args:
            name: Full record name (e.g., "mta-sts.example.com")
            ip: IPv4 address
            proxied: Whether to proxy through Cloudflare (default True)
            comment: Optional comment

        Returns:
            Tuple of (success, message)
        """
        existing = self.get_a_record(name)
        old_value = existing.get("content", "") if existing else ""

        data = {
            "type": "A",
            "name": name,
            "content": ip,
            "ttl": 1,  # Auto TTL when proxied
            "proxied": proxied,
            "comment": comment
            or f"Created by NorthFlux Security at {datetime.now(timezone.utc).isoformat()}",
        }

        if existing:
            url = f"{self.base_url}/{existing['id']}"
            success, result = self._request("PUT", url, data)
            action = "UPDATE"
        else:
            success, result = self._request("POST", self.base_url, data)
            action = "CREATE"

        if success:
            self._log_audit(action, name, "A", old_value, ip, True)
            return True, f"Successfully {action.lower()}d A record for {name}"
        else:
            error = self._extract_error(result)
            self._log_audit(action, name, "A", old_value, ip, False, error)
            return False, f"Failed to {action.lower()} A record: {error}"

    def _delete_a_record(self, name: str) -> None:
        """Delete any A records matching *name* (best-effort, no error raised)."""
        existing = self.get_a_record(name)
        if existing:
            url = f"{self.base_url}/{existing['id']}"
            self._request("DELETE", url)

    # -----------------------------------------------------------------
    # DKIM Auto-Fix
    # -----------------------------------------------------------------

    def fix_dkim(self, domain: str, scan_result: Dict) -> Tuple[bool, str]:
        """
        Refuse to guess tenant-specific DKIM values from MX records.

        MX records can identify the likely email provider, but they do not expose
        the selector targets or public keys assigned to this tenant. Writing a
        guessed record can silently break DKIM, so NorthFlux returns operator
        guidance instead of changing DNS.

        Args:
            domain: The domain name
            scan_result: Full scan result dict (needs mx_hosts)

        Returns:
            Tuple of (success, message)
        """
        ok, msg = self._ensure_ownership(domain)
        if not ok:
            return False, msg

        mx_hosts = scan_result.get("mx_hosts", "")
        provider = self.detect_email_provider(mx_hosts)
        if provider.get("provider", "unknown") != "unknown":
            return False, (
                f"Detected {provider.get('name', 'the mail provider')}, but DKIM records "
                "must be copied from that provider's admin console and reviewed manually."
            )

        return False, (
            "Could not detect email provider from MX records. "
            "DKIM requires provider-specific configuration. "
            f"MX hosts found: {mx_hosts or 'none'}"
        )

    # -----------------------------------------------------------------
    # Cloudflare Workers &#8212; MTA-STS HTTPS Policy Hosting
    # -----------------------------------------------------------------

    def get_account_id(self) -> Optional[str]:
        """
        Retrieve the Cloudflare account ID.

        Prefers the configured CF_ACCOUNT_ID env/setting, falls back to
        fetching it from the zone metadata.

        Returns:
            Account ID string, or None if unavailable.
        """
        # Prefer explicitly configured account ID
        if CF_ACCOUNT_ID:
            return CF_ACCOUNT_ID
        url = f"{CF_API_BASE}/zones/{self.zone_id}"
        success, result = self._request("GET", url)
        if success:
            return result.get("result", {}).get("account", {}).get("id")
        return None

    def deploy_mta_sts_worker(self, domain: str, mx_hosts_str: str) -> Tuple[bool, str]:
        """
        Fully automate MTA-STS HTTPS policy hosting using Cloudflare Workers.

        This replaces the manual step of setting up a web server at
        mta-sts.<domain> by:
        1. Creating a proxied DNS A record for mta-sts.<domain>
        2. Uploading a Cloudflare Worker that serves the policy file
        3. Creating a Worker route so requests hit the Worker

        The CF API token needs Workers Scripts permission in addition to DNS.

        Args:
            domain: The domain name
            mx_hosts_str: Comma-separated MX hostnames from scan

        Returns:
            Tuple of (success, message)
        """
        account_id = self.get_account_id()
        if not account_id:
            return False, (
                "Could not retrieve Cloudflare account ID. "
                "Ensure your API token has Zone:Read permission."
            )

        # Build the MTA-STS policy content from actual MX records
        mx_hosts = [h.strip() for h in mx_hosts_str.split(",") if h.strip()]
        if not mx_hosts:
            mx_hosts = [f"*.{domain}"]  # Fallback wildcard

        mx_lines = "\\n".join(f"mx: {mx}" for mx in mx_hosts)
        policy_content = f"version: STSv1\\nmode: enforce\\n{mx_lines}\\nmax_age: 86400"

        # Worker script that serves the MTA-STS policy
        # Uses Service Worker (classic) syntax for application/javascript upload
        worker_script = f"""
// NorthFlux Security MTA-STS Policy Worker for {domain}
// Auto-deployed by NorthFlux Security DNS Auto-Fix
// Serves /.well-known/mta-sts.txt for MTA-STS compliance

addEventListener('fetch', function(event) {{
  event.respondWith(handleRequest(event.request));
}});

async function handleRequest(request) {{
  var url = new URL(request.url);
  if (url.pathname === '/.well-known/mta-sts.txt') {{
    var policy = "{policy_content}\\n";
    return new Response(policy, {{
      status: 200,
      headers: {{
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'public, max-age=86400',
        'X-NorthFlux': 'mta-sts-worker',
      }},
    }});
  }}
  return new Response('Not Found', {{ status: 404 }});
}}
""".strip()

        # Sanitise the worker name (only lowercase alphanumeric and hyphens)
        worker_name = f"northflux-mta-sts-{domain.replace('.', '-')}"

        steps_done = []
        steps_failed = []

        # Step 1: Create proxied DNS A record for mta-sts.<domain>
        # Using 192.0.2.1 (RFC 5737 TEST-NET, safe dummy IP) &#8212; traffic goes
        # through Cloudflare's proxy so the origin IP doesn't matter.
        a_name = f"mta-sts.{domain}"
        ok, msg = self.create_or_update_a(
            a_name, "192.0.2.1", proxied=True,
            comment="MTA-STS Worker endpoint - NorthFlux Security auto-fix"
        )
        if ok:
            steps_done.append(f"DNS A record: {a_name} (proxied)")
        else:
            if "managed by Workers already exists on that host" in str(msg):
                # Worker-managed host already has the required DNS wiring.
                steps_done.append(f"DNS already managed by Workers: {a_name}")
            else:
                steps_failed.append(f"DNS A record failed: {msg}")
                # DNS is critical &#8212; abort if it fails
                return False, f"Failed to create DNS record for {a_name}: {msg}"

        # Step 2: Upload Worker script
        worker_url = (
            f"{CF_API_BASE}/accounts/{account_id}"
            f"/workers/scripts/{worker_name}"
        )
        if not HAS_REQUESTS:
            steps_failed.append("requests library not installed")
            return False, "requests library not installed"

        try:
            resp = requests.put(
                worker_url,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/javascript",
                },
                data=worker_script,
                timeout=30,
            )
            result = resp.json()
            if result.get("success"):
                steps_done.append(f"Worker uploaded: {worker_name}")
            else:
                error = self._extract_error(result)
                steps_failed.append(f"Worker upload failed: {error}")
                return False, (
                    f"Worker upload failed: {error}. "
                    "Ensure your API token has Account:Workers Scripts:Edit permission."
                )
        except Exception as e:
            steps_failed.append(f"Worker upload error: {e}")
            return False, f"Worker upload error: {e}"

        # Step 3: Bind Worker to the mta-sts subdomain
        # Try: A) API Token route &#8594; B) Global API Key route &#8594; C) Custom Domains
        route_pattern = f"mta-sts.{domain}/*"
        route_bound = False

        # -- Attempt A: Zone-level Workers Routes (API Token) --
        route_url = f"{CF_API_BASE}/zones/{self.zone_id}/workers/routes"
        route_data = {"pattern": route_pattern, "script": worker_name}
        try:
            resp = requests.get(route_url, headers=self.headers, timeout=10)
            route_result = resp.json()
            existing_routes = (
                route_result.get("result", []) if route_result.get("success") else []
            )
            if any(r.get("pattern") == route_pattern for r in existing_routes):
                steps_done.append(f"Worker route already exists: {route_pattern}")
                route_bound = True
            else:
                resp = requests.post(
                    route_url, headers=self.headers, json=route_data, timeout=10
                )
                result = resp.json()
                if result.get("success"):
                    steps_done.append(f"Worker route created: {route_pattern}")
                    route_bound = True
        except Exception:
            pass

        # -- Attempt B: Global API Key (broader permissions) --
        if not route_bound and self.api_key and self.email:
            gk_headers = {
                "X-Auth-Email": self.email,
                "X-Auth-Key": self.api_key,
                "Content-Type": "application/json",
            }
            try:
                # Check existing routes with global key
                resp = requests.get(route_url, headers=gk_headers, timeout=10)
                route_result = resp.json()
                existing_routes = (
                    route_result.get("result", []) if route_result.get("success") else []
                )
                if any(r.get("pattern") == route_pattern for r in existing_routes):
                    steps_done.append(f"Worker route already exists: {route_pattern}")
                    route_bound = True
                else:
                    resp = requests.post(
                        route_url, headers=gk_headers, json=route_data, timeout=10
                    )
                    result = resp.json()
                    if result.get("success"):
                        steps_done.append(f"Worker route created (global key): {route_pattern}")
                        route_bound = True
            except Exception:
                pass

        # -- Attempt C: Account-level Custom Domains (last resort) --
        # Custom Domains manages its own DNS, so remove the A record we
        # created in Step 1 to avoid the "externally managed DNS" conflict.
        if not route_bound:
            cd_hostname = f"mta-sts.{domain}"
            try:
                self._delete_a_record(cd_hostname)
            except Exception:
                pass
            cd_url = f"{CF_API_BASE}/accounts/{account_id}/workers/domains"
            cd_data = {
                "hostname": cd_hostname,
                "service": worker_name,
                "environment": "production",
                "zone_id": self.zone_id,
            }
            try:
                resp = requests.put(
                    cd_url,
                    headers=self.headers,
                    json=cd_data,
                    timeout=15,
                )
                result = resp.json()
                if result.get("success"):
                    steps_done.append(f"Worker custom domain bound: {cd_hostname}")
                    route_bound = True
                else:
                    error = self._extract_error(result)
                    steps_failed.append(f"Worker route/domain binding failed: {error}")
            except Exception as e:
                steps_failed.append(f"Worker domain binding error: {e}")

        # Log everything
        self._log_audit(
            "DEPLOY_WORKER", domain, "MTA-STS",
            "Not configured",
            f"Worker: {worker_name}, Route: {route_pattern}",
            len(steps_failed) == 0,
            "; ".join(steps_failed) if steps_failed else "",
        )

        summary_parts = []
        if steps_done:
            summary_parts.append("Done: " + ", ".join(steps_done))
        if steps_failed:
            summary_parts.append("Issues: " + ", ".join(steps_failed))

        all_ok = len(steps_failed) == 0
        summary = f"MTA-STS Worker deployment for {domain}: {' | '.join(summary_parts)}"

        if all_ok:
            logger.info(summary)
        else:
            logger.warning(summary)

        return all_ok, summary

    def generate_fixes(self, scan_result: Dict) -> List[Dict]:
        """
        Generate list of recommended fixes based on scan results.

        Args:
            scan_result: Result from scanner.scan_domain()

        Returns:
            List of fix recommendations with apply functions
        """
        domain = scan_result.get("domain", "")
        fixes = []

        # SPF fix
        if not scan_result.get("spf_present"):
            fixes.append(
                {
                    "type": "SPF",
                    "priority": "HIGH",
                    "description": "Add SPF record to prevent email spoofing",
                    "current": "Not configured",
                    "recommended": "v=spf1 include:_spf.google.com -all",
                    "auto_fix": lambda: self.fix_spf(domain, ["_spf.google.com"], "-all"),
                }
            )
        else:
            # Harden SPF: upgrade ~all (softfail) to -all (hardfail)
            spf_raw = scan_result.get("spf_record", "") or ""
            if "~all" in spf_raw and "-all" not in spf_raw:
                hardened = spf_raw.replace("~all", "-all")
                fixes.append(
                    {
                        "type": "SPF",
                        "priority": "WARN",
                        "description": "Harden SPF: upgrade ~all (softfail) to -all (hardfail)",
                        "current": spf_raw,
                        "recommended": hardened,
                        "auto_fix": lambda h=hardened: self.create_or_update_txt(
                            domain, h, "SPF hardened to -all - NorthFlux Security auto-fix"
                        ),
                    }
                )

        # DMARC fix &#8212; always target p=reject (strongest policy)
        if not scan_result.get("dmarc_present"):
            fixes.append(
                {
                    "type": "DMARC",
                    "priority": "HIGH",
                    "description": "Add DMARC record with reject policy for full protection",
                    "current": "Not configured",
                    "recommended": f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
                    "auto_fix": lambda: self.fix_dmarc(
                        domain, "reject", f"dmarc@{domain}"
                    ),
                }
            )
        elif scan_result.get("dmarc_policy") == "none":
            fixes.append(
                {
                    "type": "DMARC",
                    "priority": "HIGH",
                    "description": "Upgrade DMARC policy from 'none' to 'reject'",
                    "current": "p=none",
                    "recommended": "p=reject",
                    "auto_fix": lambda: self.fix_dmarc(
                        domain, "reject", scan_result.get("dmarc_rua") or f"dmarc@{domain}"
                    ),
                }
            )
        elif scan_result.get("dmarc_policy") == "quarantine":
            fixes.append(
                {
                    "type": "DMARC",
                    "priority": "WARN",
                    "description": "Upgrade DMARC policy from 'quarantine' to 'reject' for maximum protection",
                    "current": "p=quarantine",
                    "recommended": "p=reject",
                    "auto_fix": lambda: self.fix_dmarc(
                        domain, "reject", scan_result.get("dmarc_rua") or f"dmarc@{domain}"
                    ),
                }
            )

        # TLS-RPT fix
        if not scan_result.get("tls_rpt_present"):
            fixes.append(
                {
                    "type": "TLS-RPT",
                    "priority": "WARN",
                    "description": "Add TLS-RPT for TLS failure reporting",
                    "current": "Not configured",
                    "recommended": f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}",
                    "auto_fix": lambda: self.fix_tls_rpt(domain, f"tlsrpt@{domain}"),
                }
            )

        # MTA-STS fix &#8212; DNS record + Cloudflare Worker for HTTPS hosting
        if not scan_result.get("mta_sts_present"):
            mx_hosts = scan_result.get("mx_hosts", "")
            fixes.append(
                {
                    "type": "MTA-STS",
                    "priority": "WARN",
                    "description": "Add MTA-STS DNS record for enforced TLS",
                    "current": "Not configured",
                    "recommended": "v=STSv1; id=<timestamp>",
                    "auto_fix": lambda: self.fix_mta_sts_dns(domain),
                }
            )
            # MTA-STS HTTPS hosting &#8212; automated via Cloudflare Worker
            fixes.append(
                {
                    "type": "MTA-STS-HTTPS",
                    "priority": "WARN",
                    "description": f"Deploy Cloudflare Worker to serve MTA-STS policy at https://mta-sts.{domain}",
                    "current": "Not configured",
                    "recommended": "Cloudflare Worker serving /.well-known/mta-sts.txt",
                    "auto_fix": lambda mxh=mx_hosts: self.deploy_mta_sts_worker(domain, mxh),
                }
            )

        # DKIM &#8212; auto-detect email provider and create DNS records
        if not scan_result.get("dkim_present"):
            provider = self.detect_email_provider(scan_result.get("mx_hosts", ""))
            provider_name = provider.get("name", "Unknown")
            if provider.get("provider") != "unknown":
                # Known provider &#8212; fully automated DKIM fix
                fixes.append(
                    {
                        "type": "DKIM",
                        "priority": "HIGH",
                        "description": f"Auto-configure DKIM DNS records for {provider_name}",
                        "current": "No DKIM selectors found",
                        "recommended": f"DKIM CNAME/TXT records for {provider_name} selectors",
                        "auto_fix": lambda sr=scan_result: self.fix_dkim(domain, sr),
                        "note": f"Detected email provider: {provider_name}",
                    }
                )
            else:
                # Unknown provider &#8212; provide guidance but still try generic fix
                fixes.append(
                    {
                        "type": "DKIM",
                        "priority": "HIGH",
                        "description": "Configure DKIM signing &#8212; email provider not auto-detected",
                        "current": "No DKIM selectors found",
                        "recommended": f'selector1._domainkey.{domain}. IN TXT "v=DKIM1; k=rsa; p=<public_key>"',
                        "auto_fix": None,
                        "manual": True,
                        "steps": (
                            "Could not detect your email provider from MX records.\n"
                            "1. Log into your email provider admin console\n"
                            "2. Enable DKIM signing and generate a key pair\n"
                            "3. Copy the DNS record provided by your email provider\n"
                            "4. Add it to your domain's DNS via Cloudflare dashboard"
                        ),
                    }
                )

        return fixes


def get_cloudflare_client() -> Optional[CloudflareDNS]:
    """
    Get configured Cloudflare client if credentials are available.

    Returns:
        CloudflareDNS instance or None if not configured
    """
    if not CF_API_TOKEN or not CF_ZONE_ID:
        return None
    return CloudflareDNS()


# Legacy feature snapshot retained for compatibility with existing reports.
# Vendor capabilities and commercial terms change frequently, so callers must
# present this data with the disclaimer below and verify it before procurement.
COMPARISON_DISCLAIMER = (
    "Legacy illustrative snapshot only. Vendor capabilities, support, and pricing "
    "change; verify current details with each vendor before making a purchasing "
    "or security decision."
)

TOOL_COMPARISON = {
    "NorthFlux Security": {
        "type": "Self-hosted beta",
        "checks": ["SPF", "DKIM", "DMARC", "MTA-STS", "TLS-RPT", "STARTTLS", "BIMI", "Blacklist/RBL"],
        "auto_fix": True,
        "api": True,
        "reporting": ["CSV", "Markdown", "JSON", "Database", "PDF"],
        "cost": "Software licence not yet selected; infrastructure costs apply",
        "deployment": "Self-hosted",
        "unique": "Cloudflare remediation, DNS record generator, and score timeline",
    },
    "OnDMARC": {
        "type": "Commercial SaaS",
        "checks": ["SPF", "DKIM", "DMARC"],
        "auto_fix": False,
        "api": True,
        "reporting": ["Dashboard", "PDF"],
        "cost": "Verify with vendor",
        "deployment": "Cloud",
        "unique": "Managed service, enterprise support",
    },
    "EasyDMARC": {
        "type": "Commercial SaaS",
        "checks": ["SPF", "DKIM", "DMARC", "BIMI"],
        "auto_fix": False,
        "api": True,
        "reporting": ["Dashboard", "PDF", "Email"],
        "cost": "Verify with vendor",
        "deployment": "Cloud",
        "unique": "BIMI support, threat intelligence",
    },
    "dmarcian": {
        "type": "Commercial SaaS",
        "checks": ["SPF", "DKIM", "DMARC"],
        "auto_fix": False,
        "api": True,
        "reporting": ["Dashboard", "XML"],
        "cost": "Verify with vendor",
        "deployment": "Cloud",
        "unique": "DMARC-focused, detailed analytics",
    },
    "MXToolbox": {
        "type": "Freemium Online Tool",
        "checks": ["SPF", "DKIM", "DMARC", "Blacklist", "MX"],
        "auto_fix": False,
        "api": True,
        "reporting": ["Web", "Email Alerts"],
        "cost": "Verify with vendor",
        "deployment": "Cloud",
        "unique": "Blacklist monitoring, diagnostics",
    },
}


def generate_comparison_report() -> str:
    """Generate a labelled legacy feature-snapshot report."""
    lines = [
        "# Email Security Tool Comparison",
        "",
        f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
        "",
        f"> **Important:** {COMPARISON_DISCLAIMER}",
        "",
        "## Feature Matrix",
        "",
        "| Feature | NorthFlux Security | OnDMARC | EasyDMARC | dmarcian | MXToolbox |",
        "|---------|------------|---------|-----------|----------|-----------|",
    ]

    # Build comparison rows
    features = [
        ("Type", "type"),
        ("SPF Check", lambda t: "&#10003;" if "SPF" in t["checks"] else "&#10007;"),
        ("DKIM Check", lambda t: "&#10003;" if "DKIM" in t["checks"] else "&#10007;"),
        ("DMARC Check", lambda t: "&#10003;" if "DMARC" in t["checks"] else "&#10007;"),
        ("MTA-STS Check", lambda t: "&#10003;" if "MTA-STS" in t["checks"] else "&#10007;"),
        ("TLS-RPT Check", lambda t: "&#10003;" if "TLS-RPT" in t["checks"] else "&#10007;"),
        ("BIMI Check", lambda t: "&#10003;" if "BIMI" in t["checks"] else "&#10007;"),
        ("Blacklist/RBL", lambda t: "&#10003;" if "Blacklist/RBL" in t.get("checks", []) or "Blacklist" in t.get("checks", []) else "&#10007;"),
        ("Auto-Fix DNS", lambda t: "&#10003;" if t["auto_fix"] else "&#10007;"),
        ("PDF Reports", lambda t: "&#10003;" if "PDF" in t.get("reporting", []) else "&#10007;"),
        ("API Access", lambda t: "&#10003;" if t["api"] else "&#10007;"),
        ("Cost", "cost"),
        ("Deployment", "deployment"),
    ]

    tools = ["NorthFlux Security", "OnDMARC", "EasyDMARC", "dmarcian", "MXToolbox"]

    for feature_name, key in features:
        row = [feature_name]
        for tool in tools:
            t = TOOL_COMPARISON[tool]
            if callable(key):
                val = key(t)
            else:
                val = t.get(key, "N/A")
            row.append(str(val))
        lines.append("| " + " | ".join(row) + " |")

    lines.extend(
        [
            "",
            "## Key Differentiators",
            "",
            "### NorthFlux Security Characteristics",
            "- **Supported DNS Remediation**: Cloudflare API integration with ownership and scope guards",
            "- **Self-Hosted**: Operator-controlled deployment and local application storage",
            "- **Operator Control**: Monitoring and remediation remain independently opt-in",
            "- **Protocol Coverage**: Includes SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, and blacklist checks",
            "- **Source Availability**: Repository visibility does not grant reuse rights; review the selected licence before reuse",
            "",
            "### Typical Managed-Service Characteristics",
            "- **Managed Operations**: The vendor may operate the service infrastructure",
            "- **Support Options**: Commercial support and service commitments may be available",
            "- **Hosted Analytics**: Capabilities vary by vendor and plan and must be verified",
            "",
        ]
    )

    return "\n".join(lines)
