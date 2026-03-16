#!/usr/bin/env python3
"""
demo_prep.py — Prepare auroraedge.co.uk for an Auto-Fix demonstration.

This script talks directly to the Cloudflare API and **intentionally
degrades** DNS records so that the AuroraEdge auto-fixer has something to
repair during a live demo.

Actions
-------
1.  Weaken SPF from -all to ~all  → SPF softfail
2.  Downgrade DMARC to p=quarantine; pct=50  → weak DMARC
3.  DELETE the MTA-STS DNS record  → MTA-STS missing
4.  (TLS-RPT, DKIM already configured — left intact)

After running this, the domain should scan as Grade D/F with at least four
violations (R3_DMARC_MISSING, R6_DKIM_NOT_FOUND, R8_MTA_STS_MISSING,
R9_TLS_RPT_MISSING).  You can then hit "Auto-Fix DNS" on the scan
results page to let AuroraEdge repair everything automatically.

Usage
-----
    python scripts/demo_prep.py            # break records
    python scripts/demo_prep.py --restore  # put them back manually

Credentials are read from the AuroraEdge SQLite database (state/aurora.db)
so they stay consistent with the running server.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("ERROR: 'requests' library not found — pip install requests")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DOMAIN = "auroraedge.co.uk"
CF_API_BASE = "https://api.cloudflare.com/client/v4"

# Records to break for the demo
RECORDS_TO_DELETE = [
    {"type": "TXT", "name": f"_dmarc.{DOMAIN}",     "label": "DMARC"},
    {"type": "TXT", "name": f"_smtp._tls.{DOMAIN}",  "label": "TLS-RPT"},
]

# Default values used by --restore to recreate the records
RESTORE_DEFAULTS = {
    f"_dmarc.{DOMAIN}":    f"v=DMARC1; p=reject; rua=mailto:dmarc@{DOMAIN}",
    f"_smtp._tls.{DOMAIN}": f"v=TLSRPTv1; rua=mailto:tlsrpt@{DOMAIN}",
}


def _db_path() -> Path:
    """Locate the AuroraEdge SQLite database."""
    candidates = [
        Path(__file__).resolve().parent.parent / "state" / "auroraedge.db",
        Path("state/auroraedge.db"),
    ]
    for p in candidates:
        if p.exists():
            return p
    sys.exit("ERROR: Could not find state/auroraedge.db — run from the project root.")


def _get_cf_creds() -> tuple[str, str]:
    """Read Cloudflare credentials from the settings table."""
    db_file = _db_path()
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM settings WHERE key IN ('cf_api_token', 'cf_zone_id')")
    rows = {r["key"]: r["value"] for r in cur.fetchall()}
    conn.close()

    token = rows.get("cf_api_token", "")
    zone = rows.get("cf_zone_id", "")
    if not token or not zone:
        sys.exit(
            "ERROR: Cloudflare credentials not found in the database.\n"
            "Start the server and configure them under Settings first."
        )
    return token, zone


def _cf_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _find_records(token: str, zone_id: str, record_type: str, name: str):
    """Return a list of matching DNS records."""
    url = f"{CF_API_BASE}/zones/{zone_id}/dns_records?type={record_type}&name={name}"
    resp = requests.get(url, headers=_cf_headers(token), timeout=15)
    data = resp.json()
    if not data.get("success"):
        print(f"  WARNING: API error when listing {name}: {data}")
        return []
    return data.get("result", [])


def _delete_record(token: str, zone_id: str, record_id: str, name: str) -> bool:
    url = f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}"
    resp = requests.delete(url, headers=_cf_headers(token), timeout=15)
    data = resp.json()
    ok = data.get("success", False)
    if ok:
        print(f"  ✓ Deleted {name} (id={record_id})")
    else:
        print(f"  ✗ Failed to delete {name}: {data}")
    return ok


def _create_record(token: str, zone_id: str, name: str, content: str) -> bool:
    url = f"{CF_API_BASE}/zones/{zone_id}/dns_records"
    payload = {"type": "TXT", "name": name, "content": content, "ttl": 3600}
    resp = requests.post(url, headers=_cf_headers(token), json=payload, timeout=15)
    data = resp.json()
    ok = data.get("success", False)
    if ok:
        print(f"  ✓ Created {name} → {content}")
    else:
        print(f"  ✗ Failed to create {name}: {data}")
    return ok


# ---------------------------------------------------------------------------
# Main actions
# ---------------------------------------------------------------------------

def break_records():
    """Delete DMARC and TLS-RPT records to simulate a vulnerable domain."""
    print(f"\n🔧 DEMO PREP — Breaking DNS records for {DOMAIN}")
    print("=" * 55)

    token, zone_id = _get_cf_creds()
    deleted = 0

    for rec in RECORDS_TO_DELETE:
        print(f"\n[{rec['label']}] Looking up {rec['name']} ...")
        matches = _find_records(token, zone_id, rec["type"], rec["name"])
        if not matches:
            print(f"  – Record not found (already removed or never existed)")
            continue
        for m in matches:
            if _delete_record(token, zone_id, m["id"], rec["name"]):
                deleted += 1

    print(f"\n{'=' * 55}")
    print(f"Done — deleted {deleted} record(s).")
    print(f"\nExpected scan result after DNS propagation:")
    print(f"  • DMARC   → ❌ Missing")
    print(f"  • TLS-RPT → ❌ Missing")
    print(f"  • DKIM    → ❌ Missing  (was already absent)")
    print(f"  • MTA-STS → ❌ Missing  (was already absent)")
    print(f"  • SPF     → ✅ Present")
    print(f"\nYou can now scan {DOMAIN} and click 'Auto-Fix DNS'.\n")


def restore_records():
    """Recreate the deleted records with sensible defaults."""
    print(f"\n🔄 RESTORE — Recreating DNS records for {DOMAIN}")
    print("=" * 55)

    token, zone_id = _get_cf_creds()
    created = 0

    for name, content in RESTORE_DEFAULTS.items():
        label = "DMARC" if "_dmarc" in name else "TLS-RPT"
        print(f"\n[{label}] Creating {name} ...")
        # Remove existing first to avoid duplicates
        existing = _find_records(token, zone_id, "TXT", name)
        for ex in existing:
            _delete_record(token, zone_id, ex["id"], name)
        if _create_record(token, zone_id, name, content):
            created += 1

    print(f"\n{'=' * 55}")
    print(f"Done — created {created} record(s).")
    print(f"Run a scan to verify the domain is healthy again.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Prepare auroraedge.co.uk DNS for AuroraEdge auto-fix demo"
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Recreate the deleted records instead of breaking them",
    )
    args = parser.parse_args()

    if args.restore:
        restore_records()
    else:
        break_records()


if __name__ == "__main__":
    main()
