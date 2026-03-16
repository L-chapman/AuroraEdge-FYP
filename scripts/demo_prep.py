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

After running this, the domain should scan as Grade D with at least five
violations (R3C_SPF_SOFTFAIL, R5B_DMARC_QUARANTINE, R5C_DMARC_PCT,
R8_MTA_STS_MISSING, R12_NO_STRICT_POLICY).  You can then hit "Auto-Fix DNS"
on the scan results page to let AuroraEdge repair everything automatically.

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
RECORDS_TO_WEAKEN = [
    {
        "type": "TXT",
        "name": DOMAIN,
        "label": "SPF",
        "weak_value": f"v=spf1 include:_spf.google.com ~all",
        "strong_value": f"v=spf1 include:_spf.google.com -all",
    },
    {
        "type": "TXT",
        "name": f"_dmarc.{DOMAIN}",
        "label": "DMARC",
        "weak_value": f"v=DMARC1; p=quarantine; pct=50; aspf=s; adkim=s; rua=mailto:dmarc@{DOMAIN}; ruf=mailto:dmarc@{DOMAIN}",
        "strong_value": f"v=DMARC1; p=reject; pct=100; aspf=s; adkim=s; rua=mailto:dmarc@{DOMAIN}; ruf=mailto:dmarc@{DOMAIN}",
    },
]

RECORDS_TO_DELETE = [
    {"type": "TXT", "name": f"_mta-sts.{DOMAIN}", "label": "MTA-STS"},
]


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
    """Weaken SPF/DMARC and remove MTA-STS to simulate a vulnerable domain."""
    print(f"\n🔧 DEMO PREP — Weakening DNS records for {DOMAIN}")
    print("=" * 55)

    token, zone_id = _get_cf_creds()
    changes = 0

    for rec in RECORDS_TO_WEAKEN:
        print(f"\n[{rec['label']}] Weakening {rec['name']} ...")
        existing = _find_records(token, zone_id, rec["type"], rec["name"])
        for ex in existing:
            _delete_record(token, zone_id, ex["id"], rec["name"])
        if _create_record(token, zone_id, rec["name"], rec["weak_value"]):
            changes += 1

    for rec in RECORDS_TO_DELETE:
        print(f"\n[{rec['label']}] Deleting {rec['name']} ...")
        matches = _find_records(token, zone_id, rec["type"], rec["name"])
        if not matches:
            print(f"  – Record not found (already removed)")
            continue
        for m in matches:
            if _delete_record(token, zone_id, m["id"], rec["name"]):
                changes += 1

    print(f"\n{'=' * 55}")
    print(f"Done — {changes} change(s) applied.")
    print(f"\nExpected scan result after DNS propagation:")
    print(f"  • SPF     → ⚠ ~all (softfail, not -all)")
    print(f"  • DMARC   → ⚠ p=quarantine; pct=50 (weak)")
    print(f"  • MTA-STS → ❌ Missing")
    print(f"  • TLS-RPT → ✅ Present (unchanged)")
    print(f"  • DKIM    → ✅ Present (Google selector)")
    print(f"\nYou can now scan {DOMAIN} and click 'Auto-Fix DNS'.\n")


def restore_records():
    """Restore records to their strong/fixed state."""
    print(f"\n🔄 RESTORE — Strengthening DNS records for {DOMAIN}")
    print("=" * 55)

    token, zone_id = _get_cf_creds()
    changes = 0

    for rec in RECORDS_TO_WEAKEN:
        label = rec["label"]
        print(f"\n[{label}] Restoring {rec['name']} to strong value ...")
        existing = _find_records(token, zone_id, rec["type"], rec["name"])
        for ex in existing:
            _delete_record(token, zone_id, ex["id"], rec["name"])
        if _create_record(token, zone_id, rec["name"], rec["strong_value"]):
            changes += 1

    print(f"\n{'=' * 55}")
    print(f"Done — {changes} record(s) restored.")
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
