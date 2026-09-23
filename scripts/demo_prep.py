#!/usr/bin/env python3
"""
demo_prep.py &#8212; Prepare auroraedge.co.uk for a controlled authorised Auto-Fix demonstration.

SAFETY NOTICE: Legacy mutation modes are disabled. Only --dry-run is supported;
it prints an offline educational preview and does not contact Cloudflare.

This script talks directly to the Cloudflare API and puts the demo domain
into a known weak state so that the NorthFlux auto-fixer has something real
to repair during a live demo.

Actions
-------
1.  Weaken SPF from -all to ~all  &#8594; SPF softfail
2.  Downgrade DMARC to p=quarantine; pct=50  &#8594; weak DMARC
3.  DELETE the MTA-STS DNS record  &#8594; MTA-STS missing
4.  (TLS-RPT, DKIM already configured &#8212; left intact)

After running this, the domain should scan as Grade D with at least five
violations (R3C_SPF_SOFTFAIL, R5B_DMARC_QUARANTINE, R5C_DMARC_PCT,
R8_MTA_STS_MISSING, R12_NO_STRICT_POLICY).  You can then hit "Auto-Fix DNS"
on the scan results page to let NorthFlux repair everything automatically.

Usage
-----
    python scripts/demo_prep.py --dry-run            # offline historical preview
    python scripts/demo_prep.py --restore --dry-run  # offline restore-plan preview

No credentials are read by the supported preview. The old write implementation
below is quarantined and cannot be invoked through its public helpers.
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
    sys.exit("ERROR: 'requests' library not found &#8212; pip install requests")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DOMAIN = "auroraedge.co.uk"
CF_API_BASE = "https://api.cloudflare.com/client/v4"
DISABLED_MESSAGE = (
    "Legacy demo DNS writes are disabled: this script cannot safely preserve "
    "unrelated records or restore an operator's original configuration. "
    "Use --dry-run for an offline preview, or the validated dashboard operator "
    "workflow with an authorised test zone and a recovery plan."
)

# Records used to reset the demo domain to the known weak state
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
    {
        "type": "TXT",
        "name": f"_mta-sts.{DOMAIN}",
        "label": "MTA-STS",
        "restore_value": f"v=STSv1; id=20260414000000",
    },
]


def _db_path() -> Path:
    """Locate the NorthFlux database, with the legacy filename as fallback."""
    candidates = [
        Path(__file__).resolve().parent.parent / "state" / "northflux.db",
        Path("state/northflux.db"),
        Path(__file__).resolve().parent.parent / "state" / "auroraedge.db",
        Path("state/auroraedge.db"),
    ]
    for p in candidates:
        if p.exists():
            return p
    sys.exit("ERROR: Could not find state/northflux.db (or legacy auroraedge.db) &#8212; run from the project root.")


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
    raise RuntimeError(DISABLED_MESSAGE)
    url = f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}"
    resp = requests.delete(url, headers=_cf_headers(token), timeout=15)
    data = resp.json()
    ok = data.get("success", False)
    if ok:
        print(f"  &#10003; Deleted {name} (id={record_id})")
    else:
        print(f"  &#10007; Failed to delete {name}: {data}")
    return ok


def _create_record(token: str, zone_id: str, name: str, content: str) -> bool:
    raise RuntimeError(DISABLED_MESSAGE)
    url = f"{CF_API_BASE}/zones/{zone_id}/dns_records"
    payload = {"type": "TXT", "name": name, "content": content, "ttl": 3600}
    resp = requests.post(url, headers=_cf_headers(token), json=payload, timeout=15)
    data = resp.json()
    ok = data.get("success", False)
    if ok:
        print(f"  &#10003; Created {name} &#8594; {content}")
    else:
        print(f"  &#10007; Failed to create {name}: {data}")
    return ok


# ---------------------------------------------------------------------------
# Main actions
# ---------------------------------------------------------------------------

def break_records():
    """Disabled historical mutation entry point; never read credentials."""
    raise RuntimeError(DISABLED_MESSAGE)
    print(f"\n&#128295; DEMO RESET &#8212; Setting DNS records to the controlled demo state for {DOMAIN}")
    print("=" * 55)

    token, zone_id = _get_cf_creds()
    changes = 0

    for rec in RECORDS_TO_WEAKEN:
        print(f"\n[{rec['label']}] Setting {rec['name']} to the demo state ...")
        existing = _find_records(token, zone_id, rec["type"], rec["name"])
        for ex in existing:
            _delete_record(token, zone_id, ex["id"], rec["name"])
        if _create_record(token, zone_id, rec["name"], rec["weak_value"]):
            changes += 1

    for rec in RECORDS_TO_DELETE:
        print(f"\n[{rec['label']}] Removing {rec['name']} for the demo state ...")
        matches = _find_records(token, zone_id, rec["type"], rec["name"])
        if not matches:
            print(f"  &#8211; Record not found (already removed)")
            continue
        for m in matches:
            if _delete_record(token, zone_id, m["id"], rec["name"]):
                changes += 1

    print(f"\n{'=' * 55}")
    print(f"Done &#8212; {changes} change(s) applied.")
    print(f"\nExpected scan result after DNS propagation:")
    print(f"  &#8226; SPF     &#8594; &#9888; ~all (softfail, not -all)")
    print(f"  &#8226; DMARC   &#8594; &#9888; p=quarantine; pct=50 (weak)")
    print(f"  &#8226; MTA-STS &#8594; &#10060; Missing")
    print(f"  &#8226; TLS-RPT &#8594; &#9989; Present (unchanged)")
    print(f"  &#8226; DKIM    &#8594; &#9989; Present (Google selector)")
    print(f"\nYou can now scan {DOMAIN} and run the authorised Auto-Fix demo flow.\n")


def restore_records():
    """Disabled historical restoration entry point; never read credentials."""
    raise RuntimeError(DISABLED_MESSAGE)
    print(f"\n&#128260; RESTORE &#8212; Strengthening DNS records for {DOMAIN}")
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

    for rec in RECORDS_TO_DELETE:
        label = rec["label"]
        restore_val = rec.get("restore_value", "")
        if not restore_val:
            continue
        print(f"\n[{label}] Recreating {rec['name']} ...")
        existing = _find_records(token, zone_id, rec["type"], rec["name"])
        if existing:
            print(f"  &#8211; Already exists, skipping")
            continue
        if _create_record(token, zone_id, rec["name"], restore_val):
            changes += 1

    print(f"\n{'=' * 55}")
    print(f"Done &#8212; {changes} record(s) restored.")
    print(f"Run a scan to verify the domain is healthy again.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Offline historical DNS demonstration preview; legacy writes are disabled"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print the historical plan without credentials or network access",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Show the historical restore plan (requires --dry-run; changes nothing)",
    )
    args = parser.parse_args()

    if not args.dry_run:
        parser.error(DISABLED_MESSAGE)
    key = "strong_value" if args.restore else "weak_value"
    print(f"Historical example only for {DOMAIN}; not a recommended configuration.")
    for record in RECORDS_TO_WEAKEN:
        print(f"{record['label']}: {record['name']} -> {record[key]}")
    print("MTA-STS: " + ("historical example would restore TXT" if args.restore else "historical example would remove TXT"))
    print("No DNS records were changed; this preview made no network requests.")


if __name__ == "__main__":
    main()
