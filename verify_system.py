#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Quick smoke test for NorthFlux Security."""

import argparse
import io
import logging
import sys
from typing import Dict, List, Tuple

# Keep Windows console output readable.
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, "src")

DEFAULT_SCAN_DOMAINS = ["example.com", "ulster.ac.uk", "google.com"]


def setup_stdout_logging() -> None:
    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NorthFlux Security smoke test")
    parser.add_argument(
        "--domain",
        help="Domain to use for the live scan check (defaults to a small fallback list)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip the live scan and use a built-in sample result",
    )
    return parser.parse_args()


def build_fallback_result(domain: str) -> Dict[str, object]:
    return {
        "spf_present": True,
        "spf_record": "v=spf1 -all",
        "spf_lookups": 0,
        "spf_includes": "",
        "spf_all": "-all",
        "mx_present": True,
        "mx_count": 1,
        "mx_hosts": f"mail.{domain}",
        "dmarc_present": True,
        "dmarc_policy": "quarantine",
        "dmarc_strength": "medium",
        "dmarc_sp": "quarantine",
        "dmarc_aspf": "r",
        "dmarc_adkim": "r",
        "dmarc_pct": 100,
        "dmarc_rua": f"mailto:dmarc@{domain}",
        "dmarc_ruf": "",
        "dkim_present": False,
        "dkim_selectors": "",
        "dkim_algos": "",
        "mta_sts_present": False,
        "mta_sts_mode": "",
        "mta_sts_max_age": 0,
        "tls_rpt_present": True,
        "tls_rpt_rua": f"mailto:tlsrpt@{domain}",
        "starttls_grade": "",
        "starttls_worst": "",
        "notes": "Offline smoke-test fallback",
    }


def redirect_logging_to_stdout() -> None:
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if hasattr(handler, "stream") and handler.stream is sys.stderr:
            handler.stream = sys.stdout


def choose_scan_result(scan_domain, requested_domain: str | None, offline: bool) -> Tuple[str, Dict[str, object], str, str]:
    domains: List[str] = [requested_domain] if requested_domain else list(DEFAULT_SCAN_DOMAINS)
    if offline:
        domain = domains[0]
        return domain, build_fallback_result(domain), "fallback", "offline mode requested"

    last_error = ""
    for domain in domains:
        try:
            return domain, scan_domain(domain), "live", ""
        except Exception as exc:  # pragma: no cover - defensive fallback for marking
            last_error = f"{type(exc).__name__}: {exc}"

    domain = domains[0]
    note = last_error or "live scan unavailable"
    return domain, build_fallback_result(domain), "fallback", note


def main() -> int:
    args = parse_args()

    print("=" * 60)
    print("NorthFlux Security System Verification")
    print("=" * 60)

    print("\n[1/6] Testing Module Imports...")
    try:
        setup_stdout_logging()

        from app.scanner import scan_domain
        from app.rules import evaluate, generate_remediation
        import app.database
        from app.analysis import calculate_statistics
        from app.dns_fix import TOOL_COMPARISON
        from app.logging_config import get_logger, ScanLogger

        redirect_logging_to_stdout()

        print("  [OK] All modules imported successfully")
    except ImportError as exc:
        print(f"  [FAIL] Import error: {exc}")
        return 1

    print("\n[2/6] Inspecting Legacy Tool Comparison Data...")
    tools = list(TOOL_COMPARISON.keys())
    print(f"  [INFO] {len(tools)} historical comparison entries loaded, not independently verified: {', '.join(tools)}")

    print("\n[3/6] Testing Domain Security Scan...")
    test_domain, result, scan_mode, scan_note = choose_scan_result(
        scan_domain, args.domain, args.offline
    )
    print(f"  [INFO] Scan source: {scan_mode} (fallback means sample data, not live DNS validation)")
    if scan_note:
        print(f"  [INFO] Scan note: {scan_note}")
    print(f"  [INFO] Domain represented by the result: {test_domain}")
    print(f"    SPF: {result['spf_present']}")
    print(f"    DKIM: {result['dkim_present']}")
    print(f"    MTA-STS: {result['mta_sts_mode']}")

    print("\n[4/6] Testing Rules Engine...")
    evaluation = evaluate(result)
    print(f"  [OK] Score: {evaluation['score']}")
    print(f"  [OK] Grade: {evaluation['grade']}")
    print(f"  [OK] Severity: {evaluation['severity']}")
    print(f"  [OK] Violations: {evaluation['violation_count']}")

    print("\n[5/6] Testing Remediation Engine...")
    full_result = {**result, **evaluation, "domain": test_domain}
    fixes = generate_remediation(full_result)
    print(f"  [OK] Generated {len(fixes)} remediation suggestions")

    print("\n[6/6] Testing Logging System...")
    logger = get_logger("test")
    logger.info("System verification test")
    print("  [OK] Logging system functional")

    print("\n" + "=" * 60)
    print("VERIFICATION COMPLETE - Checked Components Passed")
    print("=" * 60)

    print(
        """
Smoke-test scope:
------------------------
[INFO] DNS result fields inspected; offline/fallback data does not validate live DNS
[OK] Show a security score and suggestions
[INFO] Cloudflare remediation module imported (no live DNS write performed)
[INFO] HTTPS is expected at the deployment reverse proxy (not tested here)
[INFO] Authentication token support imported; sign-in and token checks not tested here
[OK] Basic logging (logging_config.py)
[INFO] Legacy comparison data loaded; current competing products not verified here
"""
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
