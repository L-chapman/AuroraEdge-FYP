"""Run NorthFlux with deterministic, disposable state for browser tests."""

from __future__ import annotations

import atexit
import os
import shutil
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = PROJECT_ROOT / "frontend" / ".e2e-data"


def _clean_runtime_root(*, strict: bool = True) -> None:
    """Remove only the fixed browser-test runtime directory."""
    expected_parent = PROJECT_ROOT / "frontend"
    if RUNTIME_ROOT.parent != expected_parent:
        raise RuntimeError("Refusing to clean an unexpected browser-test path")
    try:
        if RUNTIME_ROOT.is_symlink() or RUNTIME_ROOT.is_file():
            RUNTIME_ROOT.unlink(missing_ok=True)
        elif RUNTIME_ROOT.exists():
            shutil.rmtree(RUNTIME_ROOT)
    except OSError:
        if strict:
            raise


_clean_runtime_root()
RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
# This handler is registered before the application imports logging, so Python
# closes log handlers before removing their files during normal shutdown. A
# forced process termination can leave this one ignored directory behind; the
# strict startup cleanup above removes it before the next browser test run.
atexit.register(_clean_runtime_root, strict=False)

os.environ.update(
    {
        "NORTHFLUX_ENV": "development",
        "NORTHFLUX_SERVE_REACT": "true",
        "NORTHFLUX_FRONTEND_DIST": str(PROJECT_ROOT / "frontend" / "dist"),
        "NORTHFLUX_STATE_DIR": str(RUNTIME_ROOT / "state"),
        "NORTHFLUX_REPORTS_DIR": str(RUNTIME_ROOT / "reports"),
        "NORTHFLUX_LOGS_DIR": str(RUNTIME_ROOT / "logs"),
        "NORTHFLUX_PUBLIC_ORIGIN": "http://127.0.0.1:4173",
        "DASH_TOKEN": "northflux-e2e-operator-token-0123456789",
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
        "CF_API_TOKEN": "",
        "CF_ZONE_ID": "",
        "CF_ACCOUNT_ID": "",
        "CF_API_KEY": "",
        "CF_EMAIL": "",
    }
)
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from app import dashboard  # noqa: E402
from app import database as database_module  # noqa: E402


def _close_test_database() -> None:
    """Close the already-created singleton without creating one at shutdown."""
    database = getattr(database_module, "_db_instance", None)
    if database is not None:
        database.close()


atexit.register(_close_test_database)


def deterministic_scan(domain: str, check_starttls: bool = False) -> dict:
    """Return a representative scan without touching external DNS or SMTP."""
    weak = domain.startswith("weak")
    incomplete = domain.startswith("incomplete.")
    return {
        "domain": domain,
        "spf_present": True,
        "spf_record": "v=spf1 -all",
        "spf_lookups": 0,
        "spf_includes": "",
        "spf_all": "-all",
        "mx_present": True,
        "mx_count": 1,
        "mx_hosts": f"mail.{domain}",
        "dmarc_present": not weak,
        "dmarc_policy": "reject" if not weak else "",
        "dmarc_strength": "strong" if not weak else "missing",
        "dmarc_sp": "reject" if not weak else "",
        "dmarc_aspf": "s" if not weak else "",
        "dmarc_adkim": "s" if not weak else "",
        "dmarc_pct": 100 if not weak else 0,
        "dmarc_rua": f"mailto:dmarc@{domain}" if not weak else "",
        "dmarc_ruf": "",
        "dkim_present": not weak,
        "dkim_selectors": "default" if not weak else "",
        "dkim_algos": "rsa" if not weak else "",
        "mta_sts_present": not weak,
        "mta_sts_mode": "enforce" if not weak else "",
        "mta_sts_max_age": 604800 if not weak else 0,
        "tls_rpt_present": not weak,
        "tls_rpt_rua": f"mailto:tls@{domain}" if not weak else "",
        "bimi_present": False,
        "bimi_logo": "",
        "rbl_listings": 0,
        "starttls_grade": "A",
        "starttls_worst": "TLSv1.2",
        "notes": "A DNS lookup timed out in this synthetic example" if incomplete else "Deterministic browser-test scan",
        "scan_incomplete": incomplete,
        "check_starttls": check_starttls,
    }


dashboard.scan_domain = deterministic_scan
dashboard.SCAN_TIMEOUT = 5
# The same test server serves every browser project; keep production's rate
# limiter out of this deterministic journey suite. Rate limiting is covered by
# backend tests and remains unchanged in normal application launches.
dashboard._SCAN_RATE_MAX = 1000
dashboard.HAS_DNS_FIX = False
dashboard.get_cloudflare_client = lambda: None


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        dashboard.app,
        host="127.0.0.1",
        port=4173,
        log_level="warning",
    )
