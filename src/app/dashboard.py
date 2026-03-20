"""
AuroraEdge Security – Automated Email Authentication & Cyber Defence System.

This module provides the web-based defence dashboard including:
- Real-time monitoring with SSE
- Automated domain scanning and threat assessment
- Interactive security analysis with remediation
- Automated DNS remediation via Cloudflare
- Historical scan tracking and drift alerts
- Token-based authentication

Reference: FastAPI is used for its async support and automatic OpenAPI documentation.
"""

import os
import re
import sys
import csv
import json
import asyncio
import logging
import concurrent.futures
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse, RedirectResponse

# ---------------------------------------------------------------------------
# Route uvicorn logs to stdout so PowerShell doesn't treat them as errors.
# Uvicorn writes INFO messages to stderr by default, which triggers
# NativeCommandError in PowerShell terminals.
# ---------------------------------------------------------------------------
_stdout_handler = logging.StreamHandler(sys.stdout)
_stdout_handler.setFormatter(logging.Formatter("%(levelname)s:     %(message)s"))
for _uv_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    _uv_log = logging.getLogger(_uv_logger_name)
    _uv_log.handlers.clear()
    _uv_log.addHandler(_stdout_handler)
    _uv_log.propagate = False

# ---------------------------------------------------------------------------
# Domain input sanitisation
# ---------------------------------------------------------------------------
_DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$'
)


def _sanitize_domain(raw) -> tuple:
    """Coerce *raw* to a clean, validated domain string.

    Returns ``(domain, None)`` on success or ``("", error_msg)`` on failure.
    """
    if raw is None:
        return ("", "Domain is required")
    domain = str(raw).strip().lower()
    # Strip common protocol prefixes users might paste in
    for prefix in ("https://", "http://", "ftp://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]          # Remove trailing path
    domain = domain.split("?")[0]          # Remove query string
    if not domain:
        return ("", "Domain is required")
    if not _DOMAIN_RE.match(domain):
        return ("", "Invalid domain format")
    # Reject bare IP addresses – we need a real domain for DNS checks
    if all(part.isdigit() for part in domain.split(".")):
        return ("", "IP addresses are not valid – enter a domain name")
    return (domain, None)


# Database import with fallback
try:
    from app.database import get_database, AuroraDatabase

    HAS_DB = True
except ImportError:
    HAS_DB = False
    AuroraDatabase = None

# Scanner and rules imports for live testing
try:
    from app.scanner import scan_domain
    from app.rules import evaluate, generate_remediation

    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False
    scan_domain = None
    evaluate = None
    generate_remediation = None

# DNS auto-fix imports
try:
    from app.dns_fix import CloudflareDNS, get_cloudflare_client, TOOL_COMPARISON

    HAS_DNS_FIX = True
except ImportError:
    HAS_DNS_FIX = False
    CloudflareDNS = None
    get_cloudflare_client = None
    TOOL_COMPARISON = {}

# Rule explanations import
try:
    from app.rules import (
        SEVERITY_EXPLANATIONS,
        RULE_EXPLANATIONS,
        get_severity_explanation,
        get_rule_explanation,
    )

    HAS_EXPLANATIONS = True
except ImportError:
    HAS_EXPLANATIONS = False
    SEVERITY_EXPLANATIONS = {}
    RULE_EXPLANATIONS = {}

    def get_severity_explanation(s):
        return {}

    def get_rule_explanation(r):
        return {}


logger = logging.getLogger("auroraedge")

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Modern lifespan handler — runs startup logic, then yields control."""
    # Expand the default thread-pool so multiple DNS scans can run concurrently
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=8))
    logger.info("Thread pool expanded to 8 workers for concurrent scanning")

    if HAS_DB:
        try:
            db = get_database()
            clear = db.get_setting("clear_on_start", "true").lower() in ("true", "1", "yes")
            if clear:
                db.clear_scan_data()
                logger.info("Database cleared for fresh session (clear_on_start=true)")
            else:
                logger.info("Keeping previous scan data (clear_on_start=false)")
            db.set_setting("demo_domain", "auroraedge.co.uk")
            logger.info("Demo domain seeded: auroraedge.co.uk")
        except Exception as e:
            logger.warning("Could not initialise database on startup: %s", e)

    global _monitor_task
    _monitor_task = asyncio.create_task(_monitoring_loop())
    logger.info("Background monitoring task started")

    yield  # Application runs here

    # Shutdown: cancel monitoring task
    if _monitor_task and not _monitor_task.done():
        _monitor_task.cancel()
        logger.info("Background monitoring task cancelled")


app = FastAPI(
    title="AuroraEdge Security",
    description="Automated Email Authentication & Cyber Defence System",
    version="3.1",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Security headers middleware  (OWASP recommended)
# ---------------------------------------------------------------------------
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers into every HTTP response."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent caching of API and dynamic HTML responses
        if "text/html" in response.headers.get("content-type", "") or "application/json" in response.headers.get("content-type", ""):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # CSP: allow inline styles/scripts (needed for single-file dashboard),
        # Chart.js CDN, and data: URIs for favicons.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter for scan endpoints
# ---------------------------------------------------------------------------
import time as _time
_scan_rate: dict = {}          # ip -> [timestamp, timestamp, ...]
_SCAN_RATE_WINDOW = 60         # seconds
_SCAN_RATE_MAX = 10            # max scans per window


def _rate_check(request: Request):
    """Raise 429 if the client exceeds the scan rate limit."""
    ip = request.client.host if request.client else "unknown"
    # Skip rate limiting for test clients
    if ip == "testclient":
        return
    now = _time.monotonic()
    hits = _scan_rate.get(ip, [])
    # Prune old entries
    hits = [t for t in hits if now - t < _SCAN_RATE_WINDOW]
    if len(hits) >= _SCAN_RATE_MAX:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded — max {_SCAN_RATE_MAX} scans per {_SCAN_RATE_WINDOW}s",
        )
    hits.append(now)
    _scan_rate[ip] = hits


# ---------------------------------------------------------------------------
# Custom 404 page — branded HTML instead of raw JSON
# ---------------------------------------------------------------------------
from fastapi.responses import HTMLResponse as _HTMLResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


@app.exception_handler(StarletteHTTPException)
async def _custom_http_exception(request: Request, exc: StarletteHTTPException):
    """Return a branded HTML page for 404 errors, JSON for API errors."""
    if exc.status_code == 404 and not request.url.path.startswith("/api/"):
        return _HTMLResponse(
            status_code=404,
            content=f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>404 \u2014 AuroraEdge Security</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e1a;
         color: #e2e8f0; display: flex; align-items: center; justify-content: center;
         min-height: 100vh; margin: 0; }}
  .box {{ text-align: center; max-width: 420px; }}
  h1 {{ font-size: 4rem; margin: 0; background: linear-gradient(135deg, #38bdf8, #a78bfa);
       -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  p {{ color: #94a3b8; margin: 1rem 0; }}
  a {{ color: #38bdf8; text-decoration: none; font-weight: 600; }}
  a:hover {{ text-decoration: underline; }}
</style></head><body><div class="box">
  <h1>404</h1>
  <p>The page <code>{request.url.path}</code> was not found.</p>
  <p><a href="/">\u2190 Back to Dashboard</a></p>
</div></body></html>""",
        )
    # For API routes and non-404 errors, return standard JSON
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


# Project root and reports directory
ROOT = Path(__file__).resolve().parents[2]
REPORTS_ROOT = ROOT / "reports"
REPORTS = REPORTS_ROOT / "indexed"
STATE = ROOT / "state"


def _env(name: str, default: str = "") -> str:
    """Get environment variable with default."""
    return os.environ.get(name, default)


def require_token(req: Request):
    """
    Token-based authentication dependency.

    Accepts token via:
    - Query parameter: ?token=xxx
    - Authorization header: Bearer xxx

    If DASH_TOKEN is not set, allows open access (development mode).
    """
    want = _env("DASH_TOKEN", "")
    if not want:
        return  # No token set -> open access (dev only)

    # Check query parameter
    qtok = req.query_params.get("token")
    if qtok and qtok == want:
        return

    # Check Authorization header
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and auth.split(" ", 1)[1] == want:
        return

    raise HTTPException(status_code=401, detail="Unauthorized - valid token required")


def list_csvs() -> List[Path]:
    """List all CSV report files, newest first."""
    files: List[Path] = []
    if REPORTS.exists():
        files.extend(REPORTS.glob("*_results_*.csv"))
    if REPORTS_ROOT.exists():
        files.extend(REPORTS_ROOT.glob("*_results_*.csv"))
    files = sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def load_csv(p: Path) -> List[Dict[str, str]]:
    """Load CSV file and return as list of dictionaries.
    Skips comment rows (domain starting with #) which are dataset headers."""
    rows: List[Dict[str, str]] = []
    if not p.exists():
        return rows
    with p.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            # Skip comment/header rows (e.g. '# AuroraEdge Academic Dataset')
            domain = (row.get("domain") or "").strip()
            if domain.startswith("#") or domain.startswith("\ufeff#"):
                continue
            rows.append({k: (v or "") for k, v in row.items()})
    return rows


def _latest_pair() -> tuple[Optional[Path], Optional[Path]]:
    """Get the latest CSV and its matching Markdown file."""
    files = list_csvs()
    if not files:
        return None, None
    newest = files[0]
    md = newest.with_suffix(".md")
    return newest, (md if md.exists() else None)


def _severity_counts(rows: List[Dict[str, str]]) -> Dict[str, int]:
    """Count results by severity level."""
    counts = {"OK": 0, "WARN": 0, "HIGH": 0, "INFO": 0, "CRITICAL": 0, "OTHER": 0}
    for r in rows:
        sev = (r.get("severity", "") or "").upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["OTHER"] += 1
    counts["TOTAL"] = len(rows)
    return counts


def _grade_counts(rows: List[Dict[str, str]]) -> Dict[str, int]:
    """Count results by letter grade."""
    counts = {"A+": 0, "A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for r in rows:
        grade = (r.get("grade", "") or "").upper()
        if grade in counts:
            counts[grade] += 1
        elif grade:
            counts["F"] += 1
    return counts


def _score_stats(rows: List[Dict[str, str]]) -> Dict[str, float]:
    """Calculate score statistics."""
    scores = []
    for r in rows:
        try:
            scores.append(float(r.get("score", 0)))
        except Exception:
            continue
    if not scores:
        return {"avg": 0.0, "min": 0.0, "max": 0.0, "count": 0}
    return {
        "avg": round(sum(scores) / len(scores), 1),
        "min": min(scores),
        "max": max(scores),
        "count": len(scores),
    }


# =============================================================================
# API Endpoints
# =============================================================================

# Track last modification time for change detection
_last_mtime: float = 0.0


def _check_for_updates() -> tuple[bool, float]:
    """Check if reports have been updated."""
    global _last_mtime
    files = list_csvs()
    if not files:
        return False, 0.0
    current_mtime = files[0].stat().st_mtime
    if current_mtime > _last_mtime:
        _last_mtime = current_mtime
        return True, current_mtime
    return False, current_mtime


@app.get("/health")
def health():
    """Health check endpoint."""
    return {
        "ok": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "3.1",
    }


@app.get("/api/stream", dependencies=[Depends(require_token)])
async def stream_updates():
    """
    Server-Sent Events endpoint for real-time updates.
    Clients can subscribe to this for live dashboard updates.
    """

    async def event_generator():
        last_check = 0.0
        while True:
            has_update, mtime = _check_for_updates()
            if has_update or mtime != last_check:
                # Send update event
                csv_file, _ = _latest_pair()
                if csv_file:
                    rows = load_csv(csv_file)
                    data = {
                        "type": "update",
                        "file": csv_file.name,
                        "counts": _severity_counts(rows),
                        "grades": _grade_counts(rows),
                        "scores": _score_stats(rows),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                last_check = mtime

            # Also send heartbeat every 30 seconds
            yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
            await asyncio.sleep(5)  # Check every 5 seconds

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/runs", dependencies=[Depends(require_token)])
def api_runs():
    """List all scan runs (CSV files)."""
    files = [
        {
            "name": p.name,
            "mtime": p.stat().st_mtime,
            "size": p.stat().st_size,
            "date": datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
        }
        for p in list_csvs()
    ]
    return {"count": len(files), "files": files}


@app.get("/api/latest", dependencies=[Depends(require_token)])
def api_latest():
    """Get the latest scan results."""
    csv_file, _ = _latest_pair()
    if not csv_file:
        return {"rows": [], "file": None}
    return {"rows": load_csv(csv_file), "file": csv_file.name}


@app.get("/api/summary", dependencies=[Depends(require_token)])
def api_summary():
    """Get summary statistics for the latest scan."""
    csv_file, _ = _latest_pair()
    if not csv_file:
        return {"file": None, "counts": {}, "total": 0, "scores": {}, "grades": {}}
    rows = load_csv(csv_file)
    counts = _severity_counts(rows)
    return {
        "file": csv_file.name,
        "counts": counts,
        "grades": _grade_counts(rows),
        "total": counts.get("TOTAL", 0),
        "scores": _score_stats(rows),
    }


@app.get("/api/domain/{domain}", dependencies=[Depends(require_token)])
def api_domain(domain: str):
    """Get latest result for a specific domain — checks DB first, falls back to CSV."""
    # Try database first
    if HAS_DB:
        try:
            db = get_database()
            history = db.get_domain_history(domain, limit=1)
            if history:
                return {"domain": domain, "result": history[0], "source": "database"}
        except Exception:
            pass

    # Fallback to CSV
    csv_file, _ = _latest_pair()
    if csv_file:
        rows = load_csv(csv_file)
        for row in rows:
            if row.get("domain", "").lower() == domain.lower():
                return {"domain": domain, "result": row, "source": "csv"}

    raise HTTPException(
        status_code=404, detail=f"No scan data found for {domain}. Try scanning it first."
    )


@app.get("/api/search", dependencies=[Depends(require_token)])
def api_search(
    q: str = Query(None, description="Search query (domain name)"),
    severity: str = Query(None, description="Filter by severity"),
    grade: str = Query(None, description="Filter by grade"),
    min_score: int = Query(None, description="Minimum score"),
    max_score: int = Query(None, description="Maximum score"),
):
    """Search and filter scan results."""
    rows = []

    if HAS_DB:
        try:
            db = get_database()
            latest_rows = db.get_latest_results(limit=500)
            # Keep only the newest result per domain so search reflects
            # the current platform state rather than every historical scan.
            seen_domains = set()
            for row in latest_rows:
                domain_name = (row.get("domain") or "").lower()
                if domain_name in seen_domains:
                    continue
                seen_domains.add(domain_name)
                rows.append(row)
        except Exception:
            rows = []

    if not rows:
        csv_file, _ = _latest_pair()
        if not csv_file:
            return {"results": [], "count": 0, "total": 0}
        rows = load_csv(csv_file)

    results = []

    for row in rows:
        # Apply filters
        if q and q.lower() not in row.get("domain", "").lower():
            continue
        if severity and row.get("severity", "").upper() != severity.upper():
            continue
        if grade and row.get("grade", "").upper() != grade.upper():
            continue

        try:
            score = float(row.get("score", 0))
        except ValueError:
            score = 0

        if min_score is not None and score < min_score:
            continue
        if max_score is not None and score > max_score:
            continue

        results.append(row)

    return {"results": results, "count": len(results), "total": len(rows)}


@app.get("/api/stats", dependencies=[Depends(require_token)])
def api_stats():
    """Get aggregate statistics from database."""
    if not HAS_DB:
        return {"error": "Database not available"}

    try:
        db = get_database()
        return db.get_statistics()
    except Exception as e:
        logger.error("Failed to get statistics: %s", e)
        return {"error": "Failed to retrieve statistics"}


@app.get("/api/explanations/severity/{severity}")
def api_severity_explanation(severity: str):
    """Get explanation for a severity level."""
    valid = {"OK", "INFO", "WARN", "HIGH", "CRITICAL"}
    if severity.upper() not in valid:
        raise HTTPException(status_code=404, detail=f"Unknown severity: {severity}")
    return get_severity_explanation(severity)


@app.get("/api/explanations/rule/{rule_id}")
def api_rule_explanation(rule_id: str):
    """Get explanation for a specific rule ID."""
    if rule_id not in RULE_EXPLANATIONS:
        raise HTTPException(status_code=404, detail="Unknown rule ID")
    return get_rule_explanation(rule_id)


@app.get("/api/explanations/all")
def api_all_explanations():
    """Get all severity and rule explanations."""
    return {
        "severities": SEVERITY_EXPLANATIONS,
        "rules": RULE_EXPLANATIONS,
    }


@app.get("/api/tools/comparison")
def api_tool_comparison():
    """Get tool comparison data for academic analysis."""
    if not HAS_DNS_FIX or not TOOL_COMPARISON:
        return {"tools": {}, "error": "Tool comparison data not available"}
    return {"tools": TOOL_COMPARISON}


@app.get("/api/history/{domain}", dependencies=[Depends(require_token)])
def api_history(domain: str, limit: int = 20):
    """Get historical scan results for a domain."""
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")

    clean, err = _sanitize_domain(domain)
    if err:
        raise HTTPException(status_code=404, detail="Domain not found")

    try:
        db = get_database()
        history = db.get_domain_history(clean, limit)
        return {"domain": clean, "history": history, "count": len(history)}
    except Exception as e:
        logger.error("Failed to fetch history for %s: %s", clean, e)
        raise HTTPException(status_code=500, detail="Failed to retrieve domain history")


@app.delete("/api/history/{domain}", dependencies=[Depends(require_token)])
def api_delete_history(domain: str):
    """Delete all scan history for a specific domain."""
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    clean, err = _sanitize_domain(domain)
    if err:
        raise HTTPException(status_code=400, detail=err)
    db = get_database()
    deleted = db.delete_domain_history(clean)
    return {"ok": True, "domain": clean, "deleted_records": deleted}


@app.post("/api/data/clear", dependencies=[Depends(require_token)])
def api_clear_all_data():
    """Clear all scan data (results, domains, alerts). Preserves settings."""
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    db = get_database()
    db.clear_scan_data()
    return {"ok": True, "message": "All scan data cleared. Settings preserved."}


# ---------------------------------------------------------------------------
# Single-domain rescan — used by "Rescan" buttons across the UI
# ---------------------------------------------------------------------------

@app.post("/api/rescan/{domain}", dependencies=[Depends(require_token)])
def api_rescan_domain(request: Request, domain: str):
    """Re-scan a single domain and persist updated results.

    This is the endpoint that every "Rescan" button in the UI calls.
    It mirrors the pattern used by RedSift OnDMARC and EasyDMARC where a
    single-domain refresh returns the full evaluation inline so the
    frontend can update without a page reload.

    Returns the new scan result, evaluation, and remediation list.
    """
    if not HAS_SCANNER:
        raise HTTPException(status_code=501, detail="Scanner module not available")

    _rate_check(request)

    clean, err = _sanitize_domain(domain)
    if err:
        raise HTTPException(status_code=400, detail=err)

    # Perform the scan
    scan_result = scan_domain(clean, check_starttls=False)
    scan_result["domain"] = clean
    evaluation = evaluate(scan_result)

    grade = evaluation.get("grade", "F")
    score = evaluation.get("score", 0)

    # Persist to DB
    if HAS_DB:
        try:
            db = get_database()
            scan_id = db.start_scan(notes=f"Rescan of {clean}")
            db.save_result(scan_id, clean, scan_result, evaluation)
            db.complete_scan(scan_id, 1)
            # Update managed-domain record (no-op if domain isn't managed)
            db.update_managed_domain_scan(clean, grade, score)
        except Exception as e:
            logger.warning(f"Rescan DB save failed for {clean}: {e}")

    # Generate remediation
    remediation_list = []
    try:
        remediation_list = generate_remediation({**scan_result, "domain": clean})
        if HAS_EXPLANATIONS:
            for item in remediation_list:
                rule_id = item.get("rule", "")
                if rule_id:
                    explanation = get_rule_explanation(rule_id)
                    item["why"] = explanation.get("why", "")
                    item["how_to_fix"] = explanation.get("how_to_fix", "")
                    item["example"] = explanation.get("example", "")
                    item["rfc"] = explanation.get("rfc", "")
    except Exception:
        pass

    # Enrich severity info
    severity = evaluation.get("severity", "OK")
    if HAS_EXPLANATIONS:
        try:
            severity_info = get_severity_explanation(severity)
            evaluation["severity_title"] = severity_info.get("title", severity)
            evaluation["severity_description"] = severity_info.get("description", "")
            evaluation["severity_impact"] = severity_info.get("impact", "")
            evaluation["severity_urgency"] = severity_info.get("urgency", "")
        except Exception:
            pass

    return {
        "status": "success",
        "domain": clean,
        "scan": scan_result,
        "evaluation": evaluation,
        "remediation": remediation_list,
    }


@app.get("/download/latest", dependencies=[Depends(require_token)])
def download_latest(kind: str = "csv"):
    """Download the latest report file."""
    csv_file, md_file = _latest_pair()
    if not csv_file:
        raise HTTPException(status_code=404, detail="No reports found")

    target = csv_file
    media = "text/csv"

    if kind.lower() == "md":
        if md_file is None:
            raise HTTPException(status_code=404, detail="Markdown report not found")
        target = md_file
        media = "text/markdown"

    return FileResponse(target, media_type=media, filename=target.name)


@app.get("/download/{filename}", dependencies=[Depends(require_token)])
def download_file(filename: str):
    """Download a specific report file."""
    # Sanitize filename
    safe_name = Path(filename).name
    file_path = REPORTS / safe_name
    if not file_path.exists():
        file_path = REPORTS_ROOT / safe_name

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    if file_path.suffix == ".csv":
        media = "text/csv"
    elif file_path.suffix == ".md":
        media = "text/markdown"
    else:
        media = "application/octet-stream"

    return FileResponse(file_path, media_type=media, filename=safe_name)


@app.get("/api/report/pdf/{domain}", dependencies=[Depends(require_token)])
def api_pdf_report(domain: str):
    """Generate a professional PDF security report for a single domain."""
    clean, err = _sanitize_domain(domain)
    if err:
        raise HTTPException(status_code=400, detail=err)

    # Gather data from DB
    result = None
    if HAS_DB:
        try:
            db = get_database()
            history = db.get_domain_history(clean, limit=1)
            if history:
                result = history[0]
        except Exception:
            pass

    if not result:
        raise HTTPException(status_code=404, detail=f"No scan data for {clean}")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        import io

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20*mm, bottomMargin=15*mm)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, spaceAfter=6)
        subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=10, textColor=colors.grey)

        story.append(Paragraph("AuroraEdge Security Report", title_style))
        story.append(Paragraph(f"Domain: {clean}", styles["Heading2"]))
        scanned = (result.get("scanned_at") or "Unknown")[:19].replace("T", " ")
        story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Last Scan: {scanned}", subtitle_style))
        story.append(Spacer(1, 10*mm))

        # Score summary
        grade = result.get("grade", "F")
        score = result.get("score", 0)
        severity = result.get("severity", "OK")
        story.append(Paragraph(f"Grade: {grade} &nbsp;&nbsp; Score: {score}/100 &nbsp;&nbsp; Severity: {severity}", styles["Heading3"]))
        story.append(Spacer(1, 5*mm))

        # Security checks table
        def _b(val):
            if val is None:
                return False
            if isinstance(val, (bool, int)):
                return bool(val)
            return str(val).strip().lower() in ("true", "1", "yes")

        checks_data = [["Check", "Status", "Details"]]
        check_items = [
            ("SPF", _b(result.get("spf_present")), f"Lookups: {result.get('spf_lookups', 'N/A')}, All: {result.get('spf_all', 'N/A')}"),
            ("DMARC", _b(result.get("dmarc_present")), f"Policy: {result.get('dmarc_policy', 'N/A')}, pct: {result.get('dmarc_pct', 'N/A')}"),
            ("DKIM", _b(result.get("dkim_present")), f"Selectors: {result.get('dkim_selectors', 'N/A')}"),
            ("MTA-STS", _b(result.get("mta_sts_present")), f"Mode: {result.get('mta_sts_mode', 'N/A')}"),
            ("TLS-RPT", _b(result.get("tls_rpt_present")), f"RUA: {result.get('tls_rpt_rua', 'N/A')}"),
            ("BIMI", _b(result.get("bimi_present")), f"Logo: {result.get('bimi_logo', 'N/A') or 'Not set'}"),
            ("MX Records", _b(result.get("mx_present")), f"{result.get('mx_count', 0)} records"),
        ]
        for name, ok, detail in check_items:
            checks_data.append([name, "PASS" if ok else "FAIL", detail])

        t = Table(checks_data, colWidths=[60*mm, 30*mm, 80*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4f46e5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Paragraph("Security Checks", styles["Heading3"]))
        story.append(t)
        story.append(Spacer(1, 5*mm))

        # Violations
        violations = result.get("violations") or "None"
        advice = result.get("advice") or "All checks passed"
        story.append(Paragraph("Violations & Recommendations", styles["Heading3"]))
        story.append(Paragraph(f"<b>Issues:</b> {violations}", styles["Normal"]))
        story.append(Paragraph(f"<b>Advice:</b> {advice}", styles["Normal"]))
        story.append(Spacer(1, 8*mm))

        story.append(Paragraph("Report generated by AuroraEdge — Automated Email Authentication & Cyber Defence System", subtitle_style))

        doc.build(story)
        buf.seek(0)

        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="auroraedge_{clean}_{datetime.now(timezone.utc).strftime("%Y%m%d")}.pdf"'}
        )
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF generation requires 'reportlab'. Install with: pip install reportlab")
    except Exception as e:
        logger.error("PDF generation failed for %s: %s", clean, e)
        raise HTTPException(status_code=500, detail="PDF generation failed — check server logs")


# =============================================================================
# Managed Domains API (SME Onboarding)
# =============================================================================


@app.get("/api/managed-domains", dependencies=[Depends(require_token)])
def api_managed_domains():
    """List all managed (onboarded) domains."""
    if not HAS_DB:
        return {"domains": [], "error": "Database not available"}
    db = get_database()
    domains = db.get_managed_domains()
    alert_count = db.get_alert_count()
    return {"domains": domains, "count": len(domains), "alert_count": alert_count}


@app.post("/api/managed-domains", dependencies=[Depends(require_token)])
async def api_add_managed_domain(request: Request):
    """
    Add a domain for continuous monitoring.
    POST body: {"domain": "example.com", "notes": "Our main domain"}
    """
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    domain, err = _sanitize_domain(body.get("domain"))
    if err:
        raise HTTPException(status_code=400, detail=err)
    db = get_database()
    result = db.add_managed_domain(domain, body.get("notes", ""))

    # Run initial scan immediately
    if HAS_SCANNER:
        try:
            scan_result = scan_domain(domain, check_starttls=False)
            scan_result["domain"] = domain
            evaluation = evaluate(scan_result)
            grade = evaluation.get("grade", "F")
            score = evaluation.get("score", 0)
            db.update_managed_domain_scan(domain, grade, score)
            # Save to results DB
            scan_id = db.start_scan(notes=f"Onboarding scan for {domain}")
            db.save_result(scan_id, domain, scan_result, evaluation)
            db.complete_scan(scan_id, 1)
            result["initial_scan"] = {
                "grade": grade, "score": score,
                "severity": evaluation.get("severity", "OK")
            }

            # AUTO-FIX: apply all DNS fixes immediately — no human in the loop
            fix_result = _auto_fix_domain(domain, scan_result)
            result["auto_fix"] = fix_result

            # If fixes were applied, rescan to get updated grade
            if fix_result.get("applied"):
                import time
                time.sleep(2)  # Brief pause for DNS propagation
                rescan = scan_domain(domain, check_starttls=False)
                rescan["domain"] = domain
                re_eval = evaluate(rescan)
                new_grade = re_eval.get("grade", grade)
                new_score = re_eval.get("score", score)
                db.update_managed_domain_scan(domain, new_grade, new_score)
                result["post_fix_scan"] = {
                    "grade": new_grade, "score": new_score,
                    "severity": re_eval.get("severity", "OK"),
                    "improved": new_score > score,
                }

        except Exception as e:
            result["initial_scan"] = {"error": str(e)}

    return result


@app.delete("/api/managed-domains/{domain}", dependencies=[Depends(require_token)])
def api_remove_managed_domain(domain: str):
    """Remove a domain from continuous monitoring."""
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    db = get_database()
    removed = db.remove_managed_domain(domain)
    if not removed:
        raise HTTPException(status_code=404, detail="Domain not found")
    return {"ok": True, "domain": domain}


# =============================================================================
# Settings API
# =============================================================================


@app.get("/api/settings", dependencies=[Depends(require_token)])
def api_get_settings():
    """Get all application settings."""
    if not HAS_DB:
        return {"settings": {}}
    db = get_database()
    settings = db.get_all_settings()
    # Mask the CF token for security
    if "cf_api_token" in settings and settings["cf_api_token"]:
        token = settings["cf_api_token"]
        settings["cf_api_token_masked"] = token[:8] + "..." + token[-4:] if len(token) > 12 else "***"
        del settings["cf_api_token"]
    if "cf_api_key" in settings and settings["cf_api_key"]:
        api_key = settings["cf_api_key"]
        settings["cf_api_key_masked"] = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
        del settings["cf_api_key"]
    return {"settings": settings}


@app.post("/api/settings", dependencies=[Depends(require_token)])
async def api_save_settings(request: Request):
    """
    Save application settings.
    POST body: {"cf_api_token": "...", "cf_zone_id": "...", "monitor_interval": "24", ...}
    """
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    db = get_database()
    allowed_keys = [
        "cf_api_token", "cf_zone_id", "cf_account_id",
        "cf_api_key", "cf_email",
        "monitor_interval", "alert_email", "org_name", "clear_on_start",
    ]
    allowed_intervals = {"6", "12", "24", "48", "168"}
    saved = []
    for key in allowed_keys:
        if key in body:
            if key == "monitor_interval":
                interval = str(body[key]).strip()
                if interval not in allowed_intervals:
                    raise HTTPException(
                        status_code=400,
                        detail="monitor_interval must be one of: 6, 12, 24, 48, 168",
                    )
            db.set_setting(key, str(body[key]))
            saved.append(key)

    # If CF credentials provided, update the live dns_fix module
    if any(k in body for k in ("cf_api_token", "cf_zone_id", "cf_account_id", "cf_api_key", "cf_email")):
        _apply_cf_settings(db)

    return {"ok": True, "saved": saved}


def _apply_cf_settings(db):
    """Push DB-stored CF credentials into the dns_fix module at runtime."""
    if not HAS_DNS_FIX:
        return
    import app.dns_fix as dns_mod
    token = db.get_setting("cf_api_token")
    zone = db.get_setting("cf_zone_id")
    account_id = db.get_setting("cf_account_id")
    api_key = db.get_setting("cf_api_key")
    email = db.get_setting("cf_email")
    if token:
        dns_mod.CF_API_TOKEN = token
        os.environ["CF_API_TOKEN"] = token
    if zone:
        dns_mod.CF_ZONE_ID = zone
        os.environ["CF_ZONE_ID"] = zone
    if account_id:
        dns_mod.CF_ACCOUNT_ID = account_id
        os.environ["CF_ACCOUNT_ID"] = account_id
    if api_key:
        dns_mod.CF_API_KEY = api_key
        os.environ["CF_API_KEY"] = api_key
    if email:
        dns_mod.CF_EMAIL = email
        os.environ["CF_EMAIL"] = email


def _auto_fix_domain(domain: str, scan_result: dict = None) -> dict:
    """
    Automatically scan and fix ALL DNS issues for a domain via Cloudflare.
    No human in the loop — applies every available fix.

    Args:
        domain: The domain name to fix
        scan_result: Optional pre-existing scan result (avoids double scan)

    Returns:
        dict with keys: applied, failed, skipped_reason (if CF not available)
    """
    if not HAS_DNS_FIX:
        return {"applied": [], "failed": [], "skipped_reason": "DNS fix module not available"}

    # Ensure CF credentials are loaded
    if HAS_DB:
        db = get_database()
        _apply_cf_settings(db)

    cf = get_cloudflare_client()
    if not cf:
        return {"applied": [], "failed": [], "skipped_reason": "Cloudflare not configured"}

    ok, msg = cf.validate_connection()
    if not ok:
        return {"applied": [], "failed": [], "skipped_reason": f"Cloudflare connection failed: {msg}"}

    # OWNERSHIP CHECK: ensure the domain belongs to the configured Cloudflare zone
    owned, ownership_msg = cf.verify_domain_ownership(domain)
    if not owned:
        logger.warning(f"Auto-fix blocked for {domain}: {ownership_msg}")
        return {"applied": [], "failed": [], "skipped_reason": ownership_msg}

    # Scan if no result provided
    if scan_result is None:
        if not HAS_SCANNER:
            return {"applied": [], "failed": [], "skipped_reason": "Scanner not available"}
        scan_result = scan_domain(domain, check_starttls=False)
        scan_result["domain"] = domain

    # Generate and apply ALL fixes — zero human intervention
    fixes = cf.generate_fixes(scan_result)
    applied = []
    failed = []

    for fix in fixes:
        fix_type = fix.get("type", "Unknown")
        try:
            auto_fix_fn = fix.get("auto_fix")
            if auto_fix_fn:
                success, message = auto_fix_fn()
                entry = {"type": fix_type, "success": success, "message": message}
                if success:
                    applied.append(entry)
                else:
                    failed.append(entry)
        except Exception as e:
            failed.append({"type": fix_type, "success": False, "message": str(e)})

    if applied:
        logger.info(f"Auto-fix {domain}: applied {len(applied)} fix(es) — {[f['type'] for f in applied]}")
    if failed:
        logger.warning(f"Auto-fix {domain}: {len(failed)} fix(es) failed — {[f['type'] for f in failed]}")

    return {"applied": applied, "failed": failed}


@app.get("/api/settings/test-cloudflare", dependencies=[Depends(require_token)])
def api_test_cloudflare():
    """Test the current Cloudflare connection using stored credentials.

    Returns ``zone_name`` so the frontend can perform a quick ownership
    pre-check before allowing auto-fix.  Also probes Workers API access
    and returns a granular permissions breakdown.
    """
    if not HAS_DB:
        return {"ok": False, "message": "Database not available", "zone_name": "", "workers": False, "permissions": {}}
    db = get_database()
    _apply_cf_settings(db)
    if not HAS_DNS_FIX:
        return {"ok": False, "message": "DNS fix module not available", "zone_name": "", "workers": False, "permissions": {}}
    cf = get_cloudflare_client()
    if not cf:
        return {"ok": False, "message": "Cloudflare not configured — add API token and Zone ID in Settings", "zone_name": "", "workers": False, "permissions": {}}
    ok, msg = cf.validate_connection()
    zone = (cf.zone_name or "").strip().lower().rstrip(".")

    # Granular permission probing
    perms = {"zone_read": ok, "dns_edit": False, "workers": False}
    account_id = None
    if ok:
        # Test DNS edit by listing records (safe read operation)
        try:
            import requests as _req
            _h = {"Authorization": f"Bearer {cf.api_token}", "Content-Type": "application/json"}
            dr = _req.get(f"{cf.base_url}?per_page=1", headers=_h, timeout=8)
            perms["dns_edit"] = dr.json().get("success", False)
        except Exception:
            pass

        # Get account ID (from settings or auto-detect from zone)
        account_id = db.get_setting("cf_account_id") or cf.get_account_id()

        # Actually probe Workers Scripts API (not just account ID existence)
        if account_id:
            try:
                import requests as _req
                _h = {"Authorization": f"Bearer {cf.api_token}", "Content-Type": "application/json"}
                wr = _req.get(
                    f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts",
                    headers=_h, timeout=8,
                )
                perms["workers"] = wr.json().get("success", False)
            except Exception:
                pass

        # Auto-store account ID if we discovered it and it wasn't saved
        if account_id and not db.get_setting("cf_account_id"):
            db.set_setting("cf_account_id", account_id)

    # Build feature availability summary
    features = []
    if perms["dns_edit"]:
        features.append("SPF, DMARC, DKIM, TLS-RPT, MTA-STS DNS")
    if perms["workers"]:
        features.append("MTA-STS HTTPS auto-hosting")

    return {
        "ok": ok,
        "message": msg,
        "zone_name": zone,
        "workers": perms["workers"],
        "permissions": perms,
        "account_id": account_id or "",
        "features": features,
    }


# =============================================================================
# Alerts API
# =============================================================================


@app.get("/api/alerts", dependencies=[Depends(require_token)])
def api_get_alerts(all: bool = False):
    """Get alerts (unacknowledged by default)."""
    if not HAS_DB:
        return {"alerts": [], "count": 0}
    db = get_database()
    alerts = db.get_alerts(unacknowledged_only=not all)
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/api/alerts/{alert_id}/acknowledge", dependencies=[Depends(require_token)])
def api_acknowledge_alert(alert_id: int):
    """Acknowledge (dismiss) an alert."""
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    db = get_database()
    ok = db.acknowledge_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"ok": True}


# =============================================================================
# Scheduled Monitoring (Background Task)
# =============================================================================

_monitor_task = None


async def _monitoring_loop():
    """Background task: rescan managed domains on schedule, detect drift."""
    while True:
        try:
            if not HAS_DB or not HAS_SCANNER:
                await asyncio.sleep(60)
                continue

            db = get_database()
            interval_hours = int(db.get_setting("monitor_interval", "24"))
            domains = db.get_managed_domains()

            if not domains:
                await asyncio.sleep(300)  # Check again in 5 min
                continue

            # Apply CF settings in case they were updated
            _apply_cf_settings(db)

            scan_id = db.start_scan(
                notes=f"Scheduled monitoring of {len(domains)} domain(s)"
            )

            for d in domains:
                domain = d["domain"]
                try:
                    scan_result = scan_domain(domain, check_starttls=False)
                    scan_result["domain"] = domain
                    evaluation = evaluate(scan_result)
                    grade = evaluation.get("grade", "F")
                    score = evaluation.get("score", 0)

                    # Save result
                    db.save_result(scan_id, domain, scan_result, evaluation)

                    # Update managed domain and detect drift
                    prev = db.update_managed_domain_scan(domain, grade, score)
                    prev_grade = prev.get("previous_grade")
                    prev_score = prev.get("previous_score")

                    # Drift detection: grade worsened
                    if prev_grade and prev_grade != grade:
                        grade_order = ["A+", "A", "B", "C", "D", "F"]
                        old_idx = grade_order.index(prev_grade) if prev_grade in grade_order else 5
                        new_idx = grade_order.index(grade) if grade in grade_order else 5
                        if new_idx > old_idx:
                            # Grade dropped
                            db.create_alert(
                                domain=domain,
                                alert_type="grade_drop",
                                severity="HIGH" if new_idx >= 4 else "WARN",
                                message=f"{domain} grade dropped from {prev_grade} to {grade}",
                                details=f"Score changed from {prev_score} to {score}",
                            )
                        elif new_idx < old_idx:
                            # Grade improved
                            db.create_alert(
                                domain=domain,
                                alert_type="grade_improved",
                                severity="INFO",
                                message=f"{domain} grade improved from {prev_grade} to {grade}",
                                details=f"Score changed from {prev_score} to {score}",
                            )

                    # AUTO-FIX: if domain is not A+ grade, attempt fixes
                    if grade not in ("A+", "A"):
                        fix_result = _auto_fix_domain(domain, scan_result)
                        if fix_result.get("applied"):
                            fix_types = [f["type"] for f in fix_result["applied"]]
                            db.create_alert(
                                domain=domain,
                                alert_type="auto_fix_applied",
                                severity="INFO",
                                message=f"Auto-fixed {domain}: {', '.join(fix_types)}",
                                details=f"Applied {len(fix_result['applied'])} fix(es) automatically",
                            )
                            # Rescan after fix to update grade
                            await asyncio.sleep(2)
                            rescan = scan_domain(domain, check_starttls=False)
                            rescan["domain"] = domain
                            re_eval = evaluate(rescan)
                            new_grade = re_eval.get("grade", grade)
                            new_score = re_eval.get("score", score)
                            db.update_managed_domain_scan(domain, new_grade, new_score)

                except Exception as e:
                    db.create_alert(
                        domain=domain,
                        alert_type="scan_error",
                        severity="HIGH",
                        message=f"Failed to scan {domain}: {str(e)}",
                    )

                # Small delay between domains to avoid rate limiting
                await asyncio.sleep(2)

            db.complete_scan(scan_id, len(domains))

        except Exception as e:
            logger.error(f"Monitoring loop error: {e}")

        # Sleep until next cycle
        try:
            db = get_database()
            interval_hours = int(db.get_setting("monitor_interval", "24"))
        except Exception:
            interval_hours = 24
        await asyncio.sleep(interval_hours * 3600)


# Startup logic has been moved to the lifespan() context manager above.


# =============================================================================
# HTML Dashboard
# =============================================================================


def _auth_js() -> str:
    """Inject a tiny script that extracts the auth token from the URL and
    patches ``fetch`` / ``EventSource`` / nav links so the token propagates
    automatically.  This makes the dashboard work correctly when
    ``DASH_TOKEN`` is set in production.
    """
    return """
<script>
(function(){
    const _tok = new URLSearchParams(window.location.search).get('token') || '';

    /* ---------- patch fetch ---------- */
    const _origFetch = window.fetch;
    window.fetch = function(url, opts) {
        if (_tok && typeof url === 'string' && url.startsWith('/api/')) {
            opts = opts || {};
            opts.headers = opts.headers || {};
            if (opts.headers instanceof Headers) {
                if (!opts.headers.has('Authorization')) opts.headers.set('Authorization', 'Bearer ' + _tok);
            } else {
                if (!opts.headers['Authorization']) opts.headers['Authorization'] = 'Bearer ' + _tok;
            }
        }
        return _origFetch.call(this, url, opts);
    };

    /* ---------- patch EventSource ---------- */
    const _origES = window.EventSource;
    window.EventSource = function(url, cfg) {
        if (_tok && typeof url === 'string' && url.startsWith('/api/')) {
            const sep = url.includes('?') ? '&' : '?';
            url = url + sep + 'token=' + encodeURIComponent(_tok);
        }
        return new _origES(url, cfg);
    };
    window.EventSource.prototype = _origES.prototype;

    /* ---------- patch nav links ---------- */
    document.addEventListener('DOMContentLoaded', function(){
        if (!_tok) return;
        document.querySelectorAll('a.nav-link, a.nav-brand').forEach(function(a){
            try {
                const u = new URL(a.href, window.location.origin);
                if (u.origin === window.location.origin) {
                    u.searchParams.set('token', _tok);
                    a.href = u.pathname + u.search;
                }
            } catch(e){}
        });
    });
})();

/* ---------- global toast notification system ---------- */
function showToast(message, type, duration) {
    type = type || 'info';
    duration = (duration === undefined) ? 5000 : duration;
    var container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;max-width:420px;';
        document.body.appendChild(container);
    }
    var colours = {
        success: 'border-left:4px solid #22c55e; background:rgba(34,197,94,0.15);',
        error:   'border-left:4px solid #ef4444; background:rgba(239,68,68,0.15);',
        info:    'border-left:4px solid #3b82f6; background:rgba(59,130,246,0.15);',
        warning: 'border-left:4px solid #eab308; background:rgba(234,179,8,0.15);'
    };
    var icons = { success:'✅', error:'❌', info:'ℹ️', warning:'⚠️' };
    var toast = document.createElement('div');
    toast.style.cssText = (colours[type] || colours.info) + 'padding:14px 18px;border-radius:8px;color:#e2e8f0;font-size:0.9rem;line-height:1.5;box-shadow:0 4px 12px rgba(0,0,0,0.3);cursor:pointer;white-space:pre-wrap;backdrop-filter:blur(8px);';
    toast.textContent = (icons[type] || '') + ' ' + message;
    toast.onclick = function(){ toast.remove(); };
    container.appendChild(toast);
    if (duration > 0) setTimeout(function(){ if (toast.parentNode) toast.remove(); }, duration);
    return toast;
}
</script>
"""


def _css() -> str:
    """Dashboard CSS styles - Modern, animated, user-friendly."""
    return """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

:root {
    --bg-primary: #0a0a14;
    --bg-secondary: #12121e;
    --bg-card: #1a1a2e;
    --bg-hover: #252542;
    --text-primary: #f8f8f8;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;
    --text-dim: #6b7280;
    --accent: #3b82f6;
    --accent-glow: rgba(59, 130, 246, 0.3);
    --accent-secondary: #8b5cf6;
    --success: #22c55e;
    --success-bg: rgba(34, 197, 94, 0.15);
    --warning: #f59e0b;
    --warning-bg: rgba(245, 158, 11, 0.15);
    --danger: #ef4444;
    --danger-bg: rgba(239, 68, 68, 0.15);
    --info: #3b82f6;
    --info-bg: rgba(59, 130, 246, 0.15);
    --border: rgba(255, 255, 255, 0.08);
    --shadow: 0 4px 24px rgba(0, 0, 0, 0.4);
    --radius: 16px;
    --radius-sm: 8px;

    /* Convenience aliases */
    --primary: #3b82f6;
    --accent-hover: #2563eb;
    --card-bg: #1a1a2e;
    --bg-tertiary: #16162a;
    --text: #f8f8f8;
    --bg: #0a0a14;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: linear-gradient(135deg, var(--bg-primary) 0%, #1a1a2e 100%);
    color: var(--text-primary);
    min-height: 100vh;
    padding: 24px;
    line-height: 1.6;
}

.container { max-width: 1600px; margin: 0 auto; }

/* Top Navigation Bar */
.top-nav {
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    margin: -24px -24px 24px -24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.nav-links {
    display: flex;
    gap: 8px;
}
.nav-link {
    padding: 10px 18px;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.9rem;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 8px;
}
.nav-link:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
}
.nav-link.active {
    background: var(--accent);
    color: white;
}
.nav-link.highlight {
    background: linear-gradient(135deg, var(--accent), var(--accent-secondary));
    color: white;
}
.nav-link.highlight:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px var(--accent-glow);
}
.nav-brand {
    font-weight: 700;
    font-size: 1.1rem;
    color: var(--text-primary);
    text-decoration: none;
    display: flex;
    align-items: center;
    gap: 10px;
}
.nav-brand-icon {
    font-size: 1.5rem;
}

/* Header */
header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 32px;
    padding: 28px 32px;
    background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-secondary) 100%);
    border-radius: var(--radius);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    position: relative;
    overflow: hidden;
}
header::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 4px;
    background: linear-gradient(90deg, var(--accent), var(--accent-secondary), var(--success));
}

.logo-area { display: flex; align-items: center; gap: 16px; }
.logo {
    width: 56px;
    height: 56px;
    background: linear-gradient(135deg, var(--accent), var(--accent-secondary));
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 28px;
    box-shadow: 0 4px 20px var(--accent-glow);
}

h1 {
    font-size: 1.85rem;
    font-weight: 700;
    background: linear-gradient(135deg, var(--accent), var(--accent-secondary));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.academic-badge {
    display: inline-block;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 6px 14px;
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin-left: 12px;
    font-weight: 500;
}

.header-right { display: flex; align-items: center; gap: 16px; }
.live-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    background: var(--success-bg);
    border-radius: 20px;
    font-size: 0.85rem;
    color: var(--success);
}
.live-dot {
    width: 8px;
    height: 8px;
    background: var(--success);
    border-radius: 50%;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(1.2); }
}

.subtitle { color: var(--text-secondary); font-size: 0.9rem; margin-top: 4px; }

h2 {
    color: var(--text-primary);
    font-size: 1.15rem;
    font-weight: 600;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}
h2::before {
    content: '';
    width: 4px;
    height: 20px;
    background: var(--accent);
    border-radius: 2px;
}

/* Stats Cards Grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
    margin-bottom: 32px;
}

.stat-card {
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 24px;
    border: 1px solid var(--border);
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}
.stat-card:hover {
    transform: translateY(-4px);
    box-shadow: var(--shadow);
    border-color: var(--accent);
}
.stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--accent), #ff6b9d);
}

.stat-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    margin-bottom: 16px;
}
.stat-icon.domains { background: var(--info-bg); }
.stat-icon.score { background: var(--success-bg); }
.stat-icon.high { background: var(--danger-bg); }
.stat-icon.warn { background: var(--warning-bg); }

.stat-value {
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 4px;
    font-variant-numeric: tabular-nums;
}
.stat-label { color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-change { font-size: 0.8rem; margin-top: 8px; }
.stat-change.up { color: var(--success); }
.stat-change.down { color: var(--danger); }

/* Two Column Layout */
.two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin-bottom: 32px;
}
@media (max-width: 1024px) {
    .two-col { grid-template-columns: 1fr; }
}

/* Section Cards */
.section-card {
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 24px;
    border: 1px solid var(--border);
}

/* Grade Distribution */
.grade-bars { display: flex; flex-direction: column; gap: 12px; }
.grade-bar-item { display: flex; align-items: center; gap: 12px; }
.grade-label {
    width: 40px;
    font-weight: 600;
    font-size: 0.9rem;
}
.grade-bar-container {
    flex: 1;
    height: 28px;
    background: var(--bg-secondary);
    border-radius: 6px;
    overflow: hidden;
}
.grade-bar {
    height: 100%;
    border-radius: 6px;
    transition: width 0.5s ease;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    padding-right: 8px;
    font-size: 0.8rem;
    font-weight: 600;
}
.grade-bar.a-plus, .grade-bar.a { background: linear-gradient(90deg, #22c55e, #4ade80); }
.grade-bar.b { background: linear-gradient(90deg, #06b6d4, #22d3d3); }
.grade-bar.c { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
.grade-bar.d { background: linear-gradient(90deg, #f97316, #fb923c); }
.grade-bar.f { background: linear-gradient(90deg, #dc2626, #ef4444); }
.grade-count { color: var(--text-secondary); font-size: 0.85rem; width: 40px; text-align: right; }

/* Severity Pills */
.severity-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
.severity-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px;
    border-radius: var(--radius-sm);
    transition: transform 0.2s ease;
}
.severity-item:hover { transform: scale(1.02); }
.severity-item.ok { background: var(--success-bg); border-left: 3px solid var(--success); }
.severity-item.info { background: var(--info-bg); border-left: 3px solid var(--info); }
.severity-item.warn { background: var(--warning-bg); border-left: 3px solid var(--warning); }
.severity-item.high { background: var(--danger-bg); border-left: 3px solid var(--danger); }
.sev-label { font-weight: 500; }
.sev-count { font-size: 1.5rem; font-weight: 700; }

/* Search & Filters */
.toolbar {
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    align-items: center;
}
.search-box {
    flex: 1;
    min-width: 250px;
    position: relative;
}
.search-box input {
    width: 100%;
    padding: 12px 16px 12px 44px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 0.95rem;
    transition: all 0.2s ease;
}
.search-box input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-glow);
}
.search-box::before {
    content: '🔍';
    position: absolute;
    left: 14px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 1rem;
}

.filter-select {
    padding: 12px 16px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 0.9rem;
    cursor: pointer;
}
.filter-select:focus { outline: none; border-color: var(--accent); }

/* Buttons */
.btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 12px 20px;
    border-radius: var(--radius-sm);
    font-weight: 600;
    font-size: 0.9rem;
    text-decoration: none;
    cursor: pointer;
    border: none;
    transition: all 0.2s ease;
}
.btn-primary {
    background: linear-gradient(135deg, var(--accent), #ff6b9d);
    color: white;
}
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 4px 16px var(--accent-glow); }
.btn-secondary {
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-primary);
}
.btn-secondary:hover { border-color: var(--accent); }

.downloads { display: flex; gap: 12px; flex-wrap: wrap; }

/* Results Table */
.table-container {
    background: var(--bg-card);
    border-radius: var(--radius);
    overflow: hidden;
    border: 1px solid var(--border);
}

table { width: 100%; border-collapse: collapse; }

thead {
    background: var(--bg-secondary);
    position: sticky;
    top: 0;
}

th {
    padding: 16px;
    text-align: left;
    font-weight: 600;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
    transition: color 0.2s;
}
th:hover { color: var(--accent); }
th.sorted { color: var(--accent); }
th.sorted::after { content: ' ↓'; }
th.sorted.asc::after { content: ' ↑'; }

td {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
}

tbody tr {
    transition: background 0.15s ease;
}
tbody tr:hover { background: var(--bg-hover); }

.domain-cell {
    font-weight: 600;
    color: var(--info);
}
.domain-cell a { color: inherit; text-decoration: none; }
.domain-cell a:hover { text-decoration: underline; }

/* Grade Badges */
.grade-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 0.85rem;
}
.grade-badge.a-plus, .grade-badge.a { background: var(--success-bg); color: var(--success); }
.grade-badge.b { background: rgba(6, 182, 212, 0.2); color: #06b6d4; }
.grade-badge.c { background: var(--warning-bg); color: var(--warning); }
.grade-badge.d { background: rgba(249, 115, 22, 0.2); color: #f97316; }
.grade-badge.f { background: var(--danger-bg); color: var(--danger); }

.score-cell {
    font-family: 'SF Mono', 'Consolas', monospace;
    font-weight: 600;
}

.check-icon { font-size: 1.1rem; }
.check-yes { color: var(--success); }
.check-no { color: var(--danger); }

/* Status Badge */
.status-badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}
.status-badge.ok { background: var(--success-bg); color: var(--success); }
.status-badge.warn { background: var(--warning-bg); color: var(--warning); }
.status-badge.high { background: var(--danger-bg); color: var(--danger); }
.status-badge.info { background: var(--info-bg); color: var(--info); }

/* Footer */
footer {
    text-align: center;
    padding: 32px;
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-top: 32px;
    border-top: 1px solid var(--border);
}
footer a { color: var(--accent); text-decoration: none; }
footer a:hover { text-decoration: underline; }

/* Refresh Indicator */
.refresh-toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: var(--bg-card);
    border: 1px solid var(--success);
    border-radius: var(--radius-sm);
    padding: 12px 20px;
    display: flex;
    align-items: center;
    gap: 10px;
    box-shadow: var(--shadow);
    transform: translateY(100px);
    opacity: 0;
    transition: all 0.3s ease;
}
.refresh-toast.show { transform: translateY(0); opacity: 1; }
.refresh-toast .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid var(--text-muted);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* Responsive */
@media (max-width: 768px) {
    body { padding: 12px; }
    header { flex-direction: column; gap: 16px; text-align: center; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .toolbar { flex-direction: column; }
    .search-box { min-width: 100%; }
    th, td { padding: 10px 8px; font-size: 0.8rem; }
}
</style>
"""


def _js() -> str:
    """Dashboard JavaScript for interactivity and real-time updates."""
    return """
<script>
// Auto-refresh configuration
const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds (reduced frequency)
let autoRefreshEnabled = true;
let lastUpdateTime = Date.now();
let lastKnownFile = document.querySelector('[data-file]')?.dataset.file || '';

// Initialize EventSource for real-time updates
function initSSE() {
    if (typeof EventSource === 'undefined') {
        console.warn('SSE not supported, falling back to polling');
        setInterval(checkForUpdates, AUTO_REFRESH_INTERVAL);
        return;
    }
    
    const evtSource = new EventSource('/api/stream');
    
    evtSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if (data.type === 'update' && data.file !== lastKnownFile) {
            // Update stats dynamically instead of full reload
            updateDashboardStats(data);
            lastKnownFile = data.file;
            showRefreshToast('Data updated');
        }
    };
    
    evtSource.onerror = function() {
        console.warn('SSE connection lost, will retry...');
        evtSource.close();
        // Retry SSE after 10 seconds instead of polling
        setTimeout(initSSE, 10000);
    };
}

// Dynamic stats update without page reload
function updateDashboardStats(data) {
    if (data.scores) {
        const avgEl = document.querySelector('.stat-value[data-stat="avg"]');
        if (avgEl) avgEl.textContent = data.scores.avg || 0;
    }
    if (data.counts) {
        const highEl = document.querySelector('.stat-value[data-stat="high"]');
        const warnEl = document.querySelector('.stat-value[data-stat="warn"]');
        if (highEl) highEl.textContent = data.counts.HIGH || 0;
        if (warnEl) warnEl.textContent = data.counts.WARN || 0;
    }
    // Update last update time
    const updateEl = document.getElementById('lastUpdate');
    if (updateEl) updateEl.textContent = 'Updated ' + new Date().toLocaleTimeString();
}

// Fallback polling - only reload if significantly new data
function checkForUpdates() {
    if (!autoRefreshEnabled) return;
    
    fetch('/api/summary')
        .then(res => res.json())
        .then(data => {
            if (data.file && data.file !== lastKnownFile) {
                // Only show toast, don't auto-reload
                showRefreshToast('New scan available - click to refresh');
                document.getElementById('refreshToast').onclick = () => location.reload();
            }
        })
        .catch(() => {});
}

// Toast notification
function showRefreshToast(message) {
    const toast = document.getElementById('refreshToast');
    if (toast) {
        toast.querySelector('.toast-message').textContent = message;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 3000);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Try SSE first
    initSSE();
    
    // Update last refresh time
    const timeEl = document.getElementById('lastUpdate');
    if (timeEl) {
        setInterval(() => {
            const seconds = Math.floor((Date.now() - lastUpdateTime) / 1000);
            timeEl.textContent = `Updated ${seconds}s ago`;
        }, 1000);
    }
});
</script>
"""


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_token)])
def home():
    """Main dashboard page with real-time updates."""

    # ── Gather managed-domain data from the DB ──────────────────────────
    domains_list: list = []
    alerts: list = []
    alert_count = 0
    org_name = "Your Organisation"
    if HAS_DB:
        try:
            db = get_database()
            domains_list = db.get_managed_domains()
            alerts = db.get_alerts(unacknowledged_only=True, limit=5)
            alert_count = db.get_alert_count()
            org_name = db.get_setting("org_name", "Your Organisation") or "Your Organisation"
        except Exception:
            pass

    # Filter out junk/test payloads from old security tests
    valid_domains = [d for d in domains_list if ":" not in d["domain"]
                     and "/" not in d["domain"]
                     and "javascript" not in d["domain"].lower()]
    total_domains = len(valid_domains)

    # Compute stats from managed domains
    scores = [d["last_score"] for d in valid_domains if d.get("last_score") is not None]
    avg_score = round(sum(scores) / len(scores)) if scores else 0
    grades = {}
    for d in valid_domains:
        g = d.get("last_grade") or "F"
        grades[g] = grades.get(g, 0) + 1
    passing = sum(1 for d in valid_domains if (d.get("last_score") or 0) >= 70)
    failing = total_domains - passing
    worst = sorted(valid_domains, key=lambda d: d.get("last_score") or 0)[:5]
    best = sorted(valid_domains, key=lambda d: d.get("last_score") or 0, reverse=True)[:3]

    # Overall health colour
    if avg_score >= 85:
        health_colour = "var(--success)"
        health_label = "Good"
        health_icon = "✅"
    elif avg_score >= 60:
        health_colour = "var(--warning)"
        health_label = "Needs Attention"
        health_icon = "⚠️"
    else:
        health_colour = "var(--danger)"
        health_label = "Critical"
        health_icon = "🔴"

    # ── Grade distribution mini-bar ─────────────────────────────────────
    max_g = max(grades.values()) if grades else 1
    grade_bars_html = ""
    for g, css_cls in [("A+","a-plus"),("A","a"),("B","b"),("C","c"),("D","d"),("F","f")]:
        cnt = grades.get(g, 0)
        w = round(cnt / max_g * 100) if max_g else 0
        grade_bars_html += f"""
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <span class="grade-badge {css_cls}" style="width:36px;text-align:center;">{g}</span>
            <div style="flex:1;background:var(--bg-secondary);border-radius:4px;height:22px;overflow:hidden;">
                <div style="width:{w}%;height:100%;background:var(--accent);border-radius:4px;transition:width .4s;"></div>
            </div>
            <span style="min-width:24px;text-align:right;color:var(--text-secondary);font-size:.85rem;">{cnt}</span>
        </div>"""

    # ── Domain health rows ──────────────────────────────────────────────
    domain_rows_html = ""
    for d in sorted(valid_domains, key=lambda x: x.get("last_score") or 0):
        dom = d["domain"]
        g = d.get("last_grade") or "F"
        g_cls = g.lower().replace("+", "-plus")
        s = d.get("last_score") or 0
        prev = d.get("previous_score")
        drift = ""
        if prev is not None and prev != s:
            drift = f' <span style="color:var(--success);font-size:.75rem;">▲{s-prev}</span>' if s > prev else f' <span style="color:var(--danger);font-size:.75rem;">▼{prev-s}</span>'
        last_scan = (d.get("last_scan_at") or "")[:16].replace("T", " ")
        domain_rows_html += f"""
        <tr>
            <td><a href="/domain/{dom}" style="color:var(--accent);text-decoration:none;font-weight:500;">{dom}</a></td>
            <td><span class="grade-badge {g_cls}">{g}</span></td>
            <td>{s}/100{drift}</td>
            <td style="color:var(--text-secondary);font-size:.85rem;">{last_scan}</td>
        </tr>"""

    # ── Alerts HTML ─────────────────────────────────────────────────────
    alerts_html = ""
    if alerts:
        for a in alerts[:5]:
            sev = (a.get("severity") or "info").lower()
            icon = "🔴" if sev == "high" else "⚠️" if sev == "warn" else "ℹ️"
            alerts_html += f"""
            <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);">
                <span>{icon}</span>
                <div style="flex:1;">
                    <div style="font-weight:500;color:var(--text-primary);">{a.get("domain","")}</div>
                    <div style="font-size:.85rem;color:var(--text-secondary);">{a.get("message","")}</div>
                </div>
            </div>"""
    else:
        alerts_html = '<p style="color:var(--text-muted);text-align:center;padding:24px 0;">No unacknowledged alerts</p>'

    # ── Needs-attention list (worst scoring) ────────────────────────────
    attention_html = ""
    for d in worst:
        if (d.get("last_score") or 0) >= 85:
            continue
        dom = d["domain"]
        s = d.get("last_score") or 0
        g = d.get("last_grade") or "F"
        g_cls = g.lower().replace("+", "-plus")
        bar_w = s
        attention_html += f"""
        <div style="margin-bottom:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                <a href="/domain/{dom}" style="color:var(--text-primary);text-decoration:none;font-weight:500;">{dom}</a>
                <span class="grade-badge {g_cls}" style="font-size:.75rem;padding:2px 8px;">{g} ({s})</span>
            </div>
            <div style="background:var(--bg-secondary);border-radius:4px;height:8px;overflow:hidden;">
                <div style="width:{bar_w}%;height:100%;border-radius:4px;background:{'var(--danger)' if s < 50 else 'var(--warning)' if s < 70 else 'var(--success)'};"></div>
            </div>
        </div>"""
    if not attention_html:
        attention_html = '<p style="color:var(--text-muted);text-align:center;padding:24px 0;">All domains scoring well!</p>'

    # ── Check if CSV report dashboard also needed ───────────────────────
    csv_file, md_file = _latest_pair()

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuroraEdge Security</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
    {_css()}
    {_auth_js()}
</head>
<body>
    <div class="container">
        <nav class="top-nav">
            <a href="/" class="nav-brand">
                <span class="nav-brand-icon">🛡️</span>
                <span>AuroraEdge</span>
            </a>
            <div class="nav-links">
                <a href="/" class="nav-link active">📊 Dashboard</a>
                <a href="/domains" class="nav-link">🌐 My Domains</a>
                <a href="/test" class="nav-link highlight">🔍 Scan</a>
                <a href="/generator" class="nav-link">🛠️ Generator</a>
                <a href="/settings" class="nav-link">⚙️ Settings</a>
            </div>
        </nav>

        <header>
            <div class="logo-area">
                <div class="logo">🛡️</div>
                <div>
                    <h1>AuroraEdge Security</h1>
                    <p class="subtitle">Cyber Defence Overview — {org_name}</p>
                </div>
            </div>
            <div class="header-right">
                <div class="live-indicator">
                    <span class="live-dot"></span>
                    <span>Monitoring {'Active' if total_domains > 0 else 'Inactive'}</span>
                </div>
            </div>
        </header>

        <!-- ── Stat Cards ─────────────────────────────────────────── -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon domains">🌐</div>
                <div class="stat-value">{total_domains}</div>
                <div class="stat-label">Domains Monitored</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon score">📊</div>
                <div class="stat-value" style="color:{health_colour};">{avg_score}</div>
                <div class="stat-label">Average Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon high">{health_icon}</div>
                <div class="stat-value" style="color:{health_colour};">{health_label}</div>
                <div class="stat-label">Overall Health</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon warn">🔔</div>
                <div class="stat-value" style="color:{'var(--danger)' if alert_count > 0 else 'var(--success)'};">{alert_count}</div>
                <div class="stat-label">Active Alerts</div>
            </div>
        </div>

        <!-- ── Two-Column: Grade Dist + Needs Attention ────────── -->
        <div class="two-col">
            <div class="section-card">
                <h2>Grade Distribution</h2>
                {'<p style="color:var(--text-muted);text-align:center;padding:24px 0;">Add domains in <a href="/domains" style="color:var(--accent);">My Domains</a> to see grade data.</p>' if total_domains == 0 else f"""
                <div style="padding:8px 0;">
                    {grade_bars_html}
                </div>
                <div style="display:flex;justify-content:space-between;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-size:.85rem;color:var(--text-secondary);">
                    <span>✅ Passing (≥70): <strong style="color:var(--success);">{passing}</strong></span>
                    <span>❌ Failing (&lt;70): <strong style="color:var(--danger);">{failing}</strong></span>
                </div>"""}
            </div>
            <div class="section-card">
                <h2>⚠️ Needs Attention</h2>
                {attention_html}
            </div>
        </div>

        <!-- ── Domain Health Overview ──────────────────────────── -->
        <div class="section-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h2 style="margin:0;">Domain Health Overview</h2>
                <div style="display:flex;gap:8px;">
                    <a href="/domains" class="btn btn-secondary" style="font-size:.85rem;padding:8px 16px;">Manage Domains</a>
                    <a href="/test" class="btn btn-primary" style="font-size:.85rem;padding:8px 16px;">+ Scan New</a>
                </div>
            </div>
            {'<div style="text-align:center;padding:40px 0;"><p style="font-size:1.2rem;margin-bottom:8px;">🌐 No domains onboarded yet</p><p style="color:var(--text-secondary);max-width:400px;margin:0 auto 16px;">Add your domains to begin automated monitoring and defence.</p><a href="/domains" class="btn btn-primary" style="padding:12px 24px;">Go to My Domains</a></div>' if total_domains == 0 else f"""
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Grade</th>
                            <th>Score</th>
                            <th>Last Scanned</th>
                        </tr>
                    </thead>
                    <tbody>
                        {domain_rows_html}
                    </tbody>
                </table>
            </div>"""}
        </div>

        <!-- ── Recent Alerts ───────────────────────────────────── -->
        <div class="section-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <h2 style="margin:0;">🔔 Recent Alerts</h2>
                {'<a href="/domains" style="color:var(--accent);font-size:.85rem;">View All →</a>' if alert_count > 0 else ''}
            </div>
            {alerts_html}
        </div>

        <!-- ── Quick Actions ───────────────────────────────────── -->
        <div class="section-card">
            <h2>⚡ Quick Actions</h2>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:12px;">
                <a href="/test" style="text-decoration:none;">
                    <div style="background:var(--bg-secondary);padding:20px;border-radius:var(--radius-sm);border:1px solid var(--border);text-align:center;transition:all .2s;cursor:pointer;" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="font-size:1.5rem;margin-bottom:8px;">🔍</div>
                        <div style="font-weight:600;color:var(--text-primary);">Scan Domain</div>
                        <div style="font-size:.8rem;color:var(--text-secondary);margin-top:4px;">Check email security</div>
                    </div>
                </a>
                <a href="/domains" style="text-decoration:none;">
                    <div style="background:var(--bg-secondary);padding:20px;border-radius:var(--radius-sm);border:1px solid var(--border);text-align:center;transition:all .2s;cursor:pointer;" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="font-size:1.5rem;margin-bottom:8px;">🌐</div>
                        <div style="font-weight:600;color:var(--text-primary);">My Domains</div>
                        <div style="font-size:.8rem;color:var(--text-secondary);margin-top:4px;">Manage monitored domains</div>
                    </div>
                </a>
                <a href="/settings" style="text-decoration:none;">
                    <div style="background:var(--bg-secondary);padding:20px;border-radius:var(--radius-sm);border:1px solid var(--border);text-align:center;transition:all .2s;cursor:pointer;" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="font-size:1.5rem;margin-bottom:8px;">⚙️</div>
                        <div style="font-weight:600;color:var(--text-primary);">Settings</div>
                        <div style="font-size:.8rem;color:var(--text-secondary);margin-top:4px;">Cloudflare & monitoring</div>
                    </div>
                </a>
            </div>
        </div>

        {_footer_html()}
    </div>
    {_js()}
</body>
</html>
"""

    # If there's also a CSV report, append the detailed scan-report section
    # below the main dashboard (kept for backwards compatibility)
    if csv_file:
        rows = load_csv(csv_file)
        if rows:
            return HTMLResponse(_build_report_dashboard(rows, csv_file, md_file, html))

    return HTMLResponse(html)


def _build_report_dashboard(rows, csv_file, md_file, base_html):
    """Inject a 'Batch Scan Report' section into the base dashboard HTML."""
    counts = _severity_counts(rows)
    total = counts.get("TOTAL", 0)

    # Build table rows
    table_rows = ""
    for r in rows:
        grade = r.get("grade", "F")
        grade_class = grade.lower().replace("+", "-plus")
        severity = r.get("severity", "OK")
        domain = r.get("domain", "")
        spf = '<span class="check-icon check-yes">✓</span>' if r.get("spf_present") == "True" else '<span class="check-icon check-no">✗</span>'
        dmarc_val = r.get("dmarc_policy", "")
        dmarc = f'<span class="check-icon check-yes">✓</span> {dmarc_val}' if r.get("dmarc_present") == "True" else '<span class="check-icon check-no">✗</span>'
        dkim = '<span class="check-icon check-yes">✓</span>' if r.get("dkim_present") == "True" else '<span class="check-icon check-no">✗</span>'
        sts = '<span class="check-icon check-yes">✓</span>' if r.get("mta_sts_present") == "True" else '<span class="check-icon check-no">✗</span>'
        sev_class = severity.lower() if severity.lower() in ["ok", "warn", "high", "info"] else "ok"
        table_rows += f"""
        <tr data-grade="{grade}" data-severity="{severity}">
            <td class="domain-cell"><a href="/domain/{domain}">{domain}</a></td>
            <td><span class="grade-badge {grade_class}">{grade}</span></td>
            <td class="score-cell">{r.get("score", 0)}</td>
            <td><span class="status-badge {sev_class}">{severity}</span></td>
            <td>{spf}</td><td>{dmarc}</td><td>{dkim}</td><td>{sts}</td>
        </tr>"""

    downloads = '<a href="/download/latest?kind=csv" class="btn btn-secondary" style="font-size:.85rem;padding:8px 16px;">Download CSV</a>'
    if md_file:
        downloads += ' <a href="/download/latest?kind=md" class="btn btn-secondary" style="font-size:.85rem;padding:8px 16px;">📄 Markdown</a>'

    report_section = f"""
    <!-- Batch Scan Report -->
    <div class="section-card" style="margin-top:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <h2 style="margin:0;">📋 Latest Batch Scan Report</h2>
            <div style="display:flex;gap:8px;align-items:center;">
                <span style="color:var(--text-secondary);font-size:.85rem;">{total} domains · {csv_file.name}</span>
                {downloads}
            </div>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Domain</th><th>Grade</th><th>Score</th><th>Status</th>
                        <th>SPF</th><th>DMARC</th><th>DKIM</th><th>MTA-STS</th>
                    </tr>
                </thead>
                <tbody>{table_rows}</tbody>
            </table>
        </div>
    </div>
    """

    # Inject before the footer
    return base_html.replace("</body>", report_section + "</body>")


# =============================================================================
# Interactive Testing Hub
# =============================================================================


def _test_css() -> str:
    """Additional CSS for the test hub page."""
    return """
<style>
.test-form {
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 32px;
    margin-bottom: 24px;
    border: 1px solid var(--border);
}

.form-group { margin-bottom: 20px; }

.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: var(--text-primary);
}

.form-group input[type="text"],
.form-group textarea {
    width: 100%;
    padding: 14px 16px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 1rem;
    font-family: inherit;
    transition: all 0.2s ease;
}

.form-group input:focus,
.form-group textarea:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-glow);
}

.form-group textarea {
    min-height: 150px;
    resize: vertical;
}

.form-group small {
    display: block;
    margin-top: 6px;
    color: var(--text-muted);
    font-size: 0.85rem;
}

.checkbox-group {
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
}

.checkbox-item {
    display: flex;
    align-items: center;
    gap: 8px;
}

.checkbox-item input[type="checkbox"] {
    width: 18px;
    height: 18px;
    accent-color: var(--accent);
}

.btn-scan {
    background: linear-gradient(135deg, var(--accent), #ff6b9d);
    color: white;
    border: none;
    padding: 16px 32px;
    font-size: 1rem;
    font-weight: 600;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: all 0.3s ease;
    display: inline-flex;
    align-items: center;
    gap: 10px;
}

.btn-scan:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 24px var(--accent-glow);
}

.btn-scan:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
}

.result-container {
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 24px;
    border: 1px solid var(--border);
    margin-top: 24px;
}

.result-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
}

.result-domain {
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--text-primary);
}

.result-grade {
    font-size: 2rem;
    font-weight: 700;
    padding: 8px 20px;
    border-radius: 12px;
}

.result-grade.a-plus, .result-grade.a { background: var(--success-bg); color: var(--success); }
.result-grade.b { background: rgba(6, 182, 212, 0.2); color: #06b6d4; }
.result-grade.c { background: var(--warning-bg); color: var(--warning); }
.result-grade.d { background: rgba(249, 115, 22, 0.2); color: #f97316; }
.result-grade.f { background: var(--danger-bg); color: var(--danger); }

.result-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px;
    margin-bottom: 20px;
}

.result-stat {
    text-align: center;
    padding: 16px;
    background: var(--bg-secondary);
    border-radius: var(--radius-sm);
}

.result-stat-value {
    font-size: 1.8rem;
    font-weight: 700;
}

.result-stat-label {
    font-size: 0.8rem;
    color: var(--text-muted);
    text-transform: uppercase;
}

.checks-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
}

.check-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 16px;
    background: var(--bg-secondary);
    border-radius: var(--radius-sm);
    border-left: 3px solid var(--text-muted);
}

.check-item.pass { border-left-color: var(--success); }
.check-item.fail { border-left-color: var(--danger); }

.check-name { font-weight: 600; }
.check-status { font-weight: 700; }
.check-status.pass { color: var(--success); }
.check-status.fail { color: var(--danger); }
.check-hint { font-size: 0.7rem; color: var(--text-muted); display: none; }
.check-item:hover .check-hint { display: block; }
.check-item:hover { background: var(--bg-hover); transform: translateX(4px); }

/* Enhanced Remediation Styles */
.remediation-section {
    margin-top: 24px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
}

.remediation-item-enhanced {
    margin-bottom: 16px;
    background: var(--bg-secondary);
    border-radius: var(--radius-sm);
    border-left: 4px solid var(--warning);
    overflow: hidden;
}
.remediation-item-enhanced.high { border-left-color: var(--danger); }
.remediation-item-enhanced.critical { border-left-color: #dc2626; }
.remediation-item-enhanced.info { border-left-color: var(--info); }
.remediation-item-enhanced.expanded { box-shadow: 0 4px 12px rgba(0,0,0,0.3); }

.remediation-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px;
    cursor: pointer;
    transition: background 0.2s;
}
.remediation-header:hover { background: var(--bg-hover); }

.remediation-priority-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
}
.remediation-priority-badge.high { background: var(--danger-bg); color: var(--danger); }
.remediation-priority-badge.warn { background: var(--warning-bg); color: var(--warning); }
.remediation-priority-badge.info { background: var(--info-bg); color: var(--info); }

.remediation-title { flex: 1; font-weight: 600; }
.expand-arrow { color: var(--text-muted); transition: transform 0.2s; }

.remediation-body {
    padding: 0 20px 20px;
    border-top: 1px solid var(--border);
}
.remediation-body > div { margin-top: 16px; }
.remediation-body strong { color: var(--text-primary); display: block; margin-bottom: 6px; }
.remediation-body p { color: var(--text-secondary); line-height: 1.6; margin: 0; }

.remediation-example-box {
    background: var(--bg-primary);
    padding: 16px;
    border-radius: var(--radius-sm);
    position: relative;
}
.remediation-code {
    display: block;
    font-family: 'SF Mono', Consolas, monospace;
    font-size: 0.85rem;
    color: #a5d6ff;
    word-break: break-all;
    margin: 8px 0;
}
.copy-btn {
    position: absolute;
    top: 12px;
    right: 12px;
    padding: 6px 12px;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.8rem;
}
.copy-btn:hover { background: var(--accent-hover); }

.remediation-rfc { color: var(--text-muted); font-size: 0.85rem; }

/* Severity Banner */
.severity-banner {
    padding: 16px 20px;
    margin-bottom: 20px;
    border-radius: var(--radius-sm);
    border-left: 4px solid;
}
.severity-banner.critical { background: rgba(220, 38, 38, 0.15); border-color: #dc2626; }
.severity-banner.high { background: var(--danger-bg); border-color: var(--danger); }
.severity-banner.warn { background: var(--warning-bg); border-color: var(--warning); }
.severity-banner.info { background: var(--info-bg); border-color: var(--info); }

.severity-banner-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
}
.severity-icon { font-size: 1.2rem; }
.severity-urgency {
    margin-left: auto;
    font-size: 0.8rem;
    padding: 4px 10px;
    background: rgba(255,255,255,0.1);
    border-radius: 12px;
}
.severity-description { color: var(--text-secondary); margin: 0 0 8px; }
.severity-impact { color: var(--text-muted); font-size: 0.9rem; margin: 0; }

/* Result Actions */
.result-actions {
    display: flex;
    gap: 12px;
    margin-top: 20px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    flex-wrap: wrap;
}
.action-btn {
    padding: 10px 18px;
    border-radius: var(--radius-sm);
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    border: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}
.action-btn.primary {
    background: var(--accent);
    color: white;
}
.action-btn.primary:hover { background: var(--accent-hover); transform: translateY(-2px); }
.action-btn.secondary {
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
}
.action-btn.secondary:hover { background: var(--bg-hover); }

/* Expandable Details */
.result-header { cursor: pointer; transition: all 0.2s; }
.result-header:hover { background: var(--bg-hover); margin: -24px -24px 0; padding: 24px; border-radius: var(--radius) var(--radius) 0 0; }
.expand-icon { margin-right: 8px; color: var(--text-muted); transition: transform 0.2s; }
.result-container.expanded .expand-icon { transform: rotate(90deg); }

.raw-data-section { margin-top: 20px; }
.raw-data-section h4 { color: var(--text-secondary); font-size: 0.9rem; }
.toggle-hint { font-weight: 400; color: var(--text-muted); font-size: 0.8rem; }
.raw-data pre {
    background: var(--bg-primary);
    padding: 16px;
    border-radius: var(--radius-sm);
    font-size: 0.8rem;
    color: var(--text-secondary);
    overflow-x: auto;
    margin-top: 8px;
}

/* All Good Banner */
.all-good-banner {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 20px;
    background: var(--success-bg);
    border-radius: var(--radius-sm);
    color: var(--success);
    font-weight: 500;
    margin-top: 20px;
}
.all-good-icon { font-size: 1.5rem; }

/* Clickable Stats */
.result-stat.clickable { cursor: pointer; transition: all 0.2s; }
.result-stat.clickable:hover { transform: scale(1.05); box-shadow: 0 4px 12px rgba(0,0,0,0.2); }
.stat-hint { font-size: 0.65rem; color: var(--accent); margin-top: 4px; opacity: 0; transition: opacity 0.2s; }
.result-stat.clickable:hover .stat-hint { opacity: 1; }

/* Severity-colored stats */
.result-stat.critical { background: rgba(220, 38, 38, 0.2); }
.result-stat.high { background: var(--danger-bg); }
.result-stat.warn { background: var(--warning-bg); }
.result-stat.info { background: var(--info-bg); }
.result-stat.ok { background: var(--success-bg); }

/* Legacy remediation styles */
.remediation-item {
    padding: 16px;
    margin-bottom: 12px;
    background: var(--bg-secondary);
    border-radius: var(--radius-sm);
    border-left: 3px solid var(--warning);
}

.remediation-item.high { border-left-color: var(--danger); }
.remediation-item.info { border-left-color: var(--info); }

.remediation-title {
    font-weight: 600;
    margin-bottom: 8px;
}

.remediation-example {
    font-family: 'SF Mono', Consolas, monospace;
    font-size: 0.85rem;
    color: var(--text-muted);
    background: var(--bg-primary);
    padding: 8px 12px;
    border-radius: 4px;
    margin-top: 8px;
}

.scanning-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
}

.scanning-modal {
    background: var(--bg-card);
    padding: 48px;
    border-radius: var(--radius);
    text-align: center;
}

.scanning-spinner {
    width: 48px;
    height: 48px;
    border: 4px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 24px;
}

.quick-domains {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 12px;
}

.quick-domain {
    padding: 8px 14px;
    background: rgba(59, 130, 246, 0.15);
    border: 1px solid rgba(59, 130, 246, 0.4);
    border-radius: 20px;
    font-size: 0.85rem;
    color: #e0e7ff;
    cursor: pointer;
    transition: all 0.2s;
    font-weight: 500;
}

.quick-domain:hover {
    border-color: var(--accent);
    background: rgba(59, 130, 246, 0.3);
    color: #ffffff;
    transform: translateY(-1px);
}

/* Featured demo domain button — stands out from regular quick domains */
.quick-domain.demo-domain {
    background: rgba(234, 179, 8, 0.20);
    border-color: rgba(234, 179, 8, 0.6);
    color: #fde68a;
    font-weight: 600;
    font-size: 0.9rem;
}
.quick-domain.demo-domain:hover {
    background: rgba(234, 179, 8, 0.35);
    border-color: #eab308;
    color: #fff;
}
.quick-domain.demo-domain small {
    font-weight: 400;
    opacity: 0.85;
}

.tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 24px;
    background: var(--bg-secondary);
    padding: 4px;
    border-radius: var(--radius-sm);
    width: fit-content;
}

.tab {
    padding: 10px 20px;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    color: var(--text-secondary);
}

.tab:hover { color: var(--text-primary); }
.tab.active {
    background: var(--accent);
    color: white;
}

.help-box {
    background: var(--info-bg);
    border: 1px solid var(--info);
    border-radius: var(--radius-sm);
    padding: 16px;
    margin-bottom: 24px;
}

.help-box h3 {
    color: var(--info);
    margin-bottom: 8px;
    font-size: 1rem;
}

.help-box p { color: var(--text-secondary); font-size: 0.9rem; }
.help-box code {
    background: var(--bg-secondary);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.85rem;
}
</style>
"""


def _test_js() -> str:
    """JavaScript for the interactive test hub."""
    return """
<script>
let isScanning = false;

// Quick domain suggestions
const quickDomains = [
    'google.com', 'microsoft.com', 'belfastmet.ac.uk', 'qub.ac.uk',
    'ulster.ac.uk', 'gov.uk', 'ncsc.gov.uk', 'cloudflare.com'
];

// The pre-configured demo domain for auto-fix testing
const demoDomain = 'auroraedge.co.uk';

// Add quick domain to input
function addQuickDomain(domain) {
    const input = document.getElementById('domainInput');
    const textarea = document.getElementById('batchInput');
    
    if (document.getElementById('singleTab').classList.contains('active')) {
        input.value = domain;
    } else {
        textarea.value = textarea.value ? textarea.value + '\\n' + domain : domain;
    }
}

// Switch between tabs
function switchTab(tab) {
    const singleTab = document.getElementById('singleTab');
    const batchTab = document.getElementById('batchTab');
    const singleForm = document.getElementById('singleForm');
    const batchForm = document.getElementById('batchForm');
    
    if (tab === 'single') {
        singleTab.classList.add('active');
        batchTab.classList.remove('active');
        singleForm.style.display = 'block';
        batchForm.style.display = 'none';
    } else {
        singleTab.classList.remove('active');
        batchTab.classList.add('active');
        singleForm.style.display = 'none';
        batchForm.style.display = 'block';
    }
}

// Scan a single domain
async function scanDomain() {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) {
        showToast('Please enter a domain name', 'warning');
        return;
    }
    
    await performScan([domain]);
}

// Scan multiple domains
async function scanBatch() {
    const text = document.getElementById('batchInput').value.trim();
    if (!text) {
        showToast('Please enter at least one domain', 'warning');
        return;
    }
    
    const domains = text.split('\\n')
        .map(d => d.trim())
        .filter(d => d && !d.startsWith('#'));
    
    if (domains.length === 0) {
        showToast('No valid domains found', 'warning');
        return;
    }
    
    await performScan(domains);
}

// Perform the scan — scans each domain individually so the UI shows
// real-time per-domain progress in the overlay.
async function performScan(domains) {
    if (isScanning) return;
    isScanning = true;
    
    // Show loading overlay
    const overlay = document.getElementById('scanningOverlay');
    const statusText = document.getElementById('scanStatus');
    const progressBar = document.getElementById('scanProgress');
    overlay.style.display = 'flex';
    
    // Hide previous results
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('resultsContainer').innerHTML = '';

    const total = domains.length;
    const allResults = [];
    const saveDb = document.getElementById('saveDb')?.checked ?? true;
    const remediation = document.getElementById('showRemediation')?.checked ?? true;

    try {
        for (let i = 0; i < total; i++) {
            const domain = domains[i];
            const pct = Math.round(((i) / total) * 100);
            statusText.textContent = `Scanning ${i + 1} of ${total}: ${domain}`;
            if (progressBar) {
                progressBar.style.width = pct + '%';
                progressBar.textContent = pct + '%';
            }

            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    domains: [domain],
                    save_to_db: saveDb,
                    remediation: remediation
                })
            });
            const data = await response.json();
            if (response.ok && data.results) {
                allResults.push(...data.results);
            } else {
                allResults.push({ domain: domain, error: data.detail || 'Scan failed' });
            }
        }

        // Final 100%
        if (progressBar) { progressBar.style.width = '100%'; progressBar.textContent = '100%'; }
        statusText.textContent = 'Done!';

        displayResults({ status: 'success', count: allResults.length, results: allResults });

    } catch (error) {
        const friendly = error.message.includes('Failed to fetch')
            ? 'Network error — is the server running? Check the terminal for errors.'
            : error.message;
        showToast(friendly, 'error', 8000);
    } finally {
        overlay.style.display = 'none';
        if (progressBar) { progressBar.style.width = '0%'; progressBar.textContent = ''; }
        isScanning = false;
    }
}

// Display scan results with enhanced explanations
function displayResults(data) {
    const container = document.getElementById('resultsContainer');
    const section = document.getElementById('resultsSection');

    let html = '';

    for (const result of data.results) {
        const domain = result.domain;
        const scan = result.scan;
        const ev = result.evaluation;
        const remediation = result.remediation || [];

        const grade = ev.grade || 'F';
        const gradeClass = grade.toLowerCase().replace('+', '-plus');
        const severityClass = (ev.severity || 'ok').toLowerCase();

        html += `
        <div class="result-container" id="result-${domain.replace(/\\./g, '-')}">
            <div class="result-header" onclick="toggleDetails('${domain.replace(/\\./g, '-')}')">
                <div class="result-domain">
                    <span class="expand-icon">▶</span>
                    ${domain}
                </div>
                <div class="result-grade ${gradeClass}">${grade}</div>
            </div>

            <!-- Severity Explanation Banner -->
            ${ev.severity && ev.severity !== 'OK' ? `
            <div class="severity-banner ${severityClass}">
                <div class="severity-banner-header">
                    <span class="severity-icon">${getSeverityIcon(ev.severity)}</span>
                    <strong>${ev.severity_title || ev.severity}</strong>
                    <span class="severity-urgency">${ev.severity_urgency || ''}</span>
                </div>
                <p class="severity-description">${ev.severity_description || ''}</p>
                ${ev.severity_impact ? `<p class="severity-impact"><strong>Impact:</strong> ${ev.severity_impact}</p>` : ''}
            </div>
            ` : ''}

            <div class="result-stats">
                <div class="result-stat clickable" onclick="showScoreBreakdown('${domain}', ${ev.score || 0})">
                    <div class="result-stat-value">${ev.score || 0}</div>
                    <div class="result-stat-label">Score</div>
                    <div class="stat-hint">Click for breakdown</div>
                </div>
                <div class="result-stat ${severityClass}">
                    <div class="result-stat-value">${ev.severity || 'OK'}</div>
                    <div class="result-stat-label">Severity</div>
                </div>
                <div class="result-stat">
                    <div class="result-stat-value">${ev.violation_count || 0}</div>
                    <div class="result-stat-label">Violations</div>
                </div>
                <div class="result-stat">
                    <div class="result-stat-value">${scan.mx_count || 0}</div>
                    <div class="result-stat-label">MX Records</div>
                </div>
            </div>

            <!-- Expandable Details Section -->
            <div class="result-details" id="details-${domain.replace(/\\./g, '-')}" style="display: none;">
                <h3 style="margin: 20px 0 12px; color: var(--text-secondary);">🔍 Security Checks</h3>
                <div class="checks-grid">
                    ${renderCheckEnhanced('SPF', scan.spf_present, scan.spf_all ? 'All: ' + scan.spf_all : '', 'R2_SPF_MISSING')}
                    ${renderCheckEnhanced('DMARC', scan.dmarc_present, scan.dmarc_policy ? 'Policy: ' + scan.dmarc_policy : '', 'R4_DMARC_MISSING')}
                    ${renderCheckEnhanced('DKIM', scan.dkim_present, scan.dkim_selectors ? 'Selectors: ' + scan.dkim_selectors : '', 'R6_DKIM_NOT_FOUND')}
                    ${renderCheckEnhanced('MTA-STS', scan.mta_sts_present, scan.mta_sts_mode ? 'Mode: ' + scan.mta_sts_mode : '', 'R8_MTA_STS_MISSING')}
                    ${renderCheckEnhanced('TLS-RPT', scan.tls_rpt_present, '', 'R10_TLS_RPT_MISSING')}
                    ${renderCheckEnhanced('MX Records', scan.mx_present, scan.mx_count + ' records', 'R1_MX_MISSING')}
                </div>

                <!-- Raw Data Section -->
                <div class="raw-data-section">
                    <h4 onclick="toggleRawData('${domain.replace(/\\./g, '-')}')" style="cursor: pointer;">
                        📋 Raw DNS Data <span class="toggle-hint">(click to expand)</span>
                    </h4>
                    <div class="raw-data" id="raw-${domain.replace(/\\./g, '-')}" style="display: none;">
                        <pre>${JSON.stringify(scan, null, 2)}</pre>
                    </div>
                </div>
            </div>

            ${remediation.length > 0 ? `
            <div class="remediation-section">
                <h3 style="margin-bottom: 16px; color: var(--text-secondary);">🔧 How to Fix (${remediation.length} recommendation${remediation.length > 1 ? 's' : ''})</h3>
                ${remediation.map((r, i) => `
                    <div class="remediation-item-enhanced ${(r.priority || 'info').toLowerCase()}">
                        <div class="remediation-header" onclick="toggleRemediation('rem-${domain.replace(/\\./g, '-')}-${i}')">
                            <span class="remediation-priority-badge ${(r.priority || 'info').toLowerCase()}">${r.priority || 'INFO'}</span>
                            <span class="remediation-title">${r.description}</span>
                            <span class="expand-arrow">▼</span>
                        </div>
                        <div class="remediation-body" id="rem-${domain.replace(/\\./g, '-')}-${i}" style="display: none;">
                            ${r.why ? `
                            <div class="remediation-why">
                                <strong>❓ Why is this important?</strong>
                                <p>${r.why}</p>
                            </div>
                            ` : ''}
                            ${r.how_to_fix ? `
                            <div class="remediation-fix">
                                <strong>🔧 How to fix:</strong>
                                <p>${r.how_to_fix}</p>
                            </div>
                            ` : ''}
                            ${r.example ? `
                            <div class="remediation-example-box">
                                <strong>📝 Example DNS Record:</strong>
                                <code class="remediation-code">${r.example}</code>
                                <button class="copy-btn" onclick="copyToClipboard('${r.example.replace(/'/g, "\\'")}')">📋 Copy</button>
                            </div>
                            ` : ''}
                            ${r.rfc ? `
                            <div class="remediation-rfc">
                                <strong>📚 Reference:</strong> ${r.rfc}
                            </div>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
            ` : `
            <div class="all-good-banner">
                <span class="all-good-icon">✅</span>
                <span>All security checks passed! No remediation needed.</span>
            </div>
            `}

            <!-- Action Buttons -->
            <div class="result-actions">
                <button class="action-btn secondary" onclick="rescanDomain('${domain}')">🔄 Rescan</button>
                ${ev.violation_count > 0 ? `<button class="action-btn primary" onclick="autoFixFromScan('${domain}')" style="background:var(--warning);color:#000;">🔧 Auto-Fix DNS</button>` : ''}
                <button class="action-btn secondary" onclick="showHistory('${domain}')">📊 View History</button>
                <button class="action-btn primary" onclick="exportDomainReport('${domain}', ${JSON.stringify(result).replace(/"/g, '&quot;')})">📥 Export Report</button>
            </div>
        </div>
        `;
    }

    container.innerHTML = html;
    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth' });

    // Auto-expand first result details
    if (data.results.length > 0) {
        const firstDomain = data.results[0].domain.replace(/\\./g, '-');
        toggleDetails(firstDomain);
    }
}

function getSeverityIcon(severity) {
    const icons = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'WARN': '⚡',
        'INFO': 'ℹ️',
        'OK': '✅'
    };
    return icons[severity] || '❓';
}

function toggleDetails(domainId) {
    const details = document.getElementById('details-' + domainId);
    const result = document.getElementById('result-' + domainId);
    const icon = result.querySelector('.expand-icon');

    if (details.style.display === 'none') {
        details.style.display = 'block';
        icon.textContent = '▼';
        result.classList.add('expanded');
    } else {
        details.style.display = 'none';
        icon.textContent = '▶';
        result.classList.remove('expanded');
    }
}

function toggleRemediation(remId) {
    const body = document.getElementById(remId);
    const parent = body.parentElement;
    const arrow = parent.querySelector('.expand-arrow');

    if (body.style.display === 'none') {
        body.style.display = 'block';
        arrow.textContent = '▲';
        parent.classList.add('expanded');
    } else {
        body.style.display = 'none';
        arrow.textContent = '▼';
        parent.classList.remove('expanded');
    }
}

function toggleRawData(domainId) {
    const raw = document.getElementById('raw-' + domainId);
    raw.style.display = raw.style.display === 'none' ? 'block' : 'none';
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success', 2000);
    }).catch(err => {
        console.error('Copy failed:', err);
    });
}

async function rescanDomain(domain) {
    const input = document.getElementById('domainInput');
    if (input) input.value = domain;
    await scanDomain();
}

async function autoFixFromScan(domain) {
    if (!confirm('Auto-Fix will attempt to create/update DNS records for ' + domain + ' via Cloudflare.\\n\\nThis requires Cloudflare API credentials configured in Settings.\\n\\nProceed?')) return;
    try {
        // Test Cloudflare first and get zone name for ownership check
        const cfRes = await fetch('/api/settings/test-cloudflare');
        const cfData = await cfRes.json();
        if (!cfData.ok) {
            showToast('Cloudflare is not configured. Go to Settings and add your API Token and Zone ID first.', 'error', 8000);
            return;
        }
        // Frontend ownership check — block before sending the request
        const zone = (cfData.zone_name || '').toLowerCase();
        const dom = domain.toLowerCase();
        if (zone && dom !== zone && !dom.endsWith('.' + zone)) {
            showToast('Cannot auto-fix "' + domain + '"\nYour Cloudflare zone is "' + zone + '". You can only auto-fix domains within that zone.\nGo to Settings to change your Cloudflare credentials.', 'error', 10000);
            return;
        }
        const res = await fetch('/api/apply-fix', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain })
        });
        const data = await res.json();
        if (!res.ok) {
            showToast('Auto-Fix Blocked: ' + (data.detail || 'Unknown error.'), 'error', 8000);
            return;
        }
        let msg = '';
        if (data.applied && data.applied.length > 0) {
            msg += '✅ Fixes applied:\\n' + data.applied.map(f => '  ✓ ' + f.type + ': ' + f.message).join('\\n');
        }
        if (data.failed && data.failed.length > 0) {
            msg += (msg ? '\\n\\n' : '') + '❌ Failed:\\n' + data.failed.map(f => '  ✗ ' + f.type + ': ' + f.message).join('\\n');
        }
        if (data.manual_actions && data.manual_actions.length > 0) {
            msg += (msg ? '\\n\\n' : '') + '🔧 Manual steps still needed:\\n' + data.manual_actions.map(m => '  ⚠ ' + m.type + ': ' + m.description).join('\\n');
        }
        if (data.verification) {
            msg += (msg ? '\\n\\n' : '') + '🔍 Verification: ' + data.verification;
        }
        if (data.pre_fix_grade && data.grade && data.pre_fix_grade !== data.grade) {
            msg += '\\n📈 Grade: ' + data.pre_fix_grade + ' → ' + data.grade + ' (Score: ' + data.pre_fix_score + ' → ' + data.score + ')';
        } else if (data.grade) {
            msg += '\\n📊 Grade: ' + data.grade + ' | Score: ' + data.score;
        }
        if (!msg && data.grade) {
            msg = 'Current grade: ' + data.grade + ' (Score: ' + data.score + ')\\nNo auto-fixable issues found.';
            if (data.violations > 0) msg += '\\n\\n⚠ ' + data.violations + ' issue(s) detected but they require manual configuration.';
            else msg += ' Domain looks good!';
        } else if (!msg) {
            msg = 'No issues found — domain looks good!';
        }
        const hasFailures = (data.failed && data.failed.length > 0);
        const hasApplied = (data.applied && data.applied.length > 0);
        showToast(msg, hasFailures ? 'warning' : hasApplied ? 'success' : 'info', 15000);
    } catch(e) {
        showToast('Auto-fix error: ' + e.message, 'error', 8000);
    }
}

async function showHistory(domain) {
    try {
        const response = await fetch('/api/history/' + encodeURIComponent(domain));
        const data = await response.json();
        if (data.history && data.history.length > 0) {
            let historyHtml = '<h3>Scan History for ' + domain + '</h3><ul>';
            data.history.forEach(h => {
                historyHtml += '<li>' + h.scanned_at + ': Score ' + h.score + ' (Grade ' + h.grade + ')</li>';
            });
            historyHtml += '</ul>';
            alert(historyHtml.replace(/<[^>]*>/g, '\\n'));
        } else {
            alert('No scan history found for ' + domain);
        }
    } catch (e) {
        alert('Could not load history: ' + e.message);
    }
}

function exportDomainReport(domain, result) {
    const report = {
        domain: domain,
        exported_at: new Date().toISOString(),
        ...result
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = domain.replace(/\\./g, '_') + '_report.json';
    a.click();
    URL.revokeObjectURL(url);
}

function showScoreBreakdown(domain, score) {
    const breakdown = `
Score Breakdown for ${domain}
─────────────────────────
Total Score: ${score}/100

Scoring System:
• Start with 100 points
• CRITICAL issues: -40 points each
• HIGH issues: -25 points each
• WARN issues: -10 points each
• INFO issues: -2 points each

Grade Thresholds:
• A+ (95-100): Excellent
• A  (85-94): Very Good
• B  (75-84): Good
• C  (60-74): Fair
• D  (40-59): Poor
• F  (0-39): Fail
    `;
    alert(breakdown);
}

function renderCheckEnhanced(name, present, detail, ruleId) {
    const status = present ? 'pass' : 'fail';
    const icon = present ? '✓' : '✗';
    return `
        <div class="check-item ${status}" onclick="showCheckInfo('${name}', ${present}, '${ruleId}')" style="cursor: pointer;">
            <span class="check-name">${name}</span>
            <span class="check-status ${status}">${icon} ${detail}</span>
            <span class="check-hint">Click for info</span>
        </div>
    `;
}

async function showCheckInfo(name, present, ruleId) {
    if (present) {
        alert(name + ' check PASSED\\n\\nThis security control is properly configured.');
        return;
    }

    try {
        const response = await fetch('/api/explanations/rule/' + ruleId);
        const data = await response.json();
        const info = `
${name} Check FAILED

Why is this important?
${data.why || 'This check ensures proper email security configuration.'}

How to fix:
${data.fix || 'Review the recommendation and apply the suggested configuration.'}

Example:
${data.example || 'N/A'}

Reference: ${data.rfc || 'See email security RFCs'}
        `;
        alert(info);
    } catch (e) {
        alert(name + ' check failed. Click on the remediation section for details on how to fix.');
    }
}

// Initialize quick domains
document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('quickDomains');
    if (container) {
        // Featured demo domain (pre-configured for auto-fix)
        const demoBtn = document.createElement('button');
        demoBtn.className = 'quick-domain demo-domain';
        demoBtn.innerHTML = '⭐ ' + demoDomain + ' <small>(Auto-Fix Demo)</small>';
        demoBtn.title = 'Pre-configured demo domain — scan this then click Auto-Fix DNS';
        demoBtn.onclick = () => addQuickDomain(demoDomain);
        container.appendChild(demoBtn);

        // Regular quick domains
        quickDomains.forEach(domain => {
            const btn = document.createElement('button');
            btn.className = 'quick-domain';
            btn.textContent = domain;
            btn.onclick = () => addQuickDomain(domain);
            container.appendChild(btn);
        });
    }
});
</script>
"""


@app.post("/api/scan", dependencies=[Depends(require_token)])
async def api_scan(request: Request):
    _rate_check(request)
    """
    API endpoint to scan domains on demand.

    POST body:
    {
        "domains": ["example.com", "test.org"],
        "save_to_db": true,
        "remediation": true
    }
    """
    if not HAS_SCANNER:
        raise HTTPException(status_code=501, detail="Scanner module not available")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    domains = body.get("domains", [])
    if not domains:
        raise HTTPException(status_code=400, detail="No domains provided")

    if isinstance(domains, str):
        domains = [domains]

    # Limit to prevent abuse
    if len(domains) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 domains per request")

    save_to_db = body.get("save_to_db", True)
    show_remediation = body.get("remediation", True)

    results = []
    db = None
    scan_id = None

    if save_to_db and HAS_DB:
        try:
            db = get_database()
            scan_id = db.start_scan(notes=f"Dashboard scan of {len(domains)} domain(s)")
        except Exception:
            db = None

    for raw_domain in domains:
        domain, d_err = _sanitize_domain(raw_domain)
        if d_err:
            results.append({"domain": "(invalid)", "error": d_err})
            continue

        try:
            # Run blocking DNS scan in thread pool to avoid freezing
            # the async event loop (fixes batch scan timeouts)
            scan_result = await asyncio.to_thread(
                scan_domain, domain, False
            )
            evaluation = evaluate(scan_result)

            remediation_list = []
            if show_remediation:
                res_with_domain = {**scan_result, "domain": domain}
                remediation_list = generate_remediation(res_with_domain)
                # Enhance remediation with detailed explanations
                for item in remediation_list:
                    rule_id = item.get("rule", "")
                    if rule_id and HAS_EXPLANATIONS:
                        explanation = get_rule_explanation(rule_id)
                        item["why"] = explanation.get("why", "")
                        item["how_to_fix"] = explanation.get("fix", "")
                        item["rfc"] = explanation.get("rfc", "")

            # Add severity explanation to evaluation
            severity = evaluation.get("severity", "OK")
            if HAS_EXPLANATIONS:
                severity_info = get_severity_explanation(severity)
                evaluation["severity_title"] = severity_info.get("title", severity)
                evaluation["severity_description"] = severity_info.get(
                    "description", ""
                )
                evaluation["severity_impact"] = severity_info.get("impact", "")
                evaluation["severity_urgency"] = severity_info.get("urgency", "")
                evaluation["severity_color"] = severity_info.get("color", "#6b7280")

            if db and scan_id:
                db.save_result(scan_id, domain, scan_result, evaluation)

            # Auto-add to managed domains so it appears on the dashboard
            if db:
                grade = evaluation.get("grade", "F")
                score = evaluation.get("score", 0)
                db.add_managed_domain(domain, notes="Added via scan")
                db.update_managed_domain_scan(domain, grade, score)

            results.append(
                {
                    "domain": domain,
                    "scan": scan_result,
                    "evaluation": evaluation,
                    "remediation": remediation_list,
                }
            )

        except Exception as e:
            results.append(
                {
                    "domain": domain,
                    "scan": {"error": str(e)},
                    "evaluation": {"severity": "ERROR", "score": 0, "grade": "F"},
                    "remediation": [],
                }
            )

    if db and scan_id:
        db.complete_scan(scan_id, len(results))

    ok = [r for r in results if "error" not in r]
    status = "success" if ok else "error"
    return {"status": status, "count": len(results), "results": results}


@app.post("/api/apply-fix", dependencies=[Depends(require_token)])
async def api_apply_fix(request: Request):
    """
    API endpoint to apply DNS fixes via Cloudflare.

    POST body:
    {
        "domain": "example.com",
        "fix_types": ["SPF", "DMARC", "TLS-RPT", "MTA-STS"]  // optional, defaults to all
    }

    Requires CF_API_TOKEN and CF_ZONE_ID environment variables.
    """
    if not HAS_DNS_FIX:
        raise HTTPException(status_code=501, detail="DNS fix module not available")

    # Always load the latest CF credentials from the database
    if HAS_DB:
        try:
            _apply_cf_settings(get_database())
        except Exception:
            pass

    cf = get_cloudflare_client()
    if not cf:
        raise HTTPException(
            status_code=503,
            detail="Cloudflare API not configured. Set CF_API_TOKEN and CF_ZONE_ID environment variables.",
        )

    # Validate connection
    ok, msg = cf.validate_connection()
    if not ok:
        raise HTTPException(
            status_code=503, detail=f"Cloudflare connection failed: {msg}"
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    domain, d_err = _sanitize_domain(body.get("domain"))
    if d_err:
        raise HTTPException(status_code=400, detail=d_err)

    # OWNERSHIP CHECK: refuse to modify DNS for domains outside the configured zone
    owned, ownership_msg = cf.verify_domain_ownership(domain)
    if not owned:
        raise HTTPException(status_code=403, detail=ownership_msg)

    requested_fix_types = body.get("fix_types", None)

    # First scan the domain to see what needs fixing
    if not HAS_SCANNER:
        raise HTTPException(status_code=501, detail="Scanner module not available")

    scan_result = scan_domain(domain, check_starttls=False)
    scan_result["domain"] = domain

    # Generate recommended fixes
    fixes = cf.generate_fixes(scan_result)

    # Filter to requested types if specified
    if requested_fix_types:
        fixes = [f for f in fixes if f["type"] in requested_fix_types]

    applied_fixes = []
    failed_fixes = []
    manual_actions = []

    for fix in fixes:
        fix_type = fix.get("type", "Unknown")

        # Manual-only items (no auto_fix function)
        if fix.get("manual") or fix.get("auto_fix") is None:
            manual_actions.append({
                "type": fix_type,
                "priority": fix.get("priority", "INFO"),
                "description": fix.get("description", ""),
                "recommended": fix.get("recommended", ""),
                "steps": fix.get("steps", ""),
            })
            continue

        try:
            auto_fix_fn = fix.get("auto_fix")
            success, message = auto_fix_fn()
            result = {
                "type": fix_type,
                "success": success,
                "message": message,
                "priority": fix.get("priority", "INFO"),
            }
            if success:
                applied_fixes.append(result)
            else:
                failed_fixes.append(result)
        except Exception as e:
            failed_fixes.append(
                {
                    "type": fix_type,
                    "success": False,
                    "message": str(e),
                    "priority": fix.get("priority", "INFO"),
                }
            )

    # Run evaluation to get current grade/score (PRE-fix scan)
    pre_fix_eval = evaluate(scan_result) if HAS_SCANNER else {}

    # If we applied at least one fix, perform a post-fix verification scan
    # so we can report the *actual* improvement (or surface propagation lag).
    post_fix_eval = {}
    verification_note = ""
    if applied_fixes:
        import time
        time.sleep(2)  # brief pause for Cloudflare edge propagation
        try:
            post_scan = scan_domain(domain, check_starttls=False)
            post_scan["domain"] = domain
            post_fix_eval = evaluate(post_scan)
            pre_score = pre_fix_eval.get("score", 0)
            post_score = post_fix_eval.get("score", 0)
            if post_score > pre_score:
                verification_note = (
                    f"Score improved from {pre_score} to {post_score} "
                    f"(Grade {pre_fix_eval.get('grade', '?')} → {post_fix_eval.get('grade', '?')}). "
                    "DNS changes verified."
                )
            elif post_score == pre_score:
                verification_note = (
                    "DNS changes submitted to Cloudflare but the verification "
                    "scan still sees the old values. This is normal — Cloudflare "
                    "edge propagation can take 30–120 seconds. Click Rescan in a "
                    "moment to see the updated grade."
                )
            # Persist improved result if better
            if HAS_DB and post_score >= pre_score:
                try:
                    db = get_database()
                    sid = db.start_scan(notes="Post-fix verification")
                    db.save_result(sid, domain, post_scan, post_fix_eval)
                    db.complete_scan(sid, 1)
                except Exception:
                    pass
        except Exception as ve:
            verification_note = f"Post-fix verification scan failed: {ve}"

    # Use post-fix evaluation if available, otherwise pre-fix
    final_eval = post_fix_eval if post_fix_eval else pre_fix_eval

    # Determine accurate status
    if applied_fixes and not failed_fixes and not manual_actions:
        status = "success"
    elif applied_fixes and not failed_fixes and manual_actions:
        status = "partial"
    elif applied_fixes and failed_fixes:
        status = "partial"
    elif not applied_fixes and not failed_fixes and not manual_actions:
        status = "no_action"
    else:
        status = "failed"

    return {
        "status": status,
        "domain": domain,
        "applied": applied_fixes,
        "failed": failed_fixes,
        "manual_actions": manual_actions,
        "grade": final_eval.get("grade", ""),
        "score": final_eval.get("score", 0),
        "violations": final_eval.get("violation_count", 0),
        "pre_fix_grade": pre_fix_eval.get("grade", ""),
        "pre_fix_score": pre_fix_eval.get("score", 0),
        "verification": verification_note,
        "cloudflare_zone": msg,
    }


@app.get("/api/fix-status", dependencies=[Depends(require_token)])
async def api_fix_status():
    """
    Check if Cloudflare DNS auto-fix is available.

    Returns:
        - available: boolean indicating if Cloudflare is configured
        - zone: zone name if connected
        - message: status message
    """
    if not HAS_DNS_FIX:
        return {
            "available": False,
            "zone": None,
            "message": "DNS fix module not installed",
        }

    cf = get_cloudflare_client()
    if not cf:
        return {
            "available": False,
            "zone": None,
            "message": "Cloudflare not configured. Set CF_API_TOKEN and CF_ZONE_ID.",
        }

    ok, msg = cf.validate_connection()
    return {
        "available": ok,
        "zone": msg.replace("Connected to zone: ", "") if ok else None,
        "message": msg,
    }


@app.get("/test", response_class=HTMLResponse, dependencies=[Depends(require_token)])
def test_hub():
    """Interactive testing hub for scanning domains."""
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuroraEdge Security - Scan Domains</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🧪</text></svg>">
    {_css()}
    {_auth_js()}
    {_test_css()}
</head>
<body>
    <div class="container">
        <!-- Professional Navigation Bar -->
        <nav class="top-nav">
            <a href="/" class="nav-brand">
                <span class="nav-brand-icon">🛡️</span>
                <span>AuroraEdge</span>
            </a>
            <div class="nav-links">
                <a href="/" class="nav-link">📊 Dashboard</a>
                <a href="/domains" class="nav-link">🌐 My Domains</a>
                <a href="/test" class="nav-link active">🔍 Scan</a>
                <a href="/generator" class="nav-link">🛠️ Generator</a>
                <a href="/settings" class="nav-link">⚙️ Settings</a>
            </div>
        </nav>
        
        <header>
            <div class="logo-area">
                <div class="logo">🔍</div>
                <div>
                    <h1>Domain Security Scan</h1>
                    <p class="subtitle">Analyse and defend email authentication for any domain</p>
                </div>
            </div>
        </header>
        
        <div class="help-box">
            <h3>🛡️ How It Works</h3>
            <p>
                Enter any domain below and AuroraEdge will check its 
                <strong>SPF</strong>, <strong>DMARC</strong>, <strong>DKIM</strong>, 
                <strong>MTA-STS</strong>, and <strong>TLS-RPT</strong> configurations. 
                You’ll get a security grade, score, and actionable remediation recommendations.
            </p>
        </div>
        
        <!-- Auto-Fix Demo Guide -->
        <div class="demo-guide" style="background:rgba(234,179,8,0.10); border:1px solid rgba(234,179,8,0.4); border-radius:12px; padding:20px 24px; margin-bottom:24px;">
            <h3 style="margin:0 0 10px; color:#fde68a;">⭐ Auto-Fix Demo Guide</h3>
            <p style="margin:0 0 8px; color:#e2e8f0; line-height:1.6;">
                The domain <strong style="color:#fde68a;">auroraedge.co.uk</strong> has been pre-configured with
                <strong>intentionally weakened</strong> email security records (SPF softfail, DMARC quarantine at 50%, no MTA-STS)
                so you can see the automated remediation engine detect and fix real issues.
            </p>
            <ol style="margin:8px 0 0; padding-left:20px; color:#cbd5e1; line-height:1.8;">
                <li>Click the <strong style="color:#fde68a;">⭐ auroraedge.co.uk (Auto-Fix Demo)</strong> button below, then press <strong>Scan Domain</strong>.</li>
                <li>Review the security grade and the list of violations flagged.</li>
                <li>Click the <strong style="color:#f59e0b;">🔧 Auto-Fix DNS</strong> button on the results to let AuroraEdge automatically create the missing records via the Cloudflare API.</li>
                <li>Hit <strong>🔄 Rescan</strong> to confirm the fixes have been applied and watch the grade improve.</li>
            </ol>
            <p style="margin:10px 0 0; color:#94a3b8; font-size:0.85rem;">
                You may also scan any other domain (your own, university domains, etc.) — only <em>auroraedge.co.uk</em> supports auto-fix as it is the Cloudflare-managed zone.
            </p>
        </div>
        
        <!-- Tab Navigation -->
        <div class="tabs">
            <div class="tab active" id="singleTab" onclick="switchTab('single')">Single Domain</div>
            <div class="tab" id="batchTab" onclick="switchTab('batch')">Batch Scan</div>
        </div>
        
        <!-- Single Domain Form -->
        <div class="test-form" id="singleForm">
            <div class="form-group">
                <label for="domainInput">Domain to Scan</label>
                <input type="text" id="domainInput" placeholder="e.g., auroraedge.co.uk (demo), google.com, belfastmet.ac.uk">
                <small>Enter a domain name without http:// or www. Try <strong>auroraedge.co.uk</strong> to test Auto-Fix.</small>
            </div>
            
            <div class="form-group">
                <label>Quick Examples</label>
                <div class="quick-domains" id="quickDomains"></div>
            </div>
            
            <div class="form-group">
                <div class="checkbox-group">
                    <label class="checkbox-item">
                        <input type="checkbox" id="saveDb" checked>
                        Save to database
                    </label>
                    <label class="checkbox-item">
                        <input type="checkbox" id="showRemediation" checked>
                        Show remediation tips
                    </label>
                </div>
            </div>
            
            <button class="btn-scan" onclick="scanDomain()">
                🔍 Scan Domain
            </button>
        </div>
        
        <!-- Batch Scan Form -->
        <div class="test-form" id="batchForm" style="display: none;">
            <div class="form-group">
                <label for="batchInput">Domains to Scan (one per line)</label>
                <textarea id="batchInput" placeholder="example.com
google.com
microsoft.com
# Lines starting with # are ignored"></textarea>
                <small>Enter up to 20 domains, one per line. Lines starting with # are ignored.</small>
            </div>
            
            <div class="form-group">
                <div class="checkbox-group">
                    <label class="checkbox-item">
                        <input type="checkbox" id="batchSaveDb" checked>
                        Save to database
                    </label>
                    <label class="checkbox-item">
                        <input type="checkbox" id="batchRemediation" checked>
                        Show remediation tips
                    </label>
                <div style="width:100%;background:rgba(255,255,255,0.1);border-radius:8px;overflow:hidden;margin-top:16px;height:22px;">
                    <div id="scanProgress" style="height:100%;background:var(--accent);border-radius:8px;transition:width 0.3s ease;text-align:center;font-size:0.75rem;line-height:22px;color:#fff;width:0%;"></div>
                </div>
                </div>
            </div>
            
            <button class="btn-scan" onclick="scanBatch()">
                🚀 Start Batch Scan
            </button>
        </div>
        
        <!-- Results Section -->
        <div id="resultsSection" style="display: none;">
            <h2 style="margin-bottom: 16px;">Scan Results</h2>
            <div id="resultsContainer"></div>
        </div>
        
        <!-- Scanning Overlay -->
        <div class="scanning-overlay" id="scanningOverlay" style="display: none;">
            <div class="scanning-modal">
                <div class="scanning-spinner"></div>
                <p id="scanStatus">Scanning domains...</p>
            </div>
        </div>
        
        {_footer_html()}
    </div>
    
    {_test_js()}
</body>
</html>
"""
    return HTMLResponse(html)


@app.get(
    "/domain/{domain}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_token)],
)
def domain_detail(domain: str):
    """Detailed view for a specific domain — pulls from DB, falls back to CSV."""
    result = None

    # Try database first
    if HAS_DB:
        try:
            db = get_database()
            history = db.get_domain_history(domain, limit=10)
            if history:
                result = history[0]  # Most recent
        except Exception:
            pass

    # Fallback to CSV
    if not result:
        csv_file, _ = _latest_pair()
        if csv_file:
            rows = load_csv(csv_file)
            for row in rows:
                if row.get("domain", "").lower() == domain.lower():
                    result = row
                    break

    if not result:
        # Auto-scan the domain instead of showing a 404
        if HAS_SCANNER:
            try:
                scan_result = scan_domain(domain, check_starttls=False)
                scan_result["domain"] = domain
                evaluation = evaluate(scan_result)
                # Merge scan + evaluation into result dict for the page
                result = {**scan_result, **evaluation}
                # Persist to DB for future visits
                if HAS_DB:
                    try:
                        db = get_database()
                        scan_id = db.start_scan(notes=f"Auto-scan from domain page: {domain}")
                        db.save_result(scan_id, domain, scan_result, evaluation)
                        db.complete_scan(scan_id, 1)
                        db.update_managed_domain_scan(domain, evaluation.get("grade", "F"), evaluation.get("score", 0))
                    except Exception:
                        pass
            except Exception:
                pass

    if not result:
        # Redirect to scan page if scanner unavailable or scan failed
        return RedirectResponse(url=f"/test?domain={domain}", status_code=303)

    # Normalise — DB stores integers (0/1), CSV stores strings ("True"/"False")
    def _bool(val):
        if val is None:
            return False
        if isinstance(val, bool):
            return val
        if isinstance(val, int):
            return val == 1
        return str(val).strip().lower() in ("true", "1", "yes")

    grade = result.get("grade") or "F"
    grade_class = grade.lower().replace("+", "-plus")
    score = result.get("score") or 0
    severity = result.get("severity") or "OK"
    violation_count = result.get("violation_count") or 0

    checks = [
        ("SPF", _bool(result.get("spf_present")),
         f"Lookups: {result.get('spf_lookups', 'N/A')}, All: {result.get('spf_all', 'N/A')}"),
        ("DMARC", _bool(result.get("dmarc_present")),
         f"Policy: {result.get('dmarc_policy', 'N/A')}, pct: {result.get('dmarc_pct', 'N/A')}"),
        ("DKIM", _bool(result.get("dkim_present")),
         f"Selectors: {result.get('dkim_selectors', 'N/A')}"),
        ("MTA-STS", _bool(result.get("mta_sts_present")),
         f"Mode: {result.get('mta_sts_mode', 'N/A')}"),
        ("TLS-RPT", _bool(result.get("tls_rpt_present")),
         f"RUA: {result.get('tls_rpt_rua', 'N/A')}"),
        ("BIMI", _bool(result.get("bimi_present")),
         f"Logo: {result.get('bimi_logo', 'N/A') or 'Not set'}"),
        ("MX Records", _bool(result.get("mx_present")),
         f"{result.get('mx_count', 0)} records"),
        ("Blacklists", result.get("rbl_listings", 0) == 0,
         "Clean" if result.get("rbl_listings", 0) == 0 else f"Listed on {result.get('rbl_listings', 0)} DNSBL(s)"),
    ]

    checks_html = ""
    for name, present, details in checks:
        status = (
            '<span class="check-yes">PASS</span>'
            if present
            else '<span class="check-no">FAIL</span>'
        )
        checks_html += f"""
        <tr>
            <td><strong>{name}</strong></td>
            <td>{status}</td>
            <td>{details}</td>
        </tr>"""

    # History section (from DB) + Score Timeline Chart
    history_html = ""
    timeline_chart_html = ""
    if HAS_DB:
        try:
            db = get_database()
            history = db.get_domain_history(domain, limit=10)
            if len(history) > 1:
                history_html = """
                <div class="section-card" style="margin-bottom: 24px;">
                    <h2>📈 Scan History</h2>
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Date</th><th>Grade</th><th>Score</th><th>Severity</th><th>Violations</th></tr></thead>
                            <tbody>"""
                for h in history:
                    scan_date = (h.get("scanned_at") or "")[:16].replace("T", " ")
                    h_grade = h.get("grade") or "?"
                    h_gc = h_grade.lower().replace("+", "-plus")
                    history_html += f"""
                                <tr>
                                    <td>{scan_date}</td>
                                    <td><span class="grade-badge {h_gc}" style="font-size:0.8rem;padding:2px 8px;">{h_grade}</span></td>
                                    <td>{h.get('score', 0)}</td>
                                    <td>{h.get('severity', 'OK')}</td>
                                    <td>{h.get('violation_count', 0)}</td>
                                </tr>"""
                history_html += """
                            </tbody>
                        </table>
                    </div>
                </div>"""

                # Build Chart.js score timeline
                chart_labels = []
                chart_scores = []
                for h in reversed(history):  # oldest first
                    chart_labels.append((h.get("scanned_at") or "")[:16].replace("T", " "))
                    chart_scores.append(h.get("score", 0))
                labels_json = json.dumps(chart_labels)
                scores_json = json.dumps(chart_scores)
                timeline_chart_html = f"""
                <div class="section-card" style="margin-bottom: 24px;">
                    <h2>📊 Score Timeline</h2>
                    <canvas id="scoreTimeline" height="200"></canvas>
                </div>
                <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
                <script>
                new Chart(document.getElementById('scoreTimeline'), {{
                    type: 'line',
                    data: {{
                        labels: {labels_json},
                        datasets: [{{
                            label: 'Security Score',
                            data: {scores_json},
                            borderColor: '#6366f1',
                            backgroundColor: 'rgba(99,102,241,0.1)',
                            fill: true,
                            tension: 0.3,
                            pointRadius: 5,
                            pointBackgroundColor: '#6366f1',
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{ legend: {{ display: false }} }},
                        scales: {{
                            y: {{ min: 0, max: 100, title: {{ display: true, text: 'Score', color: '#94a3b8' }}, ticks: {{ color: '#94a3b8' }}, grid: {{ color: 'rgba(148,163,184,0.1)' }} }},
                            x: {{ ticks: {{ color: '#94a3b8', maxRotation: 45 }}, grid: {{ color: 'rgba(148,163,184,0.1)' }} }}
                        }}
                    }}
                }});
                </script>"""
        except Exception:
            pass

    # Managed domain info
    managed_badge = ""
    if HAS_DB:
        try:
            db = get_database()
            managed = db.get_managed_domains()
            for m in managed:
                if m["domain"].lower() == domain.lower():
                    managed_badge = '<span style="background:var(--accent);color:#000;padding:4px 12px;border-radius:12px;font-size:0.8rem;font-weight:600;margin-left:12px;">MONITORED</span>'
                    break
        except Exception:
            pass

    scanned_at = (result.get("scanned_at") or "Unknown")[:19].replace("T", " ")

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuroraEdge Security - {domain}</title>
    {_css()}
    {_auth_js()}
    <style>
        .check-yes {{ color: var(--success); font-weight: 700; }}
        .check-no {{ color: var(--danger); font-weight: 700; }}
        .detail-actions {{ display: flex; gap: 12px; margin: 24px 0; flex-wrap: wrap; }}
    </style>
</head>
<body>
    <div class="container">
        {_nav_html()}

        <header>
            <div class="logo-area">
                <div class="logo" style="font-size: 1.5rem;">🌐</div>
                <div>
                    <h1>{domain}{managed_badge}</h1>
                    <p class="subtitle">Last scanned: {scanned_at}</p>
                </div>
            </div>
            <span class="grade-badge {grade_class}" style="font-size:2rem; padding: 12px 24px;">{grade}</span>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon score">📊</div>
                <div class="stat-value">{score}</div>
                <div class="stat-label">Security Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon {"high" if severity == "HIGH" else "warn" if severity == "WARN" else "domains"}">⚡</div>
                <div class="stat-value">{severity}</div>
                <div class="stat-label">Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon warn">🔔</div>
                <div class="stat-value">{violation_count}</div>
                <div class="stat-label">Violations</div>
            </div>
        </div>

        <div class="detail-actions">
            <button class="btn btn-primary" id="rescanBtn" onclick="rescanThisDomain()">🔄 Rescan Now</button>
            <button class="btn btn-secondary" onclick="fixDomain()" style="background:var(--warning);color:#000;border-color:var(--warning);">🔧 Auto-Fix DNS</button>
            <a href="/api/report/pdf/{domain}" class="btn btn-secondary" style="background:var(--accent);color:#000;border-color:var(--accent);">📄 Download PDF Report</a>
            <a href="/domains" class="btn btn-secondary">← Back to My Domains</a>
        </div>

        <div class="section-card" style="margin-bottom: 24px;">
            <h2>🔍 Security Checks</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr><th>Check</th><th>Status</th><th>Details</th></tr>
                    </thead>
                    <tbody>
                        {checks_html}
                    </tbody>
                </table>
            </div>
        </div>

        {history_html}

        {timeline_chart_html}

        <div class="section-card">
            <h2>📝 Violations & Recommendations</h2>
            <p style="margin-bottom: 12px;"><strong>Issues:</strong> {result.get("violations") or "None"}</p>
            <p><strong>Advice:</strong> {result.get("advice") or "All checks passed"}</p>
        </div>

        {_footer_html()}
    </div>

    <script>
    async function fixDomain() {{
        if (!confirm('Auto-Fix will attempt to update DNS records for {domain} via Cloudflare.\\n\\nProceed?')) return;
        try {{
            const cfRes = await fetch('/api/settings/test-cloudflare');
            const cfData = await cfRes.json();
            if (!cfData.ok) {{
                alert('Cloudflare is not configured.\\nGo to Settings to add your API Token and Zone ID.');
                return;
            }}
            // Frontend ownership check
            const zone = (cfData.zone_name || '').toLowerCase();
            const dom = '{domain}'.toLowerCase();
            if (zone && dom !== zone && !dom.endsWith('.' + zone)) {{
                alert('⛔ Cannot auto-fix "{domain}"\\n\\nYour Cloudflare zone is "' + zone + '".\\nYou can only auto-fix domains within that zone.\\n\\nGo to Settings if you need to change your Cloudflare credentials.');
                return;
            }}
            const res = await fetch('/api/apply-fix', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{domain: '{domain}'}})
            }});
            const data = await res.json();
            if (!res.ok) {{
                alert('⛔ Auto-Fix Blocked\\n\\n' + (data.detail || 'Unknown error.'));
                return;
            }}
            let msg = '';
            if (data.applied && data.applied.length > 0)
                msg += '✅ Fixes applied:\\n' + data.applied.map(f => '  ✓ ' + f.type + ': ' + f.message).join('\\n');
            if (data.failed && data.failed.length > 0)
                msg += (msg ? '\\n\\n' : '') + '❌ Failed:\\n' + data.failed.map(f => '  ✗ ' + f.type + ': ' + f.message).join('\\n');
            if (data.manual_actions && data.manual_actions.length > 0)
                msg += (msg ? '\\n\\n' : '') + '🔧 Manual steps still needed:\\n' + data.manual_actions.map(m => '  ⚠ ' + m.type + ': ' + m.description).join('\\n');
            if (data.verification)
                msg += (msg ? '\\n\\n' : '') + '🔍 Verification: ' + data.verification;
            if (data.pre_fix_grade && data.grade && data.pre_fix_grade !== data.grade)
                msg += '\\n📈 Grade: ' + data.pre_fix_grade + ' → ' + data.grade + ' (Score: ' + data.pre_fix_score + ' → ' + data.score + ')';
            else if (data.grade)
                msg += '\\n📊 Grade: ' + data.grade + ' | Score: ' + data.score;
            if (!msg && data.grade) {{
                msg = 'Current grade: ' + data.grade + ' (Score: ' + data.score + ')\\nNo auto-fixable issues found.';
                if (data.violations > 0) msg += '\\n\\n⚠ ' + data.violations + ' issue(s) detected but they require manual configuration.';
                else msg += ' Domain looks good!';
            }} else if (!msg) {{
                msg = 'No issues found — domain looks good!';
            }}
            alert(msg);
        }} catch(e) {{
            alert('Error: ' + e.message);
        }}
    }}

    async function rescanThisDomain() {{
        const btn = document.getElementById('rescanBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '⏳ Rescanning…';
        try {{
            const res = await fetch('/api/rescan/' + encodeURIComponent('{domain}'), {{
                method: 'POST'
            }});
            const data = await res.json();
            if (!res.ok) {{
                alert('Rescan failed: ' + (data.detail || 'Unknown error'));
                return;
            }}
            // Reload the page so the server renders fresh data
            location.reload();
        }} catch(e) {{
            alert('Error: ' + e.message);
        }} finally {{
            btn.disabled = false;
            btn.innerHTML = orig;
        }}
    }}
    </script>
</body>
</html>
"""
    return HTMLResponse(html)


# =============================================================================
# My Domains (Management Page)
# =============================================================================


def _nav_html(active: str = "") -> str:
    """Generate consistent navigation bar. active = 'dashboard'|'domains'|'scan'|'settings'"""
    # Get alert count for badge
    badge = ""
    if HAS_DB:
        try:
            db = get_database()
            count = db.get_alert_count()
            if count > 0:
                badge = f'<span style="background:var(--danger);color:#fff;border-radius:10px;padding:2px 8px;font-size:0.7rem;margin-left:4px;">{count}</span>'
        except Exception:
            pass

    def _cls(name):
        if name == active:
            return "nav-link active"
        if name == "scan":
            return "nav-link highlight"
        return "nav-link"

    return f"""
    <nav class="top-nav">
        <a href="/" class="nav-brand">
            <span class="nav-brand-icon">🛡️</span>
            <span>AuroraEdge</span>
        </a>
        <div class="nav-links">
            <a href="/" class="{_cls('dashboard')}">📊 Dashboard</a>
            <a href="/domains" class="{_cls('domains')}">🌐 My Domains{badge}</a>
            <a href="/test" class="{_cls('scan')}">🔍 Scan</a>
            <a href="/generator" class="{_cls('generator')}">🛠️ Generator</a>
            <a href="/settings" class="{_cls('settings')}">⚙️ Settings</a>
        </div>
    </nav>
    """


def _footer_html() -> str:
    """Consistent footer across all pages."""
    return """
    <footer>
        <div style="margin-bottom: 16px;">
            <strong style="font-size: 1.1rem; color: var(--text-primary);">AuroraEdge</strong>
            <span style="color: var(--accent);"> · </span>
            <span>Automated Email Authentication & Cyber Defence System</span>
        </div>
        <p><strong>Final Year Project</strong> · Leon Chapman (50030738)</p>
        <p style="margin-top: 8px;">Belfast Metropolitan College · BSc Cybersecurity &amp; Networking Infrastructure · 2025/2026</p>
        <p style="margin-top: 6px; font-size: 0.75rem; color: var(--text-dim);">Public DNS checks only &middot; Local settings stay on this device &middot; <a href="https://github.com/L-chapman/AuroraEdge-FYP/blob/master/docs/PRIVACY_AND_ETHICS.md" style="color: var(--accent);">Privacy &amp; Ethics Policy</a></p>
    </footer>
    """


@app.get("/domains", response_class=HTMLResponse, dependencies=[Depends(require_token)])
def domains_page():
    """Managed domains page \u2014 the core of the SME experience."""
    # Get managed domains and alerts
    domains_list = []
    alerts = []
    if HAS_DB:
        try:
            db = get_database()
            domains_list = db.get_managed_domains()
            alerts = db.get_alerts(unacknowledged_only=True, limit=20)
        except Exception:
            pass

    # Build domain cards
    domain_cards = ""
    if domains_list:
        for d in domains_list:
            grade = d.get("last_grade") or "—"
            score = d.get("last_score") or 0
            grade_class = grade.lower().replace("+", "-plus") if grade != "—" else "f"
            prev_grade = d.get("previous_grade") or ""
            drift = ""
            if prev_grade and prev_grade != grade:
                grade_order = ["A+", "A", "B", "C", "D", "F"]
                old_i = grade_order.index(prev_grade) if prev_grade in grade_order else 5
                new_i = grade_order.index(grade) if grade in grade_order else 5
                if new_i > old_i:
                    drift = f'<span style="color:var(--danger);font-size:0.8rem;">▼ was {prev_grade}</span>'
                elif new_i < old_i:
                    drift = f'<span style="color:var(--success);font-size:0.8rem;">▲ was {prev_grade}</span>'

            last_scan = d.get("last_scan_at") or "Never"
            if last_scan != "Never":
                last_scan = last_scan[:16].replace("T", " ")

            domain_cards += f"""
            <div class="domain-card" data-domain="{d['domain']}">
                <div class="domain-card-header">
                    <div>
                        <div class="domain-card-name">{d['domain']}</div>
                        <div class="domain-card-meta">Last scanned: {last_scan} {drift}</div>
                    </div>
                    <div class="domain-card-grade">
                        <span class="grade-badge {grade_class}" style="font-size:1.4rem;padding:8px 16px;">{grade}</span>
                        <div style="text-align:center;margin-top:4px;font-size:0.8rem;color:var(--text-muted);">{score}/100</div>
                    </div>
                </div>
                <div class="domain-card-actions">
                    <button class="action-btn primary" onclick="rescanManaged('{d['domain']}')">🔄 Rescan</button>
                    <button class="action-btn secondary" onclick="fixDomain('{d['domain']}')">🔧 Auto-Fix</button>
                    <a href="/domain/{d['domain']}" class="action-btn secondary">📋 Details</a>
                    <button class="action-btn secondary" onclick="removeDomain('{d['domain']}')" style="margin-left:auto;color:var(--danger);">✕ Remove</button>
                </div>
            </div>"""
    else:
        domain_cards = """
        <div class="section-card" style="text-align:center; padding: 48px;">
            <div style="font-size: 2.5rem; margin-bottom: 16px;">🌐</div>
            <h3 style="margin-bottom: 12px;">No Domains Onboarded</h3>
            <p style="color:var(--text-secondary); margin-bottom: 24px;">
                Add your organisation's domain to begin automated monitoring and defence.
            </p>
        </div>"""

    # Build alerts section
    alerts_html = ""
    if alerts:
        alerts_html = '<div class="alerts-section"><h2>⚡ Active Alerts</h2>'
        for a in alerts:
            sev_cls = (a.get("severity") or "info").lower()
            alerts_html += f"""
            <div class="alert-item {sev_cls}">
                <div class="alert-content">
                    <strong>{a['message']}</strong>
                    <span style="color:var(--text-muted);font-size:0.8rem;margin-left:8px;">{(a.get('created_at') or '')[:16].replace('T',' ')}</span>
                    {f'<div style="color:var(--text-secondary);font-size:0.85rem;margin-top:4px;">{a["details"]}</div>' if a.get("details") else ''}
                </div>
                <button class="action-btn secondary" onclick="dismissAlert({a['id']})" style="flex-shrink:0;">Dismiss</button>
            </div>"""
        alerts_html += "</div>"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuroraEdge Security - My Domains</title>
    {_css()}
    {_auth_js()}
    <style>
        .domain-card {{
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 24px;
            border: 1px solid var(--border);
            margin-bottom: 16px;
            transition: all 0.2s ease;
        }}
        .domain-card:hover {{ border-color: var(--accent); }}
        .domain-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        .domain-card-name {{
            font-size: 1.3rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .domain-card-meta {{
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 4px;
        }}
        .domain-card-actions {{
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .action-btn {{
            padding: 10px 18px;
            border-radius: var(--radius-sm);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.85rem;
            text-decoration: none;
        }}
        .action-btn.primary {{
            background: var(--accent);
            color: #fff;
        }}
        .action-btn.primary:hover {{ background: var(--accent-hover); transform: translateY(-1px); }}
        .action-btn.secondary {{
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }}
        .action-btn.secondary:hover {{ background: var(--bg-hover); border-color: var(--accent); }}
        .add-domain-form {{
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 24px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            display: flex;
            gap: 12px;
            align-items: flex-end;
            flex-wrap: wrap;
        }}
        .add-domain-form .form-field {{ flex: 1; min-width: 250px; }}
        .add-domain-form label {{
            display: block;
            font-weight: 600;
            margin-bottom: 6px;
            font-size: 0.9rem;
        }}
        .add-domain-form input {{
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text-primary);
            font-size: 1rem;
        }}
        .add-domain-form input:focus {{
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }}
        .alerts-section {{ margin-bottom: 24px; }}
        .alert-item {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 20px;
            border-radius: var(--radius-sm);
            margin-bottom: 8px;
            border-left: 4px solid;
        }}
        .alert-item.high {{ background: var(--danger-bg); border-color: var(--danger); }}
        .alert-item.warn {{ background: var(--warning-bg); border-color: var(--warning); }}
        .alert-item.info {{ background: var(--info-bg); border-color: var(--info); }}
        .alert-content {{ flex: 1; }}
        .fix-overlay {{
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.7); display: none; align-items: center;
            justify-content: center; z-index: 1000;
        }}
        .fix-modal {{
            background: var(--bg-card); padding: 32px; border-radius: var(--radius);
            max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        {_nav_html('domains')}

        <header>
            <div class="logo-area">
                <div class="logo">🌐</div>
                <div>
                    <h1>My Domains</h1>
                    <p class="subtitle">Manage and defend your organisation's email domains</p>
                </div>
            </div>
            <div class="header-right">
                <div class="live-indicator">
                    <span class="live-dot"></span>
                    <span>Monitoring Active</span>
                </div>
            </div>
        </header>

        {alerts_html}

        <div class="add-domain-form">
            <div class="form-field">
                <label for="newDomain">Add Domain</label>
                <input type="text" id="newDomain" placeholder="e.g., yourcompany.com">
            </div>
            <button class="btn btn-primary" onclick="addDomain()" style="height:46px;">+ Add Domain</button>
        </div>

        <div id="domainsList">
            {domain_cards}
        </div>

        <!-- Fix Modal -->
        <div class="fix-overlay" id="fixOverlay" onclick="if(event.target===this)this.style.display='none'">
            <div class="fix-modal">
                <h2 style="margin-bottom:16px;">🔧 Auto-Fix DNS Records</h2>
                <p id="fixStatus" style="color:var(--text-secondary);margin-bottom:16px;">Analysing domain...</p>
                <div id="fixResults"></div>
                <button class="btn btn-secondary" onclick="document.getElementById('fixOverlay').style.display='none'" style="margin-top:16px;">Close</button>
            </div>
        </div>

        {_footer_html()}
    </div>

    <script>
    async function addDomain() {{
        const domain = document.getElementById('newDomain').value.trim();
        if (!domain) {{ alert('Please enter a domain'); return; }}
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = 'Adding...';
        try {{
            const res = await fetch('/api/managed-domains', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{domain: domain}})
            }});
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Failed');
            location.reload();
        }} catch(e) {{
            alert('Error: ' + e.message);
            btn.disabled = false;
            btn.textContent = '+ Add Domain';
        }}
    }}

    async function removeDomain(domain) {{
        if (!confirm('Remove ' + domain + ' from monitoring?')) return;
        try {{
            const res = await fetch('/api/managed-domains/' + domain, {{method: 'DELETE'}});
            if (!res.ok) throw new Error('Failed');
            location.reload();
        }} catch(e) {{
            alert('Error: ' + e.message);
        }}
    }}

    async function rescanManaged(domain) {{
        const card = document.querySelector('[data-domain="' + domain + '"]');
        const btn = card ? card.querySelector('.action-btn.primary') : null;
        if (btn) {{ btn.disabled = true; btn.textContent = '⏳ Scanning...'; }}
        if (card) card.style.opacity = '0.6';
        try {{
            const res = await fetch('/api/rescan/' + encodeURIComponent(domain), {{
                method: 'POST'
            }});
            const data = await res.json();
            if (!res.ok) {{
                alert('Rescan failed: ' + (data.detail || 'Unknown error'));
                return;
            }}
            // Update the card in-place
            const ev = data.evaluation || {{}};
            const grade = ev.grade || 'F';
            const score = ev.score || 0;
            const gradeClass = grade.toLowerCase().replace('+', '-plus');
            if (card) {{
                const gradeBadge = card.querySelector('.grade-badge');
                if (gradeBadge) {{
                    gradeBadge.textContent = grade;
                    gradeBadge.className = 'grade-badge ' + gradeClass;
                }}
                const scoreEl = card.querySelector('.domain-card-grade div');
                if (scoreEl) scoreEl.textContent = score + '/100';
                const metaEl = card.querySelector('.domain-card-meta');
                if (metaEl) metaEl.textContent = 'Last scanned: ' + new Date().toISOString().slice(0,16).replace('T',' ');
                card.style.opacity = '1';
            }}
        }} catch(e) {{
            alert('Error: ' + e.message);
        }} finally {{
            if (btn) {{ btn.disabled = false; btn.textContent = '🔄 Rescan'; }}
            if (card) card.style.opacity = '1';
        }}
    }}

    async function fixDomain(domain) {{
        const overlay = document.getElementById('fixOverlay');
        const status = document.getElementById('fixStatus');
        const results = document.getElementById('fixResults');
        overlay.style.display = 'flex';
        status.textContent = 'Checking Cloudflare access for ' + domain + '...';
        results.innerHTML = '';

        try {{
            // Check if Cloudflare is configured and get zone name
            const cfRes = await fetch('/api/settings/test-cloudflare');
            const cfData = await cfRes.json();
            if (!cfData.ok) {{
                status.textContent = '⚠️ Cloudflare not connected';
                results.innerHTML = `
                    <div style="background:var(--warning-bg);padding:16px;border-radius:8px;margin-top:12px;">
                        <p><strong>Cloudflare API is not configured.</strong></p>
                        <p style="color:var(--text-secondary);margin-top:8px;">
                            To auto-fix DNS records, go to <a href="/settings" style="color:var(--accent);">Settings</a> 
                            and add your Cloudflare API Token and Zone ID.
                        </p>
                    </div>`;
                return;
            }}

            // Frontend ownership check — block before sending the fix request
            const zone = (cfData.zone_name || '').toLowerCase();
            const dom = domain.toLowerCase();
            if (zone && dom !== zone && !dom.endsWith('.' + zone)) {{
                status.textContent = '⛔ Domain not in your Cloudflare zone';
                results.innerHTML = `
                    <div style="background:var(--danger-bg);padding:16px;border-radius:8px;margin-top:12px;">
                        <p><strong>Cannot auto-fix "${{domain}}"</strong></p>
                        <p style="color:var(--text-secondary);margin-top:8px;">
                            Your Cloudflare zone is <strong>"${{zone}}"</strong>. You can only
                            auto-fix domains within that zone (e.g. <strong>${{zone}}</strong>
                            or <strong>sub.${{zone}}</strong>).
                        </p>
                        <p style="color:var(--text-secondary);margin-top:8px;">
                            Go to <a href="/settings" style="color:var(--accent);">Settings</a>
                            to change your Cloudflare credentials, or scan a domain you control.
                        </p>
                    </div>`;
                return;
            }}

            status.textContent = 'Scanning ' + domain + ' and applying fixes...';

            // Apply fixes
            const res = await fetch('/api/apply-fix', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{domain: domain}})
            }});
            const data = await res.json();

            if (!res.ok) {{
                // Server rejected the request (e.g. domain not in configured zone)
                status.textContent = '⛔ Auto-Fix Blocked';
                results.innerHTML = `
                    <div style="background:var(--danger-bg);padding:16px;border-radius:8px;margin-top:12px;">
                        <p><strong>${{data.detail || 'Unable to apply fixes.'}}</strong></p>
                        <p style="color:var(--text-secondary);margin-top:8px;">
                            You can only auto-fix domains whose DNS is managed by your
                            configured Cloudflare zone. Check
                            <a href="/settings" style="color:var(--accent);">Settings</a>
                            to verify your Zone ID matches this domain.
                        </p>
                    </div>`;
                return;
            }}

            let html = '<div style="margin-top:12px;">';
            let hasContent = false;

            if (data.applied && data.applied.length > 0) {{
                data.applied.forEach(f => {{
                    html += `<div style="background:var(--success-bg);padding:12px;border-radius:6px;margin-bottom:8px;">
                        <strong>✅ ${{f.type}}</strong> — ${{f.message}}</div>`;
                }});
                hasContent = true;
            }}
            if (data.failed && data.failed.length > 0) {{
                data.failed.forEach(f => {{
                    html += `<div style="background:var(--danger-bg);padding:12px;border-radius:6px;margin-bottom:8px;">
                        <strong>❌ ${{f.type}}</strong> — ${{f.message}}</div>`;
                }});
                hasContent = true;
            }}
            if (data.manual_actions && data.manual_actions.length > 0) {{
                html += `<div style="background:var(--bg-secondary);padding:12px;border-radius:6px;margin-bottom:8px;border-left:3px solid var(--warning);">
                    <strong>🔧 Manual Steps Required</strong></div>`;
                data.manual_actions.forEach(m => {{
                    html += `<div style="background:var(--bg-tertiary);padding:12px;border-radius:6px;margin-bottom:8px;border-left:3px solid var(--warning);">
                        <strong>⚠ ${{m.type}}</strong> — ${{m.description}}`;
                    if (m.steps) html += `<br><small style="color:var(--text-secondary);white-space:pre-line;margin-top:4px;display:block;">${{m.steps}}</small>`;
                    html += `</div>`;
                }});
                hasContent = true;
            }}

            if (data.verification) {{
                html += `<div style="padding:12px;border-radius:6px;margin-top:8px;background:var(--bg-secondary);border-left:3px solid var(--accent);">
                    🔍 <strong>Verification:</strong> ${{data.verification}}</div>`;
            }}
            if (data.pre_fix_grade && data.grade && data.pre_fix_grade !== data.grade) {{
                html += `<div style="padding:12px;border-radius:6px;margin-top:8px;background:var(--success-bg);text-align:center;">
                    📈 <strong>Grade: ${{data.pre_fix_grade}} → ${{data.grade}}</strong> | Score: ${{data.pre_fix_score}} → ${{data.score}} | Issues: ${{data.violations || 0}}</div>`;
            }} else if (data.grade) {{
                html += `<div style="padding:12px;border-radius:6px;margin-top:8px;background:var(--bg-secondary);text-align:center;">
                    📊 <strong>Grade: ${{data.grade}}</strong> | Score: ${{data.score}} | Issues: ${{data.violations || 0}}</div>`;
            }}
            html += '</div>';

            if (data.applied && data.applied.length > 0 && (!data.manual_actions || data.manual_actions.length === 0)) {{
                status.textContent = '✅ All fixes applied successfully!';
            }} else if (data.applied && data.applied.length > 0) {{
                status.textContent = '⚠️ Some fixes applied — manual steps still needed';
            }} else if (data.manual_actions && data.manual_actions.length > 0) {{
                status.textContent = '🔧 No auto-fixes available — manual configuration required';
            }} else if (!hasContent && data.violations === 0) {{
                status.textContent = '✅ No fixes needed — domain looks good!';
            }} else if (!hasContent) {{
                status.textContent = '⚠️ Issues detected but no auto-fixes available';
            }} else {{
                status.textContent = '⚠️ Some fixes failed';
            }}

            if (hasContent || data.grade) results.innerHTML = html;
        }} catch(e) {{
            status.textContent = '❌ Error: ' + e.message;
        }}
    }}

    async function dismissAlert(id) {{
        try {{
            await fetch('/api/alerts/' + id + '/acknowledge', {{method: 'POST'}});
            location.reload();
        }} catch(e) {{
            alert('Error: ' + e.message);
        }}
    }}

    // Enter key to add domain
    document.getElementById('newDomain')?.addEventListener('keydown', function(e) {{
        if (e.key === 'Enter') addDomain();
    }});
    </script>
</body>
</html>
"""
    return HTMLResponse(html)


# =============================================================================
# DNS Record Generator (Wizard)
# =============================================================================


@app.get("/generator", response_class=HTMLResponse, dependencies=[Depends(require_token)])
def generator_page():
    """Interactive DNS record generator for SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI."""
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuroraEdge — DNS Record Generator</title>
    {_css()}
    {_auth_js()}
    <style>
        .gen-form {{ background:var(--card-bg); border:1px solid var(--border); border-radius:12px; padding:24px; margin-bottom:24px; }}
        .gen-form h3 {{ color:var(--accent); margin-bottom:12px; }}
        .gen-form label {{ display:block; margin:8px 0 4px; font-weight:600; font-size:0.85rem; color: var(--text-dim); }}
        .gen-form input, .gen-form select {{ width:100%; padding:8px 12px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--text); font-size:0.9rem; box-sizing:border-box; }}
        .gen-form input:focus, .gen-form select:focus {{ border-color:var(--primary); outline:none; }}
        .gen-output {{ background:#1e293b; color:#e2e8f0; padding:16px; border-radius:8px; font-family:monospace; font-size:0.85rem; word-break:break-all; margin-top:12px; min-height:40px; position:relative; }}
        .gen-output .copy-btn {{ position:absolute; top:8px; right:8px; background:var(--primary); color:#fff; border:none; padding:4px 12px; border-radius:6px; cursor:pointer; font-size:0.75rem; }}
        .gen-grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap:24px; }}
    </style>
</head>
<body>
    <div class="container">
        {_nav_html(active="generator")}

        <header>
            <div class="logo-area">
                <div class="logo" style="font-size:1.5rem;">🛠️</div>
                <div>
                    <h1>DNS Record Generator</h1>
                    <p class="subtitle">Build RFC-compliant email security records interactively</p>
                </div>
            </div>
        </header>

        <div class="gen-grid">
            <!-- SPF Generator -->
            <div class="gen-form">
                <h3>🔒 SPF Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 7208 — Sender Policy Framework</p>
                <label>Domain</label>
                <input type="text" id="spf_domain" placeholder="example.com" oninput="genSPF()">
                <label>Email Provider Includes (comma-separated)</label>
                <input type="text" id="spf_includes" placeholder="_spf.google.com, spf.protection.outlook.com" oninput="genSPF()">
                <label>Additional IPs (comma-separated)</label>
                <input type="text" id="spf_ips" placeholder="203.0.113.10, 198.51.100.0/24" oninput="genSPF()">
                <label>Failure Policy</label>
                <select id="spf_all" onchange="genSPF()">
                    <option value="-all" selected>-all (Hardfail — recommended)</option>
                    <option value="~all">~all (Softfail)</option>
                    <option value="?all">?all (Neutral)</option>
                </select>
                <div class="gen-output" id="spf_out"><button class="copy-btn" onclick="copyRec('spf_out')">Copy</button></div>
            </div>

            <!-- DMARC Generator -->
            <div class="gen-form">
                <h3>📋 DMARC Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 7489 — Domain-based Message Authentication</p>
                <label>Domain</label>
                <input type="text" id="dmarc_domain" placeholder="example.com" oninput="genDMARC()">
                <label>Policy</label>
                <select id="dmarc_policy" onchange="genDMARC()">
                    <option value="reject">reject (Strongest — recommended)</option>
                    <option value="quarantine">quarantine</option>
                    <option value="none">none (Monitor only)</option>
                </select>
                <label>Subdomain Policy</label>
                <select id="dmarc_sp" onchange="genDMARC()">
                    <option value="">(inherit from main policy)</option>
                    <option value="reject">reject</option>
                    <option value="quarantine">quarantine</option>
                    <option value="none">none</option>
                </select>
                <label>Aggregate Report Email (rua=)</label>
                <input type="text" id="dmarc_rua" placeholder="dmarc@example.com" oninput="genDMARC()">
                <label>Forensic Report Email (ruf=)</label>
                <input type="text" id="dmarc_ruf" placeholder="" oninput="genDMARC()">
                <label>Percentage</label>
                <input type="number" id="dmarc_pct" value="100" min="0" max="100" oninput="genDMARC()">
                <div class="gen-output" id="dmarc_out"><button class="copy-btn" onclick="copyRec('dmarc_out')">Copy</button></div>
            </div>

            <!-- MTA-STS Generator -->
            <div class="gen-form">
                <h3>🔐 MTA-STS Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 8461 — Mail Transfer Agent Strict Transport Security</p>
                <label>Domain</label>
                <input type="text" id="sts_domain" placeholder="example.com" oninput="genSTS()">
                <label>Mode</label>
                <select id="sts_mode" onchange="genSTS()">
                    <option value="enforce" selected>enforce (Recommended)</option>
                    <option value="testing">testing</option>
                    <option value="none">none</option>
                </select>
                <label>MX Hosts (one per line)</label>
                <input type="text" id="sts_mx" placeholder="mail.example.com" oninput="genSTS()">
                <label>Max Age (seconds)</label>
                <input type="number" id="sts_maxage" value="604800" oninput="genSTS()">
                <div class="gen-output" id="sts_dns_out"><button class="copy-btn" onclick="copyRec('sts_dns_out')">Copy</button><strong>DNS TXT Record:</strong><br></div>
                <div class="gen-output" id="sts_policy_out" style="margin-top:8px;"><button class="copy-btn" onclick="copyRec('sts_policy_out')">Copy</button><strong>Policy File (mta-sts.txt):</strong><br></div>
            </div>

            <!-- TLS-RPT Generator -->
            <div class="gen-form">
                <h3>📊 TLS-RPT Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 8460 — TLS Reporting</p>
                <label>Domain</label>
                <input type="text" id="tlsrpt_domain" placeholder="example.com" oninput="genTLSRPT()">
                <label>Report Email</label>
                <input type="text" id="tlsrpt_email" placeholder="tlsrpt@example.com" oninput="genTLSRPT()">
                <div class="gen-output" id="tlsrpt_out"><button class="copy-btn" onclick="copyRec('tlsrpt_out')">Copy</button></div>
            </div>

            <!-- BIMI Generator -->
            <div class="gen-form">
                <h3>🎨 BIMI Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 9495 — Brand Indicators for Message Identification</p>
                <label>Domain</label>
                <input type="text" id="bimi_domain" placeholder="example.com" oninput="genBIMI()">
                <label>SVG Logo URL</label>
                <input type="text" id="bimi_logo" placeholder="https://example.com/logo.svg" oninput="genBIMI()">
                <label>VMC Certificate URL (optional)</label>
                <input type="text" id="bimi_vmc" placeholder="https://example.com/vmc.pem" oninput="genBIMI()">
                <div class="gen-output" id="bimi_out"><button class="copy-btn" onclick="copyRec('bimi_out')">Copy</button></div>
            </div>
        </div>

        {_footer_html()}
    </div>

    <script>
    function genSPF() {{
        const d = document.getElementById('spf_domain').value.trim() || 'example.com';
        const inc = document.getElementById('spf_includes').value.split(',').map(s=>s.trim()).filter(Boolean);
        const ips = document.getElementById('spf_ips').value.split(',').map(s=>s.trim()).filter(Boolean);
        const all = document.getElementById('spf_all').value;
        let parts = ['v=spf1'];
        ips.forEach(ip => parts.push(ip.includes('/') || ip.includes(':') ? 'ip6:'+ip : 'ip4:'+ip));
        inc.forEach(i => parts.push('include:'+i));
        parts.push(all);
        const rec = parts.join(' ');
        const el = document.getElementById('spf_out');
        el.innerHTML = '<button class="copy-btn" onclick="copyRec(\\'spf_out\\')">Copy</button>' + d + '. IN TXT "' + rec + '"';
    }}

    function genDMARC() {{
        const d = document.getElementById('dmarc_domain').value.trim() || 'example.com';
        const p = document.getElementById('dmarc_policy').value;
        const sp = document.getElementById('dmarc_sp').value;
        const rua = document.getElementById('dmarc_rua').value.trim();
        const ruf = document.getElementById('dmarc_ruf').value.trim();
        const pct = parseInt(document.getElementById('dmarc_pct').value) || 100;
        let parts = ['v=DMARC1', 'p=' + p];
        if (sp) parts.push('sp=' + sp);
        if (pct < 100) parts.push('pct=' + pct);
        if (rua) parts.push('rua=mailto:' + rua);
        if (ruf) parts.push('ruf=mailto:' + ruf);
        const rec = parts.join('; ');
        const el = document.getElementById('dmarc_out');
        el.innerHTML = '<button class="copy-btn" onclick="copyRec(\\'dmarc_out\\')">Copy</button>_dmarc.' + d + '. IN TXT "' + rec + '"';
    }}

    function genSTS() {{
        const d = document.getElementById('sts_domain').value.trim() || 'example.com';
        const mode = document.getElementById('sts_mode').value;
        const mx = document.getElementById('sts_mx').value.trim() || ('mail.' + d);
        const maxAge = document.getElementById('sts_maxage').value || '604800';
        const id = new Date().toISOString().slice(0,10).replace(/-/g,'');
        document.getElementById('sts_dns_out').innerHTML = '<button class="copy-btn" onclick="copyRec(\\'sts_dns_out\\')">Copy</button><strong>DNS TXT Record:</strong><br>_mta-sts.' + d + '. IN TXT "v=STSv1; id=' + id + '"';
        document.getElementById('sts_policy_out').innerHTML = '<button class="copy-btn" onclick="copyRec(\\'sts_policy_out\\')">Copy</button><strong>Policy File (https://mta-sts.' + d + '/.well-known/mta-sts.txt):</strong><br>version: STSv1\\nmode: ' + mode + '\\nmx: ' + mx + '\\nmax_age: ' + maxAge;
    }}

    function genTLSRPT() {{
        const d = document.getElementById('tlsrpt_domain').value.trim() || 'example.com';
        const email = document.getElementById('tlsrpt_email').value.trim() || ('tlsrpt@' + d);
        const el = document.getElementById('tlsrpt_out');
        el.innerHTML = '<button class="copy-btn" onclick="copyRec(\\'tlsrpt_out\\')">Copy</button>_smtp._tls.' + d + '. IN TXT "v=TLSRPTv1; rua=mailto:' + email + '"';
    }}

    function genBIMI() {{
        const d = document.getElementById('bimi_domain').value.trim() || 'example.com';
        const logo = document.getElementById('bimi_logo').value.trim();
        const vmc = document.getElementById('bimi_vmc').value.trim();
        const el = document.getElementById('bimi_out');
        el.innerHTML = '<button class="copy-btn" onclick="copyRec(\\'bimi_out\\')">Copy</button>default._bimi.' + d + '. IN TXT "v=BIMI1; l=' + (logo || 'https://' + d + '/logo.svg') + '; a=' + (vmc || '') + '"';
    }}

    function copyRec(id) {{
        const el = document.getElementById(id);
        const text = el.innerText.replace('Copy', '').trim();
        navigator.clipboard.writeText(text).then(() => {{
            if (typeof showToast === 'function') showToast('Copied to clipboard!', 'success');
        }});
    }}

    // Initialize
    genSPF(); genDMARC(); genSTS(); genTLSRPT(); genBIMI();
    </script>
</body>
</html>
"""
    return HTMLResponse(html)


# =============================================================================
# Settings Page
# =============================================================================


@app.get("/settings", response_class=HTMLResponse, dependencies=[Depends(require_token)])
def settings_page():
    """Application settings page — Cloudflare credentials, monitoring config."""
    settings = {}
    if HAS_DB:
        try:
            db = get_database()
            settings = db.get_all_settings()
        except Exception:
            pass

    cf_token_display = ""
    cf_token_set = False
    if settings.get("cf_api_token"):
        t = settings["cf_api_token"]
        cf_token_display = t[:8] + "..." + t[-4:] if len(t) > 12 else "***"
        cf_token_set = True
    cf_api_key_display = ""
    cf_api_key_set = False
    if settings.get("cf_api_key"):
        k = settings["cf_api_key"]
        cf_api_key_display = k[:8] + "..." + k[-4:] if len(k) > 12 else "***"
        cf_api_key_set = True

    zone_id = settings.get("cf_zone_id", "")
    account_id = settings.get("cf_account_id", "")
    cf_email = settings.get("cf_email", "")
    interval = settings.get("monitor_interval", "24")
    org_name = settings.get("org_name", "")
    alert_email = settings.get("alert_email", "")
    clear_on_start = settings.get("clear_on_start", "true").lower() in ("true", "1", "yes")

    # Gather system info
    db_status = "Connected" if HAS_DB else "Not available"
    scanner_status = "Loaded" if HAS_SCANNER else "Not available"
    dns_fix_status = "Loaded" if HAS_DNS_FIX else "Not available"
    domain_count = 0
    scan_count = 0
    if HAS_DB:
        try:
            d = get_database()
            domain_count = len(d.get_managed_domains())
            stats = d.get_statistics()
            scan_count = stats.get("total_scans", 0)
        except Exception:
            pass

    cf_badge = '<span class="status-chip connected">Connected</span>' if cf_token_set and zone_id else '<span class="status-chip not-connected">Not configured</span>'

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuroraEdge Security - Settings</title>
    {_css()}
    {_auth_js()}
    <style>
        .settings-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }}
        @media (max-width: 900px) {{
            .settings-grid {{ grid-template-columns: 1fr; }}
        }}
        .settings-card {{
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 28px;
            border: 1px solid var(--border);
        }}
        .settings-card.full-width {{
            grid-column: 1 / -1;
        }}
        .settings-card h3 {{
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.05rem;
        }}
        .settings-card .card-desc {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 20px;
            line-height: 1.5;
        }}
        .form-row {{
            margin-bottom: 18px;
        }}
        .form-row label {{
            display: block;
            font-weight: 600;
            margin-bottom: 6px;
            font-size: 0.88rem;
            color: var(--text-primary);
        }}
        .form-row input, .form-row select {{
            width: 100%;
            padding: 11px 14px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text-primary);
            font-size: 0.92rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        .form-row input:focus, .form-row select:focus {{
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }}
        .form-row small {{
            display: block;
            margin-top: 4px;
            color: var(--text-muted);
            font-size: 0.78rem;
        }}
        .form-row .current-value {{
            color: var(--text-secondary);
            font-size: 0.83rem;
            margin-top: 4px;
        }}
        .input-group {{
            position: relative;
            display: flex;
            align-items: center;
        }}
        .input-group input {{
            padding-right: 48px;
        }}
        .toggle-vis {{
            position: absolute;
            right: 8px;
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 6px;
            font-size: 1.1rem;
            border-radius: 4px;
            transition: color 0.2s;
        }}
        .toggle-vis:hover {{
            color: var(--text-primary);
        }}
        .test-result {{
            padding: 12px 16px;
            border-radius: var(--radius-sm);
            margin-top: 12px;
            display: none;
            font-size: 0.88rem;
            line-height: 1.5;
        }}
        .test-result.ok {{ display: block; background: var(--success-bg); color: var(--success); }}
        .test-result.fail {{ display: block; background: var(--danger-bg); color: var(--danger); }}
        .btn-row {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .status-chip {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.72rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}
        .status-chip.connected {{
            background: var(--success-bg);
            color: var(--success);
        }}
        .status-chip.not-connected {{
            background: var(--danger-bg);
            color: var(--danger);
        }}
        .status-chip.ready {{
            background: var(--info-bg);
            color: var(--info);
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
        }}
        .info-item {{
            background: var(--bg-secondary);
            border-radius: var(--radius-sm);
            padding: 14px 16px;
            border: 1px solid var(--border);
        }}
        .info-item .info-label {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .info-item .info-value {{
            font-weight: 600;
            font-size: 0.95rem;
        }}
        .quick-link {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--accent);
            text-decoration: none;
            font-size: 0.82rem;
            font-weight: 500;
            padding: 4px 0;
            transition: opacity 0.2s;
        }}
        .quick-link:hover {{ opacity: 0.8; text-decoration: underline; }}
        .perm-tag {{
            display: inline-block;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 0.75rem;
            font-family: 'Courier New', monospace;
            color: var(--accent);
            margin: 2px 2px;
        }}
        .save-bar {{
            position: sticky;
            bottom: 24px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            box-shadow: 0 -4px 24px rgba(0,0,0,0.5);
            z-index: 10;
            margin-top: 24px;
        }}
        .save-bar .save-status {{
            color: var(--success);
            font-weight: 500;
            font-size: 0.9rem;
            display: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        {_nav_html('settings')}

        <header>
            <div class="logo-area">
                <div class="logo">⚙️</div>
                <div>
                    <h1>Settings</h1>
                    <p class="subtitle">Configure AuroraEdge Security for your organisation</p>
                </div>
            </div>
            <div>
                {cf_badge}
            </div>
        </header>

        <div class="settings-grid">

            <!-- Organisation -->
            <div class="settings-card">
                <h3>🏢 Organisation</h3>
                <p class="card-desc">Identity details used in reports and the dashboard header.</p>
                <div class="form-row">
                    <label for="orgName">Organisation Name</label>
                    <input type="text" id="orgName" value="{org_name}" placeholder="e.g., Belfast Met IT Services">
                    <small>Displayed on exports, reports, and the dashboard</small>
                </div>
                <div class="form-row">
                    <label for="alertEmail">Contact Email (Optional)</label>
                    <input type="email" id="alertEmail" value="{alert_email}" placeholder="e.g., security@yourorg.com">
                    <small>Stored locally only for operator reference. This version does not send email automatically.</small>
                </div>
            </div>

            <!-- Monitoring -->
            <div class="settings-card">
                <h3>🔄 Monitoring Schedule</h3>
                <p class="card-desc">Automatic background rescans of managed domains with drift detection alerts.</p>
                <div class="form-row">
                    <label for="monitorInterval">Scan Interval</label>
                    <select id="monitorInterval">
                        <option value="6" {"selected" if interval == "6" else ""}>Every 6 hours</option>
                        <option value="12" {"selected" if interval == "12" else ""}>Every 12 hours</option>
                        <option value="24" {"selected" if interval == "24" else ""}>Every 24 hours (recommended)</option>
                        <option value="48" {"selected" if interval == "48" else ""}>Every 48 hours</option>
                        <option value="168" {"selected" if interval == "168" else ""}>Weekly</option>
                    </select>
                    <small>How often AuroraEdge rescans your domains and checks for grade changes</small>
                </div>
                <div class="form-row" style="margin-top:16px;">
                    <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                        <input type="checkbox" id="clearOnStart" {"checked" if clear_on_start else ""} style="width:18px;height:18px;">
                        Clear scan data on every launch
                    </label>
                    <small>When enabled, the dashboard starts empty each time the server restarts (demo mode). Disable this to keep scan history across restarts.</small>
                </div>
            </div>

            <!-- Cloudflare Integration -->
            <div class="settings-card full-width">
                <h3>☁️ Cloudflare Integration {cf_badge}</h3>
                <p class="card-desc">
                    Connect your Cloudflare account to enable one-click DNS auto-fix.
                    Enter your API token, Zone ID, and optionally Account ID, Global API Key, and account email below.
                    Your credentials are stored locally and never leave this server.
                </p>

                <!-- Token creation guide -->
                <details style="margin-bottom:20px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px 18px;">
                    <summary style="cursor:pointer;font-weight:600;font-size:0.88rem;color:var(--accent);">📖 How to create a Cloudflare API token</summary>
                    <div style="margin-top:12px;font-size:0.84rem;color:var(--text-secondary);line-height:1.7;">
                        <ol style="padding-left:18px;margin:8px 0;">
                            <li>Go to <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener" class="quick-link" style="display:inline;">dash.cloudflare.com/profile/api-tokens</a></li>
                            <li>Click <strong>Create Token</strong></li>
                            <li>Use <strong>Create Custom Token</strong> (not a template)</li>
                            <li>Add these permissions:
                                <div style="margin:8px 0 4px 0;">
                                    <span class="perm-tag" style="background:var(--success-bg);border-color:var(--success);color:var(--success);">Zone : DNS : Edit</span>
                                    <span style="font-size:0.75rem;color:var(--text-muted);margin:0 4px;">— Required for SPF, DMARC, DKIM, TLS-RPT, MTA-STS DNS</span>
                                </div>
                                <div style="margin:4px 0;">
                                    <span class="perm-tag" style="background:var(--success-bg);border-color:var(--success);color:var(--success);">Zone : Zone : Read</span>
                                    <span style="font-size:0.75rem;color:var(--text-muted);margin:0 4px;">— Required for zone verification</span>
                                </div>
                                <div style="margin:4px 0;">
                                    <span class="perm-tag" style="background:var(--warning-bg);border-color:var(--warning);color:var(--warning);">Account : Workers Scripts : Edit</span>
                                    <span style="font-size:0.75rem;color:var(--text-muted);margin:0 4px;">— Needed for MTA-STS HTTPS policy auto-hosting via Worker</span>
                                </div>
                            </li>
                            <li>Under <strong>Zone Resources</strong>, select your domain</li>
                            <li>Under <strong>Account Resources</strong>, select your account</li>
                            <li>Click <strong>Continue to summary</strong> → <strong>Create Token</strong></li>
                            <li>Copy the token and paste it below</li>
                        </ol>
                    </div>
                </details>

                <div class="settings-grid" style="margin-bottom:0;gap:16px;">
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfToken">API Token</label>
                        <div class="input-group">
                            <input type="password" id="cfToken" placeholder="{"Token saved — enter new value to change" if cf_token_set else "Paste your Cloudflare API token"}" autocomplete="off">
                            <button class="toggle-vis" onclick="toggleTokenVis()" title="Show/hide token" type="button">👁️</button>
                        </div>
                        {"<div class='current-value'>Current: <code style=\"color:var(--accent);\">" + cf_token_display + "</code></div>" if cf_token_display else ""}
                        <small>
                            <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener" class="quick-link">
                                🔗 Create token on Cloudflare
                            </a>
                        </small>
                    </div>
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfZone">Zone ID</label>
                        <div class="input-group">
                            <input type="text" id="cfZone" value="{zone_id}" placeholder="32-character hex string" autocomplete="off">
                        </div>
                        <small>Cloudflare dashboard → your domain → Overview → right sidebar → Zone ID</small>
                    </div>
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfAccount">Account ID <span style="color:var(--text-muted);font-weight:400;font-size:0.8rem;">(auto-detected)</span></label>
                        <div class="input-group">
                            <input type="text" id="cfAccount" value="{account_id}" placeholder="Auto-detected when you test the connection" autocomplete="off">
                        </div>
                        <small>Found on the same Overview page as Zone ID. Usually auto-detected.</small>
                    </div>
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfApiKey">Global API Key <span style="color:var(--text-muted);font-weight:400;font-size:0.8rem;">(optional fallback)</span></label>
                        <div class="input-group">
                            <input type="password" id="cfApiKey" placeholder="{"Key saved — enter new value to change" if cf_api_key_set else "Only needed if Worker routes fail with your token"}" autocomplete="off">
                        </div>
                        {"<div class='current-value'>Current: <code style=\"color:var(--accent);\">" + cf_api_key_display + "</code></div>" if cf_api_key_display else ""}
                        <small>Optional. Used only when your API token cannot create Cloudflare Worker routes.</small>
                    </div>
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfEmail">Cloudflare Account Email <span style="color:var(--text-muted);font-weight:400;font-size:0.8rem;">(optional fallback)</span></label>
                        <div class="input-group">
                            <input type="email" id="cfEmail" value="{cf_email}" placeholder="Email used with the optional Global API Key" autocomplete="off">
                        </div>
                        <small>Only needed if you also use the optional Global API Key.</small>
                    </div>
                </div>
                <div class="btn-row" style="margin-top:16px;">
                    <button class="btn btn-secondary" onclick="testCloudflare()" style="padding:10px 20px;">🧪 Test Connection</button>
                </div>
                <div class="test-result" id="cfTestResult"></div>

                <!-- Permissions checklist (populated by Test Connection) -->
                <div id="cfPermissions" style="display:none;margin-top:16px;padding:16px 20px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius-sm);">
                    <div style="font-weight:600;font-size:0.88rem;margin-bottom:10px;">Token Permissions</div>
                    <div id="cfPermList" style="font-size:0.85rem;line-height:2;"></div>
                    <div id="cfFeatureList" style="margin-top:10px;font-size:0.82rem;color:var(--text-secondary);"></div>
                </div>
            </div>

            <!-- Data Management -->
            <div class="settings-card">
                <h3>📦 Data &amp; Export</h3>
                <p class="card-desc">Download your scan data and settings for backup or academic review.</p>
                <div class="btn-row" style="flex-direction:column;gap:10px;">
                    <button class="btn btn-secondary" onclick="exportSettings()" style="width:100%;text-align:left;padding:12px 16px;">
                        📋 Export Settings as JSON
                    </button>
                    <a href="/download/latest?kind=csv" class="btn btn-secondary" style="width:100%;text-align:left;padding:12px 16px;text-decoration:none;display:block;">
                        📊 Download Latest Scan CSV
                    </a>
                    <a href="/download/latest?kind=md" class="btn btn-secondary" style="width:100%;text-align:left;padding:12px 16px;text-decoration:none;display:block;">
                        📄 Download Latest Scan Markdown
                    </a>
                    <hr style="border-color:rgba(255,255,255,0.08);margin:8px 0;">
                    <button class="btn btn-secondary" onclick="clearAllData()" style="width:100%;text-align:left;padding:12px 16px;color:#ef4444;">
                        🗑️ Clear All Scan Data
                    </button>
                </div>
                <div class="test-result" id="clearDataResult"></div>
            </div>

            <!-- System Info -->
            <div class="settings-card">
                <h3>ℹ️ System Information</h3>
                <p class="card-desc">AuroraEdge instance details and module status.</p>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Version</div>
                        <div class="info-value">3.1</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Database</div>
                        <div class="info-value" style="color:{'var(--success)' if HAS_DB else 'var(--danger)'};">{db_status}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Scanner</div>
                        <div class="info-value" style="color:{'var(--success)' if HAS_SCANNER else 'var(--danger)'};">{scanner_status}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">DNS Fix</div>
                        <div class="info-value" style="color:{'var(--success)' if HAS_DNS_FIX else 'var(--danger)'};">{dns_fix_status}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Domains</div>
                        <div class="info-value">{domain_count}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Total Scans</div>
                        <div class="info-value">{scan_count}</div>
                    </div>
                </div>
            </div>

        </div><!-- end settings-grid -->

        <!-- Sticky save bar -->
        <div class="save-bar">
            <div style="display:flex;align-items:center;gap:12px;">
                <button class="btn btn-primary" onclick="saveSettings()" style="padding:12px 28px;">💾 Save All Settings</button>
                <span class="save-status" id="saveStatus">✓ Settings saved</span>
            </div>
            <div style="color:var(--text-muted);font-size:0.8rem;">
                Changes take effect immediately
            </div>
        </div>

        {_footer_html()}
    </div>

    <script>
    function toggleTokenVis() {{
        const inp = document.getElementById('cfToken');
        const btn = inp.parentElement.querySelector('.toggle-vis');
        if (inp.type === 'password') {{
            inp.type = 'text';
            btn.textContent = '🔒';
            btn.title = 'Hide token';
        }} else {{
            inp.type = 'password';
            btn.textContent = '👁️';
            btn.title = 'Show token';
        }}
    }}

    async function saveSettings() {{
        const data = {{
            org_name: document.getElementById('orgName').value,
            cf_zone_id: document.getElementById('cfZone').value,
            cf_account_id: document.getElementById('cfAccount').value,
            cf_email: document.getElementById('cfEmail').value,
            monitor_interval: document.getElementById('monitorInterval').value,
            alert_email: document.getElementById('alertEmail').value,
            clear_on_start: document.getElementById('clearOnStart').checked ? 'true' : 'false',
        }};
        const tokenInput = document.getElementById('cfToken');
        const apiKeyInput = document.getElementById('cfApiKey');
        if (tokenInput.value) {{
            data.cf_api_token = tokenInput.value;
        }}
        if (apiKeyInput.value) {{
            data.cf_api_key = apiKeyInput.value;
        }}
        try {{
            const res = await fetch('/api/settings', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(data)
            }});
            if (!res.ok) throw new Error('Failed to save');
            const status = document.getElementById('saveStatus');
            status.style.display = 'inline';
            setTimeout(() => status.style.display = 'none', 3000);
            if (tokenInput.value) {{
                tokenInput.value = '';
                tokenInput.placeholder = 'Token saved — enter new value to change';
            }}
            if (apiKeyInput.value) {{
                apiKeyInput.value = '';
                apiKeyInput.placeholder = 'Key saved — enter new value to change';
            }}
        }} catch(e) {{
            alert('Error saving settings: ' + e.message);
        }}
    }}

    async function testCloudflare() {{
        // Save first if token/zone was entered
        const tokenInput = document.getElementById('cfToken');
        if (tokenInput.value || document.getElementById('cfZone').value) {{
            await saveSettings();
        }}
        const result = document.getElementById('cfTestResult');
        const permBox = document.getElementById('cfPermissions');
        const permList = document.getElementById('cfPermList');
        const featList = document.getElementById('cfFeatureList');
        result.className = 'test-result';
        result.style.display = 'block';
        result.innerHTML = '<span style="opacity:0.7;">Testing connection…</span>';
        permBox.style.display = 'none';
        try {{
            const res = await fetch('/api/settings/test-cloudflare');
            const data = await res.json();
            if (data.ok) {{
                let info = '✅ <strong>Connected</strong> — Zone: <code>' + data.zone_name + '</code>';
                result.className = 'test-result ok';
                result.innerHTML = info;

                // Auto-fill account ID if discovered
                if (data.account_id) {{
                    const acctInput = document.getElementById('cfAccount');
                    if (!acctInput.value) {{
                        acctInput.value = data.account_id;
                    }}
                }}

                // Show permissions checklist
                const p = data.permissions || {{}};
                const tick = '<span style="color:var(--success);font-weight:700;">✓</span>';
                const cross = '<span style="color:var(--danger);font-weight:700;">✗</span>';
                let html = '';
                html += '<div>' + (p.zone_read ? tick : cross) + ' <span class="perm-tag">Zone : Zone : Read</span> Zone verification</div>';
                html += '<div>' + (p.dns_edit ? tick : cross) + ' <span class="perm-tag">Zone : DNS : Edit</span> SPF, DMARC, DKIM, TLS-RPT, MTA-STS records</div>';
                html += '<div>' + (p.workers ? tick : cross) + ' <span class="perm-tag">Account : Workers Scripts : Edit</span> MTA-STS HTTPS auto-hosting';
                if (!p.workers) {{
                    html += ' <span style="color:var(--warning);font-size:0.78rem;margin-left:6px;">— update your token to enable this</span>';
                }}
                html += '</div>';
                permList.innerHTML = html;

                if (data.features && data.features.length) {{
                    featList.innerHTML = '🔧 <strong>Available auto-fix features:</strong> ' + data.features.join(', ');
                }} else {{
                    featList.innerHTML = '⚠️ No auto-fix features available. Check your token permissions.';
                }}
                permBox.style.display = 'block';
            }} else {{
                result.className = 'test-result fail';
                result.innerHTML = '❌ ' + data.message;
                permBox.style.display = 'none';
            }}
        }} catch(e) {{
            result.className = 'test-result fail';
            result.innerHTML = '❌ Connection failed: ' + e.message;
            permBox.style.display = 'none';
        }}
    }}

    async function exportSettings() {{
        try {{
            const res = await fetch('/api/settings');
            const data = await res.json();
            // Add export metadata
            data.exported_at = new Date().toISOString();
            data.version = '3.1';
            const blob = new Blob([JSON.stringify(data, null, 2)], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'auroraedge_settings_' + new Date().toISOString().slice(0,10) + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }} catch(e) {{
            alert('Export failed: ' + e.message);
        }}
    }}

    async function clearAllData() {{
        if (!confirm('This will permanently delete ALL scan results, managed domains, and alerts.\\n\\nSettings (Cloudflare credentials, preferences) will be preserved.\\n\\nThis cannot be undone. Continue?')) return;
        const result = document.getElementById('clearDataResult');
        try {{
            const res = await fetch('/api/data/clear', {{ method: 'POST' }});
            const data = await res.json();
            if (data.ok) {{
                result.className = 'test-result success';
                result.innerHTML = '\\u2705 ' + data.message;
            }} else {{
                result.className = 'test-result fail';
                result.innerHTML = '\\u274c ' + (data.detail || 'Clear failed');
            }}
        }} catch(e) {{
            result.className = 'test-result fail';
            result.innerHTML = '\\u274c Error: ' + e.message;
        }}
    }}

    // Auto-save on Enter in input fields
    document.querySelectorAll('.form-row input').forEach(inp => {{
        inp.addEventListener('keydown', e => {{
            if (e.key === 'Enter') {{ e.preventDefault(); saveSettings(); }}
        }});
    }});
    </script>
</body>
</html>
"""
    return HTMLResponse(html)