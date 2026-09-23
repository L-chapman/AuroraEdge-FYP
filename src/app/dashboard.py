"""FastAPI dashboard and API routes for NorthFlux Security."""

import os
import re
import sys
import csv
import json
import asyncio
import logging
import math
import concurrent.futures
import threading
import tempfile
import html as html_lib
import time as _time
import importlib.util
from contextlib import asynccontextmanager
from functools import wraps
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone
from urllib.parse import parse_qs

from app.branding import DEMO_DOMAIN, PRODUCT_DESCRIPTION, PRODUCT_NAME, PRODUCT_VERSION
from app.auth_state import AuthenticationState
from app.request_security import RequestSizeLimitMiddleware, constant_time_equal, json_object

from fastapi import FastAPI, Depends, HTTPException, Request, Query, Response
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.api_models import (
    AlertResponse,
    AuthState,
    BootstrapResponse,
    CapabilityMetadata,
    DashboardResponse,
    DashboardSettings,
    DashboardStats,
    LoginRequest,
    ManagedDomainResponse,
    OperatorMetadata,
    ProductMetadata,
    RuntimeMetadata,
    ScoreStatistics,
)
from app.runtime_paths import (
    INDEXED_REPORTS_DIR,
    LOGS_DIR,
    PROJECT_ROOT,
    REPORTS_DIR,
    STATE_DIR,
)

# Keep uvicorn INFO logs on stdout so PowerShell does not treat them as errors.
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
    if not isinstance(raw, str):
        return ("", "Domain must be text")
    domain = raw.strip().lower()
    # Strip common protocol prefixes users might paste in
    for prefix in ("https://", "http://", "ftp://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]          # Remove trailing path
    domain = domain.split("?")[0]          # Remove query string
    if not domain:
        return ("", "Domain is required")
    if len(domain) > 253 or not _DOMAIN_RE.fullmatch(domain):
        return ("", "Invalid domain format")
    # Reject bare IP addresses &#8211; we need a real domain for DNS checks
    if all(part.isdigit() for part in domain.split(".")):
        return ("", "IP addresses are not valid &#8211; enter a domain name")
    return (domain, None)


# Database import with fallback
try:
    from app.database import get_database

    HAS_DB = True
except ImportError:
    HAS_DB = False

# Scanner and rules imports for live testing
try:
    from app.scanner import scan_domain, SCAN_TIMEOUT
    from app.rules import evaluate, generate_remediation

    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False
    scan_domain = None
    evaluate = None
    generate_remediation = None

# DNS auto-fix imports
try:
    from app.dns_fix import (
        COMPARISON_DISCLAIMER,
        CloudflareDNS,
        TOOL_COMPARISON,
        get_cloudflare_client,
    )

    HAS_DNS_FIX = True
except ImportError:
    HAS_DNS_FIX = False
    CloudflareDNS = None
    get_cloudflare_client = None
    TOOL_COMPARISON = {}
    COMPARISON_DISCLAIMER = "Comparison data is unavailable."

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


logger = logging.getLogger("northflux")


def _is_enabled(value: object, default: bool = False) -> bool:
    """Parse an explicit boolean setting without truthy-string surprises."""
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _is_production() -> bool:
    return os.environ.get("NORTHFLUX_ENV", "development").strip().lower() == "production"


def _escape(value: object) -> str:
    """Escape untrusted text before placing it in server-rendered HTML."""
    return html_lib.escape(str(value if value is not None else ""), quote=True)


def _escape_record(record: Dict) -> Dict:
    return {
        key: _escape(value) if isinstance(value, str) else value
        for key, value in record.items()
    }


_SESSION_COOKIE = "northflux_session"
_CSRF_COOKIE = "northflux_csrf"
_SESSION_TTL_SECONDS = 60 * 60 * 12


def _create_session(configured_token: str) -> tuple[str, str]:
    """Keep the HTTP adapter bound to the application's single state owner."""
    return app.state.authentication.create_session(configured_token)


def _get_session(session_id: str, configured_token: str) -> Optional[Dict]:
    return app.state.authentication.get_session(session_id, configured_token)


def _expected_origin(request: Request) -> str:
    configured = _env("NORTHFLUX_PUBLIC_ORIGIN", "").strip().rstrip("/")
    if configured:
        return configured
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",", 1)[0].strip()
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc)).split(",", 1)[0].strip()
    return f"{scheme}://{host}"


def _require_session_csrf(request: Request, session: Dict) -> None:
    if request.method.upper() in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return
    origin = request.headers.get("origin", "").rstrip("/")
    expected_origin = _expected_origin(request)
    if not origin or not constant_time_equal(origin, expected_origin):
        raise HTTPException(status_code=403, detail="Invalid request origin")
    header_token = request.headers.get("x-csrf-token", "")
    cookie_token = request.cookies.get(_CSRF_COOKIE, "")
    expected_token = session.get("csrf_token", "")
    if not (
        header_token
        and cookie_token
        and constant_time_equal(header_token, expected_token)
        and constant_time_equal(cookie_token, expected_token)
    ):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def _load_cf_runtime_settings(db) -> List[str]:
    """Load Cloudflare runtime configuration without persisting env secrets."""
    if not HAS_DNS_FIX:
        return []
    import app.dns_fix as dns_mod

    mapping = {
        "cf_api_token": ("CF_API_TOKEN", "CF_API_TOKEN"),
        "cf_zone_id": ("CF_ZONE_ID", "CF_ZONE_ID"),
        "cf_account_id": ("CF_ACCOUNT_ID", "CF_ACCOUNT_ID"),
        "cf_api_key": ("CF_API_KEY", "CF_API_KEY"),
        "cf_email": ("CF_EMAIL", "CF_EMAIL"),
    }
    secret_keys = {"cf_api_token", "cf_api_key", "cf_email"}
    loaded = []
    for db_key, (env_key, module_name) in mapping.items():
        env_value = (os.environ.get(env_key, "") or "").strip()
        stored_value = (db.get_setting(db_key, "") or "").strip()
        if _is_production() and db_key in secret_keys and stored_value and env_value:
            db.delete_setting(db_key)
            stored_value = ""
            logger.info("Removed migrated %s secret from local settings", db_key)
        value = env_value
        if not value and not (_is_production() and db_key in secret_keys):
            value = stored_value
        setattr(dns_mod, module_name, value)
        if value:
            loaded.append(f"{db_key} ({'environment' if env_value else 'settings'})")
    return loaded

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Modern lifespan handler &#8212; runs startup logic, then yields control."""
    configured_token = os.environ.get("DASH_TOKEN", "").strip()
    if _is_production() and not configured_token:
        raise RuntimeError("DASH_TOKEN is required when NORTHFLUX_ENV=production")
    if _is_production() and len(configured_token) < 32:
        raise RuntimeError("DASH_TOKEN must be at least 32 characters in production")
    if _is_production() and not _react_frontend_available():
        raise RuntimeError(
            "The compiled React frontend is required in production; "
            "run `npm ci && npm run build` in frontend/ or use the production image"
        )
    for runtime_dir in (STATE, REPORTS, REPORTS_ROOT / "archive", LOGS_ROOT):
        runtime_dir.mkdir(parents=True, exist_ok=True)
    # Expand the default thread-pool so multiple DNS scans can run concurrently
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=8))
    logger.info("Thread pool expanded to 8 workers for concurrent scanning")

    if HAS_DB:
        try:
            db = get_database()
            loaded_settings = _load_cf_runtime_settings(db)
            if loaded_settings:
                logger.info("Loaded Cloudflare runtime settings: %s", ", ".join(loaded_settings))
            clear = _is_enabled(db.get_setting("clear_on_start", "false"))
            if clear:
                db.clear_scan_data()
                logger.info("Database cleared for fresh session (clear_on_start=true)")
            else:
                logger.info("Keeping previous scan data (clear_on_start=false)")
            if (
                not _is_production()
                and _is_enabled(os.environ.get("NORTHFLUX_DEMO_MODE"))
            ):
                db.set_setting("demo_domain", DEMO_DOMAIN)
                db.add_managed_domain(DEMO_DOMAIN, notes="Auto-Fix demo domain")
                logger.info("Demo mode enabled; seeded managed domain: %s", DEMO_DOMAIN)
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
    title=PRODUCT_NAME,
    description=PRODUCT_DESCRIPTION,
    version=PRODUCT_VERSION,
    lifespan=lifespan,
    docs_url=None if _is_production() else "/docs",
    redoc_url=None if _is_production() else "/redoc",
    openapi_url=None if _is_production() else "/openapi.json",
)
# One owner per application, including tests. The state module has no singleton
# and adapters do not keep aliases to its dictionaries or locks.
app.state.authentication = AuthenticationState(session_ttl_seconds=_SESSION_TTL_SECONDS)


# ---------------------------------------------------------------------------
# Security headers middleware  (OWASP recommended)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers into every HTTP response."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent caching of API and dynamic HTML responses
        if (
            "text/html" in response.headers.get("content-type", "")
            or "application/json" in response.headers.get("content-type", "")
            or request.url.path.startswith(("/download/", "/api/report/"))
        ):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if _react_frontend_enabled():
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                "object-src 'none'; base-uri 'self'; form-action 'self'; "
                "frame-ancestors 'none'"
            )
        else:
            # Development fallback for the deprecated single-file interface.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
            )
        return response


app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter for scan endpoints
# ---------------------------------------------------------------------------
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
            detail=f"Rate limit exceeded &#8212; max {_SCAN_RATE_MAX} scans per {_SCAN_RATE_WINDOW}s",
        )
    hits.append(now)
    _scan_rate[ip] = hits


def _login_rate_check(request: Request) -> str:
    """Return the client key or raise when failed logins exceed the limit."""
    client_key = request.client.host if request.client else "unknown"
    if not app.state.authentication.login_allowed(client_key):
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts")
    return client_key


def _record_login_failure(client_key: str) -> None:
    app.state.authentication.record_login_failure(client_key)


def _clear_login_failures(client_key: str) -> None:
    app.state.authentication.clear_login_failures(client_key)


# ---------------------------------------------------------------------------
# Custom 404 page &#8212; branded HTML instead of raw JSON
@app.exception_handler(StarletteHTTPException)
async def _custom_http_exception(request: Request, exc: StarletteHTTPException):
    """Return a branded HTML page for 404 errors, JSON for API errors."""
    if (
        exc.status_code == 401
        and not request.url.path.startswith("/api/")
        and request.url.path != "/login"
    ):
        return RedirectResponse("/login", status_code=303)
    if exc.status_code == 404 and not request.url.path.startswith("/api/"):
        return HTMLResponse(
            status_code=404,
            content=f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>404 \u2014 NorthFlux Security</title>
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
  <p>The page <code>{_escape(request.url.path)}</code> was not found.</p>
  <p><a href="/">\u2190 Back to Dashboard</a></p>
</div></body></html>""",
        )
    # For API routes and non-404 errors, return standard JSON
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


# Project root and environment-overridable runtime directories
ROOT = PROJECT_ROOT
REPORTS_ROOT = REPORTS_DIR
REPORTS = INDEXED_REPORTS_DIR
STATE = STATE_DIR
LOGS_ROOT = LOGS_DIR
FRONTEND_DIST = Path(
    os.environ.get("NORTHFLUX_FRONTEND_DIST", str(ROOT / "frontend" / "dist"))
).resolve()


def _react_frontend_enabled() -> bool:
    """Use the compiled SPA in production or when explicitly requested."""
    configured = os.environ.get("NORTHFLUX_SERVE_REACT")
    return _is_enabled(configured) if configured is not None else _is_production()


def _react_frontend_available() -> bool:
    return _react_frontend_enabled() and (FRONTEND_DIST / "index.html").is_file()


def _spa_index_response():
    if not _react_frontend_enabled():
        return None
    if not (FRONTEND_DIST / "index.html").is_file():
        raise HTTPException(
            status_code=503,
            detail="The compiled React frontend is unavailable",
        )
    return FileResponse(
        FRONTEND_DIST / "index.html",
        media_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


def _env(name: str, default: str = "") -> str:
    """Get environment variable with default."""
    return os.environ.get(name, default)


def require_token(req: Request):
    """
    Token-based authentication dependency.

    Accepts an authenticated session cookie or an Authorization bearer token.
    Query-string tokens remain available in development for legacy local links.

    If DASH_TOKEN is not set, allows open access (development mode).
    """
    want = _env("DASH_TOKEN", "").strip()
    if not want:
        if _is_production():
            raise HTTPException(status_code=503, detail="Authentication is not configured")
        # Even an intentionally open local instance must reject browser writes
        # from unrelated sites (including simple text/plain JSON requests).
        origin = req.headers.get("origin")
        if req.method.upper() not in {"GET", "HEAD", "OPTIONS", "TRACE"} and origin is not None:
            if not constant_time_equal(origin.rstrip("/"), _expected_origin(req)):
                raise HTTPException(status_code=403, detail="Invalid request origin")
        return  # No token set -> open access in local development

    # Explicit bearer credentials are not ambient browser authority, so they do
    # not require a CSRF token.
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and constant_time_equal(auth.split(" ", 1)[1], want):
        return

    # Query-string tokens are retained only for legacy local development links.
    qtok = req.query_params.get("token")
    if not _is_production() and qtok and constant_time_equal(qtok, want):
        return

    session_id = req.cookies.get(_SESSION_COOKIE, "")
    session = _get_session(session_id, want)
    if session:
        _require_session_csrf(req, session)
        req.state.session_id = session_id
        return

    raise HTTPException(status_code=401, detail="Unauthorised - valid token required")


@app.get("/login", response_class=HTMLResponse)
def login_page():
    """Render the operator login page when token authentication is enabled."""
    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response
    if not _env("DASH_TOKEN", "").strip():
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(
        """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in - NorthFlux Security</title>
<style>body{font-family:Segoe UI,system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;
display:grid;place-items:center;min-height:100vh;margin:0}.card{width:min(380px,calc(100% - 40px));
background:#111827;border:1px solid #263248;border-radius:16px;padding:28px;box-shadow:0 20px 50px #0008}
h1{margin:0 0 8px;font-size:1.5rem}p{color:#94a3b8}label{display:block;margin:20px 0 8px}
input{box-sizing:border-box;width:100%;padding:12px;border-radius:8px;border:1px solid #334155;
background:#0f172a;color:#fff}button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:8px;
background:#38bdf8;color:#082f49;font-weight:700;cursor:pointer}.error{color:#fca5a5}</style></head>
<body><main class="card"><h1>NorthFlux Security</h1><p>Sign in to manage this instance.</p>
<form method="post" action="/login"><label for="token">Access token</label>
<input id="token" name="token" type="password" required autocomplete="current-password">
<button type="submit">Sign in</button></form></main></body></html>"""
    )


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page():
    """Publish the essential operator and visitor privacy boundaries."""
    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response
    return HTMLResponse(
        """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy - NorthFlux Security</title>
<style>body{font-family:Segoe UI,system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;
margin:0;padding:40px 20px}.card{box-sizing:border-box;width:min(760px,100%);margin:auto;
background:#111827;border:1px solid #263248;border-radius:16px;padding:32px;box-shadow:0 20px 50px #0008}
h1,h2{color:#f8fafc}h1{margin-top:0}h2{font-size:1.05rem;margin-top:28px}p,li{color:#b8c4d6;
line-height:1.65}a{color:#38bdf8}code{color:#c4b5fd}</style></head><body><main class="card">
<h1>NorthFlux Security privacy summary</h1>
<p>NorthFlux is self-hosted software. The operator of this instance controls its deployment, access,
retention, backups, and any optional integrations.</p>
<h2>Data processed</h2><p>NorthFlux queries public DNS records and limited public HTTPS and SMTP posture signals.
It does not read mailboxes or message content. Public records can contain contact addresses, such as DMARC or
TLS reporting destinations.</p>
<h2>Local storage</h2><p>Scan history, managed-domain metadata, alerts, settings, reports, and logs are stored on the
operator's system. NorthFlux does not provide an application-managed vendor cloud or advertising analytics.</p>
<h2>Credentials and changes</h2><p>Production Cloudflare credentials must be supplied through the runtime environment.
NorthFlux does not return them through its settings API. DNS changes are opt-in and must be limited to zones the
operator owns or is explicitly authorised to manage.</p>
<h2>Your operator</h2><p>Contact the operator of this instance about access, retention, or deletion. Operators should
document their own legal basis, retention period, processor arrangements, and incident process before handling
personal data or offering the service to others.</p>
<p><a href="/">Back to NorthFlux Security</a></p></main></body></html>"""
    )


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    """Exchange the configured access token for an HttpOnly session cookie."""
    want = _env("DASH_TOKEN", "").strip()
    client_key = _login_rate_check(request)
    raw_body = bytearray()
    async for chunk in request.stream():
        raw_body.extend(chunk)
        if len(raw_body) > 4096:
            _record_login_failure(client_key)
            raise HTTPException(status_code=413, detail="Sign-in request is too large")
    try:
        body = parse_qs(raw_body.decode("utf-8", errors="strict"), max_num_fields=10)
    except (ValueError, UnicodeError):
        _record_login_failure(client_key)
        raise HTTPException(status_code=400, detail="Invalid sign-in form")
    supplied = body.get("token", [""])[0]
    if not want or not constant_time_equal(supplied, want):
        _record_login_failure(client_key)
        raise HTTPException(status_code=401, detail="Invalid access token")
    _clear_login_failures(client_key)
    session_id, csrf_token = _create_session(want)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        _SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=_is_production(),
        samesite="strict",
        max_age=_SESSION_TTL_SECONDS,
    )
    response.set_cookie(
        _CSRF_COOKIE,
        csrf_token,
        httponly=False,
        secure=_is_production(),
        samesite="strict",
        max_age=_SESSION_TTL_SECONDS,
    )
    return response


@app.post("/logout", dependencies=[Depends(require_token)])
def logout(request: Request):
    session_id = request.cookies.get(_SESSION_COOKIE, "")
    if session_id:
        app.state.authentication.revoke_session(session_id)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(_SESSION_COOKIE)
    response.delete_cookie(_CSRF_COOKIE)
    return response


def _auth_state(request: Request) -> AuthState:
    """Describe the request's existing authority without creating a session."""

    configured_token = _env("DASH_TOKEN", "").strip()
    if not configured_token:
        return AuthState(
            required=False,
            authenticated=not _is_production(),
            expires_at=None,
        )

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and constant_time_equal(
        auth.split(" ", 1)[1], configured_token
    ):
        return AuthState(required=True, authenticated=True, expires_at=None)

    query_token = request.query_params.get("token")
    if (
        not _is_production()
        and query_token
        and constant_time_equal(query_token, configured_token)
    ):
        return AuthState(required=True, authenticated=True, expires_at=None)

    session = _get_session(
        request.cookies.get(_SESSION_COOKIE, ""),
        configured_token,
    )
    if not session:
        return AuthState(required=True, authenticated=False, expires_at=None)

    expires_at = datetime.fromtimestamp(session["expires_at"], tz=timezone.utc)
    return AuthState(required=True, authenticated=True, expires_at=expires_at)


def _parse_api_timestamp(value: object) -> Optional[datetime]:
    if isinstance(value, datetime):
        parsed = value
    elif value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _normalise_score(value: object, *, optional: bool = False) -> Optional[int]:
    if value is None and optional:
        return None
    try:
        return max(0, min(100, int(value or 0)))
    except (TypeError, ValueError, OverflowError):
        return None if optional else 0


def _normalise_grade(value: object, *, optional: bool = False):
    grade = str(value or "").upper()
    if grade in {"A+", "A", "B", "C", "D", "F"}:
        return grade
    return None if optional else "F"


def _dashboard_settings(db) -> DashboardSettings:
    interval_text = str(db.get_setting("monitor_interval", "24") or "24").strip()
    try:
        interval = int(interval_text)
    except ValueError:
        interval = 24
    if interval not in {6, 12, 24, 48, 168}:
        interval = 24
    return DashboardSettings(
        monitor_interval_hours=interval,
        monitoring_enabled=_is_enabled(db.get_setting("monitoring_enabled", "false")),
        automatic_remediation=_is_enabled(
            db.get_setting("automatic_remediation", "false")
        ),
    )


@app.get("/api/v1/auth/session", response_model=AuthState)
def api_v1_auth_session(request: Request):
    """Return browser authentication state without exposing credential material."""

    return _auth_state(request)


@app.post("/api/v1/auth/login", response_model=AuthState)
def api_v1_auth_login(payload: LoginRequest, request: Request, response: Response):
    """Exchange a JSON access token for the existing browser session cookies."""

    configured_token = _env("DASH_TOKEN", "").strip()
    if not configured_token:
        raise HTTPException(status_code=409, detail="Authentication is not enabled")

    client_key = _login_rate_check(request)
    if not constant_time_equal(payload.token, configured_token):
        _record_login_failure(client_key)
        raise HTTPException(status_code=401, detail="Invalid access token")

    _clear_login_failures(client_key)
    session_id, csrf_token = _create_session(configured_token)
    response.set_cookie(
        _SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=_is_production(),
        samesite="strict",
        max_age=_SESSION_TTL_SECONDS,
    )
    response.set_cookie(
        _CSRF_COOKIE,
        csrf_token,
        httponly=False,
        secure=_is_production(),
        samesite="strict",
        max_age=_SESSION_TTL_SECONDS,
    )
    session = _get_session(session_id, configured_token)
    expires_at = datetime.fromtimestamp(session["expires_at"], tz=timezone.utc)
    return AuthState(required=True, authenticated=True, expires_at=expires_at)


@app.post(
    "/api/v1/auth/logout",
    response_model=AuthState,
    dependencies=[Depends(require_token)],
)
def api_v1_auth_logout(request: Request, response: Response):
    """Revoke the current browser session and clear its authentication cookies."""

    session_id = request.cookies.get(_SESSION_COOKIE, "")
    if session_id:
        app.state.authentication.revoke_session(session_id)
    response.delete_cookie(_SESSION_COOKIE)
    response.delete_cookie(_CSRF_COOKIE)
    return AuthState(
        required=bool(_env("DASH_TOKEN", "").strip()),
        authenticated=False,
        expires_at=None,
    )


@app.get(
    "/api/v1/bootstrap",
    response_model=BootstrapResponse,
    dependencies=[Depends(require_token)],
)
def api_v1_bootstrap(request: Request):
    """Return the non-secret product and runtime metadata needed by the SPA."""

    settings = DashboardSettings(
        monitor_interval_hours=24,
        monitoring_enabled=False,
        automatic_remediation=False,
    )
    org_name = "Your Organisation"
    if HAS_DB:
        try:
            db = get_database()
            settings = _dashboard_settings(db)
            org_name = str(db.get_setting("org_name", org_name) or org_name)
        except Exception:
            logger.exception("Could not load API bootstrap settings")

    production = _is_production()
    return BootstrapResponse(
        product=ProductMetadata(
            name=PRODUCT_NAME,
            version=PRODUCT_VERSION,
            description=PRODUCT_DESCRIPTION,
        ),
        auth=_auth_state(request),
        runtime=RuntimeMetadata(
            production=production,
            demo_mode=(
                not production
                and _is_enabled(os.environ.get("NORTHFLUX_DEMO_MODE"))
            ),
        ),
        capabilities=CapabilityMetadata(
            scanner=HAS_SCANNER,
            database=HAS_DB,
            dns_fix=HAS_DNS_FIX,
            pdf=importlib.util.find_spec("reportlab") is not None,
            monitoring_enabled=settings.monitoring_enabled,
            automatic_remediation=settings.automatic_remediation,
        ),
        operator=OperatorMetadata(org_name=org_name),
    )


@app.get(
    "/api/v1/dashboard",
    response_model=DashboardResponse,
    dependencies=[Depends(require_token)],
)
def api_v1_dashboard():
    """Return a typed, normalised dashboard snapshot for the React client."""

    if not HAS_DB:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        db = get_database()
        with db.snapshot():
            raw_domains = db.get_managed_domains()
            raw_alerts = db.get_alerts(unacknowledged_only=True, limit=5)
            alert_count = db.get_alert_count()
            raw_stats = db.get_statistics()
            settings = _dashboard_settings(db)
    except Exception:
        logger.exception("Could not build API dashboard snapshot")
        raise HTTPException(status_code=500, detail="Failed to load dashboard")

    domains = []
    for record in raw_domains:
        domain, error = _sanitize_domain(record.get("domain"))
        if error:
            logger.warning("Skipping invalid managed domain in API response: %s", error)
            continue
        domains.append(
            ManagedDomainResponse(
                id=int(record.get("id") or 0),
                domain=domain,
                added_at=_parse_api_timestamp(record.get("added_at")),
                is_active=bool(record.get("is_active")),
                last_scan_at=_parse_api_timestamp(record.get("last_scan_at")),
                last_grade=_normalise_grade(record.get("last_grade"), optional=True),
                last_score=_normalise_score(record.get("last_score"), optional=True),
                last_scan_incomplete=bool(record.get("last_scan_incomplete")),
                previous_grade=_normalise_grade(
                    record.get("previous_grade"), optional=True
                ),
                previous_score=_normalise_score(
                    record.get("previous_score"), optional=True
                ),
                notes=str(record.get("notes") or ""),
            )
        )

    alerts = []
    for record in raw_alerts:
        domain, error = _sanitize_domain(record.get("domain"))
        if error:
            logger.warning("Skipping invalid alert domain in API response: %s", error)
            continue
        alerts.append(
            AlertResponse(
                id=int(record.get("id") or 0),
                domain=domain,
                alert_type=str(record.get("alert_type") or ""),
                severity=str(record.get("severity") or "INFO").upper(),
                message=str(record.get("message") or ""),
                details=str(record.get("details") or ""),
                created_at=_parse_api_timestamp(record.get("created_at")),
                acknowledged=bool(record.get("acknowledged")),
                acknowledged_at=_parse_api_timestamp(record.get("acknowledged_at")),
            )
        )

    scores = [domain.last_score for domain in domains if domain.last_score is not None]
    grade_distribution = {
        grade: sum(1 for domain in domains if domain.last_grade == grade)
        for grade in ("A+", "A", "B", "C", "D", "F")
    }
    passing_domains = sum(1 for score in scores if score >= 70)
    raw_score_stats = raw_stats.get("score_stats") or {}
    severity_distribution = {
        str(severity or "UNKNOWN"): int(count or 0)
        for severity, count in (raw_stats.get("severity_distribution") or {}).items()
    }
    return DashboardResponse(
        stats=DashboardStats(
            total_scans=max(0, int(raw_stats.get("total_scans") or 0)),
            unique_domains=max(0, int(raw_stats.get("unique_domains") or 0)),
            total_results=max(0, int(raw_stats.get("total_results") or 0)),
            score_stats=ScoreStatistics(
                avg_score=(
                    float(raw_score_stats["avg_score"])
                    if raw_score_stats.get("avg_score") is not None
                    else None
                ),
                min_score=(
                    _normalise_score(raw_score_stats.get("min_score"), optional=True)
                ),
                max_score=(
                    _normalise_score(raw_score_stats.get("max_score"), optional=True)
                ),
            ),
            severity_distribution=severity_distribution,
            total_domains=len(domains),
            average_score=round(sum(scores) / len(scores)) if scores else 0,
            passing_domains=passing_domains,
            failing_domains=len(scores) - passing_domains,
            grade_distribution=grade_distribution,
            alert_count=int(alert_count),
        ),
        domains=domains,
        alerts=alerts,
        settings=settings,
    )


def _contained_report(path: Path, root: Path) -> bool:
    """Exclude directories and report links that escape their storage root."""
    try:
        return path.is_file() and path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError):
        return False


def list_csvs() -> List[Path]:
    """List all CSV report files, newest first."""
    files: List[Path] = []
    if REPORTS.exists():
        files.extend(p for p in REPORTS.glob("*_results_*.csv") if _contained_report(p, REPORTS))
    if REPORTS_ROOT.exists():
        files.extend(p for p in REPORTS_ROOT.glob("*_results_*.csv") if _contained_report(p, REPORTS_ROOT))
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
            # Skip comment/header rows in exported or hand-maintained datasets.
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
    return newest, (md if _contained_report(md, newest.parent) else None)


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
        if _is_enabled(r.get("scan_incomplete")):
            continue
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
        if _is_enabled(r.get("scan_incomplete")):
            continue
        try:
            score = float(r.get("score"))
            if math.isfinite(score) and 0 <= score <= 100:
                scores.append(score)
        except (ValueError, TypeError, OverflowError):
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
    """Process liveness endpoint."""
    return {
        "ok": True,
        "service": PRODUCT_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": PRODUCT_VERSION,
    }


def _directory_writable(path: Path) -> bool:
    """Verify a runtime directory with a real, automatically removed probe."""
    try:
        with tempfile.NamedTemporaryFile(
            dir=path,
            prefix=".northflux-ready-",
            delete=True,
        ):
            return True
    except (OSError, ValueError):
        return False


@app.get("/ready")
def readiness():
    """Check database availability and writable runtime directories."""
    checks = {
        "database": False,
        "state_writable": _directory_writable(STATE),
        "reports_writable": _directory_writable(REPORTS_ROOT),
        "logs_writable": _directory_writable(LOGS_ROOT),
    }
    if HAS_DB:
        try:
            db = get_database()
            checks["database"] = db.ping()
        except Exception:
            logger.exception("Readiness database check failed")
    ready = all(checks.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"ok": ready, "checks": checks, "version": PRODUCT_VERSION},
    )


@app.get("/api/stream", dependencies=[Depends(require_token)])
async def stream_updates(request: Request):
    """
    Server-Sent Events endpoint for real-time updates.
    Clients can subscribe to this for live dashboard updates.
    """

    async def event_generator():
        last_check = 0.0
        while True:
            # An open connection is not permanent authority. Stop disclosing
            # reports after sign-out, expiry or operator token rotation.
            try:
                require_token(request)
            except HTTPException:
                yield f"data: {json.dumps({'type': 'session_expired'})}\n\n"
                return
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


def _saved_scan_evidence(row: Dict) -> Dict:
    """Keep extensible observations without overriding authoritative columns."""
    try:
        raw = json.loads(row.get("raw_json") or "{}")
        if isinstance(raw, dict):
            return {**raw, **row}
    except (ValueError, TypeError, RecursionError):
        pass
    return row


@app.get("/api/domain/{domain}", dependencies=[Depends(require_token)])
def api_domain(domain: str):
    """Get latest result for a specific domain &#8212; checks DB first, falls back to CSV."""
    clean, error = _sanitize_domain(domain)
    if error:
        raise HTTPException(status_code=400, detail=error)

    # Try database first
    if HAS_DB:
        try:
            db = get_database()
            history = db.get_domain_history(clean, limit=1)
            if history:
                return {"domain": clean, "result": _saved_scan_evidence(history[0]), "source": "database"}
        except Exception:
            logger.exception("Failed to retrieve the latest result for %s", clean)
            raise HTTPException(status_code=500, detail="Failed to retrieve domain data")
        raise HTTPException(
            status_code=404,
            detail=f"No scan data found for {clean}. Try scanning it first.",
        )

    # Legacy fallback for installations running without database support.
    csv_file, _ = _latest_pair()
    if csv_file:
        rows = load_csv(csv_file)
        for row in rows:
            if row.get("domain", "").lower() == clean:
                return {"domain": clean, "result": row, "source": "csv"}

    raise HTTPException(
        status_code=404, detail=f"No scan data found for {clean}. Try scanning it first."
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
                rows.append(_saved_scan_evidence(row))
        except Exception:
            logger.exception("Failed to search saved results")
            raise HTTPException(status_code=500, detail="Failed to search saved results")

    else:
        csv_file, _ = _latest_pair()
        if not csv_file:
            return {"results": [], "count": 0, "total": 0}
        rows = load_csv(csv_file)

    results = []

    for row in rows:
        # Apply filters
        if q and q.lower() not in row.get("domain", "").lower():
            continue
        if severity and str(row.get("severity") or "").upper() != severity.upper():
            continue
        if grade and str(row.get("grade") or "").upper() != grade.upper():
            continue

        try:
            score = float(row.get("score"))
            if _is_enabled(row.get("scan_incomplete")) or not math.isfinite(score) or not 0 <= score <= 100:
                score = None
        except (ValueError, TypeError, OverflowError):
            score = None

        if min_score is not None and (score is None or score < min_score):
            continue
        if max_score is not None and (score is None or score > max_score):
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
    """Return the labelled legacy feature snapshot."""
    if not HAS_DNS_FIX or not TOOL_COMPARISON:
        return {"tools": {}, "error": "Tool comparison data not available"}
    return {
        "status": "legacy_snapshot",
        "disclaimer": COMPARISON_DISCLAIMER,
        "tools": TOOL_COMPARISON,
    }


@app.get("/api/history/{domain}", dependencies=[Depends(require_token)])
def api_history(domain: str, limit: int = Query(20, ge=1, le=100)):
    """Get historical scan results for a domain."""
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")

    clean, err = _sanitize_domain(domain)
    if err:
        raise HTTPException(status_code=404, detail="Domain not found")

    try:
        db = get_database()
        history = [_saved_scan_evidence(row) for row in db.get_domain_history(clean, limit)]
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


_GENERATED_REPORT_NAME = re.compile(
    r"^(?:northflux|auroraedge|stage\d+)_results_\d{8}_\d{6}\.(?:csv|md)$",
    re.IGNORECASE,
)
_OWNED_REPORT_DIRECTORIES = ("indexed", "archive")


def _validated_reports_root(configured_root: Path) -> Path:
    """Resolve a reports root while rejecting paths that own other app data."""
    if configured_root.is_symlink():
        raise RuntimeError("The reports directory cannot be a symbolic link")

    reports_root = configured_root.resolve()
    filesystem_root = Path(reports_root.anchor).resolve()
    protected_paths = {
        filesystem_root,
        Path.home().resolve(),
        PROJECT_ROOT.resolve(),
        STATE.resolve(),
        LOGS_ROOT.resolve(),
        FRONTEND_DIST.resolve(),
    }
    if any(
        reports_root == protected or protected.is_relative_to(reports_root)
        for protected in protected_paths
    ):
        raise RuntimeError("The configured reports directory is unsafe")
    if reports_root.exists() and not reports_root.is_dir():
        raise RuntimeError("The configured reports path is not a directory")
    return reports_root


def _clear_generated_reports() -> int:
    """Delete only recognised generated reports from app-owned locations.

    NorthFlux currently writes timestamped CSV/Markdown pairs. The previous
    AuroraEdge and numbered project-stage prefixes are retained so upgrades
    can clear known legacy reports.
    Unrelated files and nested directories are never traversed or removed.
    """
    reports_root = _validated_reports_root(REPORTS_ROOT)
    if not reports_root.exists():
        return 0

    owned_directories = [
        reports_root,
        *(reports_root / name for name in _OWNED_REPORT_DIRECTORIES),
    ]
    for directory in owned_directories:
        if directory.is_symlink():
            raise RuntimeError("An owned reports directory cannot be a symbolic link")
        if directory.exists() and not directory.is_dir():
            raise RuntimeError("An owned reports path is not a directory")

    generated_reports = [
        path
        for directory in owned_directories
        if directory.exists()
        for path in directory.iterdir()
        if _GENERATED_REPORT_NAME.fullmatch(path.name)
        and (path.is_file() or path.is_symlink())
    ]
    for report in generated_reports:
        report.unlink()

    (reports_root / "indexed").mkdir(parents=True, exist_ok=True)
    (reports_root / "archive").mkdir(parents=True, exist_ok=True)
    return len(generated_reports)


@app.post("/api/data/clear", dependencies=[Depends(require_token)])
def api_clear_all_data():
    """Clear database scan data and generated reports. Preserve settings/logs."""
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    db = get_database()
    try:
        deleted_reports = _clear_generated_reports()
    except (OSError, RuntimeError):
        logger.exception("Refused or failed to clear the configured reports directory")
        raise HTTPException(
            status_code=500,
            detail="Reports could not be cleared; scan data was not changed",
        )
    db.clear_scan_data()
    return {
        "ok": True,
        "deleted_reports": deleted_reports,
        "message": "All scan data and generated reports cleared. Settings preserved.",
    }


# ---------------------------------------------------------------------------
# Single-domain rescan &#8212; used by "Rescan" buttons across the UI
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
    if not HAS_DB:
        raise HTTPException(status_code=503, detail="Database not available")

    _rate_check(request)

    clean, err = _sanitize_domain(domain)
    if err:
        raise HTTPException(status_code=400, detail=err)

    db = get_database()
    data_generation = db.get_data_generation()

    # Perform the scan
    scan_result = scan_domain(clean, check_starttls=False)
    scan_result["domain"] = clean
    evaluation = evaluate(scan_result)

    grade = evaluation.get("grade", "F")
    score = evaluation.get("score", 0)

    persisted = db.write_scan_results(
        [(clean, scan_result, evaluation)],
        notes=f"Rescan of {clean}",
        expected_generation=data_generation,
        save_history=True,
        update_managed=True,
    )
    if not persisted:
        raise HTTPException(
            status_code=409,
            detail="Scan data changed during the rescan; retry the request",
        )

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
        "saved": True,
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
    # Only report formats are downloadable, never arbitrary local files or
    # Windows alternate streams. Resolve the final path to reject escaped links.
    safe_name = Path(filename).name
    if safe_name != filename or any(char in filename for char in "/\\:") or Path(filename).suffix.lower() not in {".csv", ".md"}:
        raise HTTPException(status_code=404, detail="Report not found")
    file_path = REPORTS / safe_name
    reports_root = REPORTS.resolve()
    if not file_path.is_file():
        file_path = REPORTS_ROOT / safe_name
        reports_root = REPORTS_ROOT.resolve()

    if not file_path.is_file() or not file_path.resolve().is_relative_to(reports_root):
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

    # Some newer scanner fields (including BIMI) live in the extensible JSON
    # snapshot. Persisted columns remain authoritative for grades and timestamps.
    try:
        raw_result = json.loads(result.get("raw_json") or "{}")
        if isinstance(raw_result, dict):
            result = {**raw_result, **result}
    except (ValueError, TypeError):
        pass
    incomplete = _is_enabled(result.get("scan_incomplete"))

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
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm,
            topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, spaceAfter=6)
        subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=10, textColor=colors.grey)
        detail_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8,
            leading=11, splitLongWords=True)

        story.append(Paragraph("NorthFlux Security Report", title_style))
        story.append(Paragraph(f"Domain: {clean}", styles["Heading2"]))
        scanned = str(result.get("scanned_at") or "Unknown")[:19].replace("T", " ")
        story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Last Scan: {_escape(scanned)}", subtitle_style))
        story.append(Spacer(1, 10*mm))

        # Score summary
        grade = result.get("grade", "F")
        score = result.get("score", 0)
        severity = result.get("severity", "OK")
        if incomplete:
            story.append(Paragraph("Incomplete scan - no security grade assigned", styles["Heading3"]))
            story.append(Paragraph(_escape(result.get("notes") or "Some checks could not finish. Retry before relying on these findings."), styles["Normal"]))
        else:
            story.append(Paragraph(f"Grade: {_escape(grade)} &nbsp;&nbsp; Score: {_escape(score)}/100 &nbsp;&nbsp; Severity: {_escape(severity)}", styles["Heading3"]))
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
            text = str(detail)
            if len(text) > 1500:
                text = text[:1500] + " [truncated; see the saved scan for the full value]"
            checks_data.append([name, "Found" if ok else "Not confirmed" if incomplete else "Not found",
                Paragraph(_escape(text), detail_style)])

        t = Table(checks_data, colWidths=[35*mm, 30*mm, doc.width - 65*mm], repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12354b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Paragraph("Security Checks", styles["Heading3"]))
        story.append(Paragraph("Record presence is not a pass/fail verdict on the policy. Review the findings below.", subtitle_style))
        story.append(Spacer(1, 3*mm))
        story.append(t)
        story.append(Spacer(1, 5*mm))

        # Violations
        violations = result.get("violations") or "None"
        advice = result.get("advice") or "Review the observed records and scan notes before making changes."
        story.append(Paragraph("Violations & Recommendations", styles["Heading3"]))
        story.append(Paragraph(f"<b>Issues:</b> {_escape(violations)}", styles["Normal"]))
        story.append(Paragraph(f"<b>Advice:</b> {_escape(advice)}", styles["Normal"]))
        story.append(Spacer(1, 8*mm))

        story.append(Paragraph("Report generated by NorthFlux Security", subtitle_style))

        def page_footer(canvas, document):
            canvas.saveState()
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.grey)
            canvas.drawString(document.leftMargin, 10*mm, "NorthFlux Security | Configuration assessment, not a security guarantee")
            canvas.drawRightString(A4[0] - document.rightMargin, 10*mm, f"Page {document.page}")
            canvas.restoreState()

        doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
        buf.seek(0)

        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="northflux_{clean}_{datetime.now(timezone.utc).strftime("%Y%m%d")}.pdf"'}
        )
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF generation requires 'reportlab'. Install with: pip install reportlab")
    except Exception as e:
        logger.error("PDF generation failed for %s: %s", clean, e)
        raise HTTPException(status_code=500, detail="PDF generation failed &#8212; check server logs")


# =============================================================================
# Managed Domains API (SME Onboarding)
# =============================================================================


@app.get("/api/managed-domains", dependencies=[Depends(require_token)])
def api_managed_domains():
    """List all managed (onboarded) domains."""
    if not HAS_DB:
        return {"domains": [], "error": "Database not available"}
    db = get_database()
    with db.snapshot():
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
    body = await json_object(request)
    domain, err = _sanitize_domain(body.get("domain"))
    if err:
        raise HTTPException(status_code=400, detail=err)
    db = get_database()
    notes = str(body.get("notes") or "")[:500]
    data_generation = db.get_data_generation()
    result = {"ok": True, "domain": domain}

    # Run initial scan immediately
    if not HAS_SCANNER:
        if not db.add_managed_domain_if_generation(domain, notes, data_generation):
            raise HTTPException(
                status_code=409,
                detail="Scan data changed during onboarding; retry the request",
            )
        return result

    try:
        scan_result = await asyncio.to_thread(scan_domain, domain, False)
        scan_result["domain"] = domain
        evaluation = evaluate(scan_result)
    except Exception:
        logger.exception("Initial onboarding scan failed for %s", domain)
        if not db.add_managed_domain_if_generation(domain, notes, data_generation):
            raise HTTPException(
                status_code=409,
                detail="Scan data changed during onboarding; retry the request",
            )
        result["initial_scan"] = {
            "error": "Initial scan could not be completed. Try a rescan."
        }
        return result

    persisted = db.write_scan_results(
        [(domain, scan_result, evaluation)],
        notes=f"Onboarding scan for {domain}",
        expected_generation=data_generation,
        save_history=True,
        manage_domains=True,
        update_managed=True,
        managed_notes=notes,
    )
    if not persisted:
        raise HTTPException(
            status_code=409,
            detail="Scan data changed during onboarding; retry the request",
        )

    grade = evaluation.get("grade", "F")
    score = evaluation.get("score", 0)
    result["initial_scan"] = {
        "grade": grade,
        "score": score,
        "severity": evaluation.get("severity", "OK"),
    }
    if scan_result.get("scan_incomplete"):
        result["initial_scan"] = {
            "scan_incomplete": True,
            "error": "The domain was added, but some checks could not finish. Retry the scan before relying on its findings.",
        }

    # DNS changes require both the global safety setting and an explicit opt-in
    # on this individual onboarding request.
    remediation_requested = _is_enabled(
        body.get("automatic_remediation"), default=False
    )
    if not scan_result.get("scan_incomplete") and remediation_requested and _is_enabled(
        db.get_setting("automatic_remediation", "false")
    ):
        if db.get_data_generation() != data_generation:
            raise HTTPException(
                status_code=409,
                detail="Scan data changed during onboarding; remediation cancelled",
            )
        try:
            fix_result = await asyncio.to_thread(
                _auto_fix_domain, domain, scan_result,
                should_continue=lambda: (
                    db.get_data_generation() == data_generation
                    and _is_enabled(db.get_setting("automatic_remediation", "false"))
                ),
            )
            result["auto_fix"] = fix_result
        except Exception:
            logger.exception("Onboarding remediation failed for %s", domain)
            fix_result = {"applied": [], "failed": [{"message": "Remediation failed"}]}
            result["auto_fix"] = fix_result
    else:
        fix_result = {
            "applied": [],
            "failed": [],
            "skipped_reason": "Automatic remediation is disabled",
        }

    # If fixes were applied, rescan and save the updated baseline as history.
    if fix_result.get("applied"):
        await asyncio.sleep(2)
        try:
            rescan = await asyncio.to_thread(scan_domain, domain, False)
            rescan["domain"] = domain
            re_eval = evaluate(rescan)
            post_fix_saved = db.write_scan_results(
                [(domain, rescan, re_eval)],
                notes=f"Post-remediation onboarding scan for {domain}",
                expected_generation=data_generation,
                save_history=True,
                update_managed=True,
            )
            if not post_fix_saved:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Scan data changed during onboarding; "
                        "the post-remediation result was not saved"
                    ),
                )
            if rescan.get("scan_incomplete"):
                result["post_fix_scan"] = {
                    "scan_incomplete": True,
                    "error": "Changes were submitted, but verification was incomplete. No post-change grade is available.",
                }
            else:
                new_grade = re_eval.get("grade", grade)
                new_score = re_eval.get("score", score)
                result["post_fix_scan"] = {
                    "grade": new_grade,
                    "score": new_score,
                    "severity": re_eval.get("severity", "OK"),
                    "improved": new_score > score,
                }
        except HTTPException:
            raise
        except Exception:
            logger.exception("Post-remediation scan failed for %s", domain)
            result["post_fix_scan"] = {
                "error": "Post-remediation scan could not be completed."
            }

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
    # Never return secret material or even partial secret values.
    for setting_key, env_key in (
        ("cf_api_token", "CF_API_TOKEN"),
        ("cf_api_key", "CF_API_KEY"),
        ("cf_email", "CF_EMAIL"),
    ):
        stored_value = settings.pop(setting_key, "")
        env_value = os.environ.get(env_key, "")
        settings[f"{setting_key}_configured"] = bool(
            env_value or (stored_value and not _is_production())
        )
    return {"settings": settings}


@app.post("/api/settings", dependencies=[Depends(require_token)])
async def api_save_settings(request: Request):
    """
    Save application settings.
    POST body: {"cf_api_token": "...", "cf_zone_id": "...", "monitor_interval": "24", ...}
    """
    if not HAS_DB:
        raise HTTPException(status_code=501, detail="Database not available")
    body = await json_object(request)

    db = get_database()
    allowed_keys = [
        "cf_api_token", "cf_zone_id", "cf_account_id",
        "cf_api_key", "cf_email",
        "monitor_interval", "monitoring_enabled", "automatic_remediation",
        "alert_email", "org_name", "clear_on_start",
    ]
    production_secret_keys = {"cf_api_token", "cf_api_key", "cf_email"}
    allowed_intervals = {"6", "12", "24", "48", "168"}
    boolean_keys = {"monitoring_enabled", "automatic_remediation", "clear_on_start"}
    prepared = {}
    for key in allowed_keys:
        if key in body:
            value = body[key]
            if key in boolean_keys:
                if not isinstance(value, (str, bool, int)) or str(value).strip().lower() not in {
                    "true", "false", "1", "0", "yes", "no", "on", "off",
                }:
                    raise HTTPException(status_code=400, detail=f"{key} must be true or false")
                value = "true" if _is_enabled(value) else "false"
            elif key != "monitor_interval" and not isinstance(value, str):
                raise HTTPException(status_code=400, detail=f"{key} must be text")
            if len(str(value)) > 4096:
                raise HTTPException(status_code=400, detail=f"{key} is too long (maximum 4096 characters)")
            if _is_production() and key in production_secret_keys:
                if str(value).strip():
                    raise HTTPException(
                        status_code=400,
                        detail=f"{key} must be supplied through the runtime environment in production",
                    )
                continue
            if key == "monitor_interval":
                interval = str(value).strip()
                if interval not in allowed_intervals:
                    raise HTTPException(
                        status_code=400,
                        detail="monitor_interval must be one of: 6, 12, 24, 48, 168",
                    )
                value = interval
            prepared[key] = str(value)

    db.set_settings(prepared)

    # If CF credentials provided, update the live dns_fix module
    if any(k in body for k in ("cf_api_token", "cf_zone_id", "cf_account_id", "cf_api_key", "cf_email")):
        _apply_cf_settings(db)

    return {"ok": True, "saved": list(prepared)}


def _apply_cf_settings(db):
    """Refresh the live Cloudflare module from environment/settings sources."""
    _load_cf_runtime_settings(db)


_remediation_lock = threading.Lock()
_remediation_in_progress: set[str] = set()


def _serialise_domain_remediation(operation):
    """Reject overlapping manual/scheduled changes instead of queuing stale work."""
    @wraps(operation)
    def run(domain: str, *args, **kwargs):
        key = domain.strip().lower().rstrip(".")
        with _remediation_lock:
            if key in _remediation_in_progress:
                raise HTTPException(status_code=409, detail="A DNS change for this domain is already in progress")
            _remediation_in_progress.add(key)
        try:
            return operation(domain, *args, **kwargs)
        finally:
            with _remediation_lock:
                _remediation_in_progress.discard(key)
    return run


@_serialise_domain_remediation
def _auto_fix_domain(domain: str, scan_result: dict = None, should_continue=None) -> dict:
    """
    Compatibility orchestration for explicitly enabled provider integrations.
    Current generated recommendations are manual and never supply a write
    callback. Separately reviewed callbacks still require ownership and
    cancellation checks; this is not unattended mail-policy enforcement.

    Args:
        domain: The domain name to fix
        scan_result: Optional pre-existing scan result (avoids double scan)
        should_continue: Optional scheduled-work cancellation check. Provider
            writes already sent cannot be recalled.

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

    if should_continue is not None and not should_continue():
        return {"applied": [], "failed": [], "skipped_reason": "Operator stopped scheduled remediation"}

    # Scan if no result provided
    if scan_result is None:
        if not HAS_SCANNER:
            return {"applied": [], "failed": [], "skipped_reason": "Scanner not available"}
        scan_result = scan_domain(domain, check_starttls=False)
        scan_result["domain"] = domain

    # Generated recommendations are manual-only. This compatibility loop may
    # execute only callbacks supplied by a separately reviewed integration.
    fixes = cf.generate_fixes(scan_result)
    applied = []
    failed = []

    for fix in fixes:
        fix_type = fix.get("type", "Unknown")
        try:
            if should_continue is not None and not should_continue():
                return {"applied": applied, "failed": failed, "skipped_reason": "Operator stopped scheduled remediation"}
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
        logger.info(f"Auto-fix {domain}: applied {len(applied)} fix(es) &#8212; {[f['type'] for f in applied]}")
    if failed:
        logger.warning(f"Auto-fix {domain}: {len(failed)} fix(es) failed &#8212; {[f['type'] for f in failed]}")

    return {"applied": applied, "failed": failed}


@app.get("/api/settings/test-cloudflare", dependencies=[Depends(require_token)])
@app.post("/api/settings/test-cloudflare", dependencies=[Depends(require_token)])
def api_test_cloudflare():
    """Read-check the saved Cloudflare connection; never test a provider write.

    Returns the observed zone name and read-access probe results. These reads
    do not establish permission to edit DNS or deploy Workers.
    """
    if not HAS_DB:
        return {"ok": False, "message": "Database not available", "zone_name": "", "workers": False, "permissions": {}}
    db = get_database()
    _apply_cf_settings(db)
    if not HAS_DNS_FIX:
        return {"ok": False, "message": "DNS fix module not available", "zone_name": "", "workers": False, "permissions": {}}
    cf = get_cloudflare_client()
    if not cf:
        return {"ok": False, "message": "Cloudflare not configured &#8212; add API token and Zone ID in Settings", "zone_name": "", "workers": False, "permissions": {}}
    ok, msg = cf.validate_connection()
    zone = (cf.zone_name or "").strip().lower().rstrip(".")

    # Listing resources proves read access, never write permission. Keep legacy
    # keys, but use null for the write capabilities this read-only check cannot test.
    perms = {"zone_read": ok, "dns_read": False, "dns_edit": None,
             "workers": False, "workers_edit": None}
    account_id = None
    if ok:
        # Read-only DNS access probe.
        try:
            import requests as _req
            _h = {"Authorization": f"Bearer {cf.api_token}", "Content-Type": "application/json"}
            dr = _req.get(f"{cf.base_url}?per_page=1", headers=_h, timeout=8)
            perms["dns_read"] = dr.json().get("success", False)
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

    # Describe observations, not untested ability to deploy or edit resources.
    features = []
    if perms["dns_read"]:
        features.append("DNS records readable")
    if perms["workers"]:
        features.append("Worker scripts readable")

    return {
        "ok": ok,
        "message": msg + ". This is a read-only check; write permission is not tested.",
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
            if not _is_enabled(db.get_setting("monitoring_enabled", "false")):
                await asyncio.sleep(60)
                continue
            interval_hours = int(db.get_setting("monitor_interval", "24"))
            domains = db.get_managed_domains()

            if not domains:
                await asyncio.sleep(300)  # Check again in 5 min
                continue

            # Apply CF settings in case they were updated
            _apply_cf_settings(db)

            data_generation = db.get_data_generation()

            def cycle_active():
                return (
                    db.get_data_generation() == data_generation
                    and _is_enabled(db.get_setting("monitoring_enabled", "false"))
                )

            for d in domains:
                if not cycle_active():
                    break
                domain = d["domain"]
                try:
                    scan_result = await asyncio.to_thread(scan_domain, domain, False)
                    if not cycle_active():
                        logger.info("Monitoring cycle stopped after operator settings or data changed")
                        break
                    scan_result["domain"] = domain
                    evaluation = evaluate(scan_result)
                    grade = evaluation.get("grade", "F")
                    score = evaluation.get("score", 0)

                    persisted = db.write_scan_results(
                        [(domain, scan_result, evaluation)],
                        notes=f"Scheduled monitoring scan for {domain}",
                        expected_generation=data_generation,
                        save_history=True,
                        update_managed=True,
                    )
                    if not persisted:
                        logger.info("Monitoring cycle cancelled after scan data changed")
                        break

                    if scan_result.get("scan_incomplete"):
                        db.create_alert(
                            domain=domain,
                            alert_type="scan_incomplete",
                            severity="WARN",
                            message=f"Some checks for {domain} could not finish; no grade or automatic fixes were applied.",
                            details="Retry the scan and check network availability.",
                            expected_generation=data_generation,
                        )
                        await asyncio.sleep(2)
                        continue

                    # Detect drift against the snapshot read at cycle start.
                    prev_grade = d.get("last_grade")
                    prev_score = d.get("last_score")

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
                                expected_generation=data_generation,
                            )
                        elif new_idx < old_idx:
                            # Grade improved
                            db.create_alert(
                                domain=domain,
                                alert_type="grade_improved",
                                severity="INFO",
                                message=f"{domain} grade improved from {prev_grade} to {grade}",
                                details=f"Score changed from {prev_score} to {score}",
                                expected_generation=data_generation,
                            )

                    # Remediation requires a separate explicit operator opt-in.
                    if grade not in ("A+", "A") and _is_enabled(
                        db.get_setting("automatic_remediation", "false")
                    ):
                        if not cycle_active():
                            logger.info("Automatic remediation cancelled after scan data changed")
                            break
                        fix_result = await asyncio.to_thread(
                            _auto_fix_domain, domain, scan_result,
                            should_continue=lambda: cycle_active() and _is_enabled(
                                db.get_setting("automatic_remediation", "false")
                            ),
                        )
                        if fix_result.get("applied"):
                            fix_types = [f["type"] for f in fix_result["applied"]]
                            db.create_alert(
                                domain=domain,
                                alert_type="auto_fix_applied",
                                severity="INFO",
                                message=f"Auto-fixed {domain}: {', '.join(fix_types)}",
                                details=f"Applied {len(fix_result['applied'])} fix(es) automatically",
                                expected_generation=data_generation,
                            )
                            # Rescan after fix to update grade
                            await asyncio.sleep(2)
                            if not cycle_active():
                                break
                            rescan = await asyncio.to_thread(scan_domain, domain, False)
                            if not cycle_active():
                                break
                            rescan["domain"] = domain
                            re_eval = evaluate(rescan)
                            post_fix_saved = db.write_scan_results(
                                [(domain, rescan, re_eval)],
                                notes=f"Scheduled post-remediation scan for {domain}",
                                expected_generation=data_generation,
                                save_history=True,
                                update_managed=True,
                            )
                            if not post_fix_saved:
                                logger.info(
                                    "Post-remediation result discarded after scan data changed"
                                )
                                break

                except Exception:
                    logger.exception("Scheduled monitoring failed for %s", domain)
                    db.create_alert(
                        domain=domain,
                        alert_type="scan_error",
                        severity="HIGH",
                        message=f"Failed to scan {domain}",
                        details="Review the server log for the internal error.",
                        expected_generation=data_generation,
                    )

                # Small delay between domains to avoid rate limiting
                await asyncio.sleep(2)

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
    """Provide browser auth, CSRF protection, toasts, and progress helpers."""
    script = """
<script>
(function(){
    const _allowLegacyToken = __ALLOW_LEGACY_TOKEN__;
    const _tok = _allowLegacyToken
        ? (new URLSearchParams(window.location.search).get('token') || '')
        : '';

    function readCookie(name) {
        const prefix = name + '=';
        const item = document.cookie.split('; ').find(row => row.startsWith(prefix));
        return item ? decodeURIComponent(item.slice(prefix.length)) : '';
    }

    /* ---------- patch fetch ---------- */
    const _origFetch = window.fetch;
    window.fetch = function(url, opts) {
        opts = opts || {};
        let requestUrl = null;
        try {
            requestUrl = new URL(typeof url === 'string' ? url : url.url, window.location.origin);
        } catch (e) {}
        const sameOrigin = requestUrl && requestUrl.origin === window.location.origin;
        const method = String(opts.method || (url instanceof Request ? url.method : 'GET')).toUpperCase();
        const headers = new Headers(opts.headers || (url instanceof Request ? url.headers : undefined));

        if (_tok && sameOrigin && requestUrl.pathname.startsWith('/api/') && !headers.has('Authorization')) {
            headers.set('Authorization', 'Bearer ' + _tok);
        }
        const csrfToken = readCookie('northflux_csrf');
        if (csrfToken && sameOrigin && !['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
            headers.set('X-CSRF-Token', csrfToken);
        }
        opts.headers = headers;
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
    var icons = { success:'\u2705', error:'\u274C', info:'\u2139\uFE0F', warning:'\u26A0\uFE0F' };
    var toast = document.createElement('div');
    toast.style.cssText = (colours[type] || colours.info) + 'padding:14px 18px;border-radius:8px;color:#e2e8f0;font-size:0.9rem;line-height:1.5;box-shadow:0 4px 12px rgba(0,0,0,0.3);cursor:pointer;white-space:pre-wrap;backdrop-filter:blur(8px);';
    toast.textContent = (icons[type] || '') + ' ' + message;
    toast.onclick = function(){ toast.remove(); };
    container.appendChild(toast);
    if (duration > 0) setTimeout(function(){ if (toast.parentNode) toast.remove(); }, duration);
    return toast;
}

/* ---------- global progress popup (indeterminate bar) ---------- */
function showProgressPopup(title, message) {
    var overlay = document.getElementById('globalProgressOverlay');
    if (!overlay) {
        var style = document.createElement('style');
        style.textContent = `
        @keyframes ae_progress_move {
            0% { background-position: 0 0; }
            100% { background-position: 80px 0; }
        }`;
        document.head.appendChild(style);

        overlay = document.createElement('div');
        overlay.id = 'globalProgressOverlay';
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(5,8,20,0.75);backdrop-filter:blur(2px);z-index:10020;display:none;align-items:center;justify-content:center;padding:20px;';
        overlay.innerHTML = `
            <div style="width:min(520px,95vw);background:#171a2d;border:1px solid rgba(59,130,246,0.35);border-radius:12px;padding:18px 18px 16px;box-shadow:0 10px 30px rgba(0,0,0,0.45);">
                <h3 id="globalProgressTitle" style="margin:0 0 8px;color:#e2e8f0;font-size:1.05rem;">Working&#8230;</h3>
                <p id="globalProgressMessage" style="margin:0 0 12px;color:#94a3b8;font-size:0.92rem;">Please wait.</p>
                <div style="height:12px;border-radius:8px;background:#0f172a;overflow:hidden;border:1px solid rgba(148,163,184,0.25);">
                    <div style="height:100%;width:100%;background:repeating-linear-gradient(45deg,#3b82f6 0,#3b82f6 16px,#60a5fa 16px,#60a5fa 32px);background-size:80px 80px;animation:ae_progress_move 1.1s linear infinite;"></div>
                </div>
            </div>`;
        document.body.appendChild(overlay);
    }
    var t = document.getElementById('globalProgressTitle');
    var m = document.getElementById('globalProgressMessage');
    if (t) t.textContent = title || 'Working\u2026';
    if (m) m.textContent = message || 'Please wait.';
    overlay.style.display = 'flex';
}

function updateProgressPopup(message) {
    var m = document.getElementById('globalProgressMessage');
    if (m && message) m.textContent = message;
}

function hideProgressPopup() {
    var overlay = document.getElementById('globalProgressOverlay');
    if (overlay) overlay.style.display = 'none';
}
</script>
"""
    return script.replace(
        "__ALLOW_LEGACY_TOKEN__", "false" if _is_production() else "true"
    )


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
    content: '\\1F50D';
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
th.sorted::after { content: ' \\2193'; }
th.sorted.asc::after { content: ' \\2191'; }

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

// Set up EventSource for real-time updates
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

// Set up the page when it loads
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

    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response

    # &#9472;&#9472; Gather managed-domain data from the DB &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
    domains_list: list = []
    alerts: list = []
    alert_count = 0
    org_name = "Your Organisation"
    monitoring_enabled = False
    if HAS_DB:
        try:
            db = get_database()
            domains_list = db.get_managed_domains()
            alerts = db.get_alerts(unacknowledged_only=True, limit=5)
            alert_count = db.get_alert_count()
            org_name = db.get_setting("org_name", "Your Organisation") or "Your Organisation"
            monitoring_enabled = _is_enabled(
                db.get_setting("monitoring_enabled", "false")
            )
        except Exception:
            pass

    org_name = _escape(org_name)

    # Revalidate persisted records at the rendering boundary. This protects the
    # page even if an older database predates the API's current validation.
    valid_domains = []
    allowed_grades = {"A+", "A", "B", "C", "D", "F"}
    for record in domains_list:
        clean_domain, domain_error = _sanitize_domain(record.get("domain"))
        if domain_error:
            continue
        clean_record = dict(record)
        clean_record["domain"] = clean_domain
        incomplete = _is_enabled(record.get("last_scan_incomplete"))
        clean_record["last_scan_incomplete"] = incomplete
        clean_record["last_grade"] = str(record.get("last_grade") or "").upper()
        if clean_record["last_grade"] not in allowed_grades:
            clean_record["last_grade"] = None
        try:
            clean_record["last_score"] = (
                max(0, min(100, int(record["last_score"])))
                if not incomplete and record.get("last_score") is not None else None
            )
        except (TypeError, ValueError):
            clean_record["last_score"] = None
        if clean_record["last_score"] is None:
            clean_record["last_grade"] = None
        try:
            previous_score = record.get("previous_score")
            clean_record["previous_score"] = (
                max(0, min(100, int(previous_score))) if previous_score is not None else None
            )
        except (TypeError, ValueError):
            clean_record["previous_score"] = None
        valid_domains.append(clean_record)
    total_domains = len(valid_domains)
    monitoring_status = "Enabled" if monitoring_enabled else "Off"
    monitoring_dot_style = (
        "" if monitoring_enabled else "background:var(--text-muted);box-shadow:none;"
    )

    # Compute stats from managed domains
    scores = [d["last_score"] for d in valid_domains if d.get("last_score") is not None]
    avg_score = round(sum(scores) / len(scores)) if scores else None
    unknown_count = total_domains - len(scores)
    grades = {}
    for d in valid_domains:
        g = d.get("last_grade")
        if g:
            grades[g] = grades.get(g, 0) + 1
    passing = sum(1 for d in valid_domains if (d.get("last_score") or 0) >= 70)
    failing = len(scores) - passing
    worst = sorted(
        (d for d in valid_domains if d.get("last_score") is not None),
        key=lambda d: d["last_score"],
    )[:5]
    # Overall health colour
    if avg_score is None:
        health_colour = "var(--text-muted)"
        health_label = "Unknown"
        health_icon = "&#8505;&#65039;"
    elif avg_score >= 85:
        health_colour = "var(--success)"
        health_label = "Good"
        health_icon = "&#9989;"
    elif avg_score >= 60:
        health_colour = "var(--warning)"
        health_label = "Needs Attention"
        health_icon = "&#9888;&#65039;"
    else:
        health_colour = "var(--danger)"
        health_label = "Critical"
        health_icon = "&#128308;"

    # &#9472;&#9472; Grade distribution mini-bar &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
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

    # &#9472;&#9472; Domain health rows &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
    domain_rows_html = ""
    for d in sorted(valid_domains, key=lambda x: x.get("last_score") or 0):
        dom = d["domain"]
        g = d.get("last_grade") or ("Incomplete" if d.get("last_scan_incomplete") else "Not scanned")
        g_cls = g.lower().replace("+", "-plus") if d.get("last_grade") else "info"
        s = d.get("last_score")
        score_label = f"{s}/100" if s is not None else "Not available"
        prev = d.get("previous_score")
        drift = ""
        if s is not None and prev is not None and prev != s:
            drift = f' <span style="color:var(--success);font-size:.75rem;">&#9650;{s-prev}</span>' if s > prev else f' <span style="color:var(--danger);font-size:.75rem;">&#9660;{prev-s}</span>'
        last_scan = _escape((d.get("last_scan_at") or "")[:16].replace("T", " "))
        domain_rows_html += f"""
        <tr>
            <td><a href="/domain/{dom}" style="color:var(--accent);text-decoration:none;font-weight:500;">{dom}</a></td>
            <td><span class="grade-badge {g_cls}">{g}</span></td>
            <td>{score_label}{drift}</td>
            <td style="color:var(--text-secondary);font-size:.85rem;">{last_scan}</td>
        </tr>"""

    # &#9472;&#9472; Alerts HTML &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
    alerts_html = ""
    if alerts:
        for a in alerts[:5]:
            sev = (a.get("severity") or "info").lower()
            icon = "&#128308;" if sev == "high" else "&#9888;&#65039;" if sev == "warn" else "&#8505;&#65039;"
            alerts_html += f"""
            <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);">
                <span>{icon}</span>
                <div style="flex:1;">
                    <div style="font-weight:500;color:var(--text-primary);">{_escape(a.get("domain", ""))}</div>
                    <div style="font-size:.85rem;color:var(--text-secondary);">{_escape(a.get("message", ""))}</div>
                </div>
            </div>"""
    else:
        alerts_html = '<p style="color:var(--text-muted);text-align:center;padding:24px 0;">No unacknowledged alerts</p>'

    # &#9472;&#9472; Needs-attention list (worst scoring) &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
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
    if unknown_count:
        attention_html += f'<p style="color:var(--text-muted);">{unknown_count} domain(s) have incomplete or unavailable scan evidence. Rescan before relying on their results.</p>'
    if not attention_html:
        attention_html = '<p style="color:var(--text-muted);text-align:center;padding:24px 0;">All domains scoring well!</p>'

    # &#9472;&#9472; Check if CSV report dashboard also needed &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
    csv_file, md_file = _latest_pair() if not HAS_DB else (None, None)

    if total_domains == 0:
        _grade_dist_html = '<p style="color:var(--text-muted);text-align:center;padding:24px 0;">Add domains in <a href="/domains" style="color:var(--accent);">My Domains</a> to see grade data.</p>'
    else:
        _grade_dist_html = f"""
                <div style="padding:8px 0;">
                    {grade_bars_html}
                </div>
                <div style="display:flex;justify-content:space-between;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-size:.85rem;color:var(--text-secondary);">
                    <span>&#9989; Passing (&#8805;70): <strong style="color:var(--success);">{passing}</strong></span>
                    <span>&#10060; Failing (&lt;70): <strong style="color:var(--danger);">{failing}</strong></span>
                </div>"""

    if total_domains == 0:
        _domain_table_html = '<div style="text-align:center;padding:40px 0;"><p style="font-size:1.2rem;margin-bottom:8px;">&#127760; No domains onboarded yet</p><p style="color:var(--text-secondary);max-width:440px;margin:0 auto 16px;">Add domains to track their security posture. Scheduled monitoring remains off until you enable it in Settings.</p><a href="/domains" class="btn btn-primary" style="padding:12px 24px;">Go to My Domains</a></div>'
    else:
        _domain_table_html = f"""
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
            </div>"""

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NorthFlux Security</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#128737;&#65039;</text></svg>">
    {_css()}
    {_auth_js()}
</head>
<body>
    <div class="container">
        <nav class="top-nav">
            <a href="/" class="nav-brand">
                <span class="nav-brand-icon">&#128737;&#65039;</span>
                <span>NorthFlux</span>
            </a>
            <div class="nav-links">
                <a href="/" class="nav-link active">&#128202; Dashboard</a>
                <a href="/domains" class="nav-link">&#127760; My Domains</a>
                <a href="/test" class="nav-link highlight">&#128269; Scan</a>
                <a href="/generator" class="nav-link">&#128736;&#65039; Generator</a>
                <a href="/settings" class="nav-link">&#9881;&#65039; Settings</a>
            </div>
        </nav>

        <header>
            <div class="logo-area">
                <div class="logo">&#128737;&#65039;</div>
                <div>
                    <h1>NorthFlux Security</h1>
                    <p class="subtitle">Cyber Defence Overview &#8212; {org_name}</p>
                </div>
            </div>
            <div class="header-right">
                <div class="live-indicator">
                    <span class="live-dot" style="{monitoring_dot_style}"></span>
                    <span>Scheduled Monitoring {monitoring_status}</span>
                </div>
            </div>
        </header>

        <!-- &#9472;&#9472; Stat Cards &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472; -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon domains">&#127760;</div>
                <div class="stat-value">{total_domains}</div>
                <div class="stat-label">Managed Domains</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon score">&#128202;</div>
                <div class="stat-value" style="color:{health_colour};">{avg_score if avg_score is not None else 'Not available'}</div>
                <div class="stat-label">Average Score (complete scans)</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon high">{health_icon}</div>
                <div class="stat-value" style="color:{health_colour};">{health_label}</div>
                <div class="stat-label">Overall Health</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon warn">&#128276;</div>
                <div class="stat-value" style="color:{'var(--danger)' if alert_count > 0 else 'var(--success)'};">{alert_count}</div>
                <div class="stat-label">Active Alerts</div>
            </div>
        </div>

        <!-- &#9472;&#9472; Two-Column: Grade Dist + Needs Attention &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472; -->
        <div class="two-col">
            <div class="section-card">
                <h2>Grade Distribution</h2>
                {_grade_dist_html}
            </div>
            <div class="section-card">
                <h2>&#9888;&#65039; Needs Attention</h2>
                {attention_html}
            </div>
        </div>

        <!-- &#9472;&#9472; Domain Health Overview &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472; -->
        <div class="section-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h2 style="margin:0;">Domain Health Overview</h2>
                <div style="display:flex;gap:8px;">
                    <a href="/domains" class="btn btn-secondary" style="font-size:.85rem;padding:8px 16px;">Manage Domains</a>
                    <a href="/test" class="btn btn-primary" style="font-size:.85rem;padding:8px 16px;">+ Scan New</a>
                </div>
            </div>
            {_domain_table_html}
        </div>

        <!-- &#9472;&#9472; Recent Alerts &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472; -->
        <div class="section-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <h2 style="margin:0;">&#128276; Recent Alerts</h2>
                {'<a href="/domains" style="color:var(--accent);font-size:.85rem;">View All &#8594;</a>' if alert_count > 0 else ''}
            </div>
            {alerts_html}
        </div>

        <!-- &#9472;&#9472; Quick Actions &#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472; -->
        <div class="section-card">
            <h2>&#9889; Quick Actions</h2>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:12px;">
                <a href="/test" style="text-decoration:none;">
                    <div style="background:var(--bg-secondary);padding:20px;border-radius:var(--radius-sm);border:1px solid var(--border);text-align:center;transition:all .2s;cursor:pointer;" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="font-size:1.5rem;margin-bottom:8px;">&#128269;</div>
                        <div style="font-weight:600;color:var(--text-primary);">Scan Domain</div>
                        <div style="font-size:.8rem;color:var(--text-secondary);margin-top:4px;">Check email security</div>
                    </div>
                </a>
                <a href="/domains" style="text-decoration:none;">
                    <div style="background:var(--bg-secondary);padding:20px;border-radius:var(--radius-sm);border:1px solid var(--border);text-align:center;transition:all .2s;cursor:pointer;" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="font-size:1.5rem;margin-bottom:8px;">&#127760;</div>
                        <div style="font-weight:600;color:var(--text-primary);">My Domains</div>
                        <div style="font-size:.8rem;color:var(--text-secondary);margin-top:4px;">Manage monitored domains</div>
                    </div>
                </a>
                <a href="/settings" style="text-decoration:none;">
                    <div style="background:var(--bg-secondary);padding:20px;border-radius:var(--radius-sm);border:1px solid var(--border);text-align:center;transition:all .2s;cursor:pointer;" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
                        <div style="font-size:1.5rem;margin-bottom:8px;">&#9881;&#65039;</div>
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
        r = _escape_record(r)
        incomplete = _is_enabled(r.get("scan_incomplete"))
        grade = "Incomplete" if incomplete else r.get("grade") or "Not available"
        score = "Not available" if incomplete else r.get("score", "Not available")
        grade_class = grade.lower().replace("+", "-plus")
        severity = r.get("severity", "OK")
        domain = r.get("domain", "")
        spf = '<span class="check-icon check-yes">&#10003;</span>' if r.get("spf_present") == "True" else '<span class="check-icon check-no">&#10007;</span>'
        dmarc_val = r.get("dmarc_policy", "")
        dmarc = f'<span class="check-icon check-yes">&#10003;</span> {dmarc_val}' if r.get("dmarc_present") == "True" else '<span class="check-icon check-no">&#10007;</span>'
        dkim = '<span class="check-icon check-yes">&#10003;</span>' if r.get("dkim_present") == "True" else '<span class="check-icon check-no">&#10007;</span>'
        sts = '<span class="check-icon check-yes">&#10003;</span>' if r.get("mta_sts_present") == "True" else '<span class="check-icon check-no">&#10007;</span>'
        sev_class = severity.lower() if severity.lower() in ["ok", "warn", "high", "info"] else "high"
        if incomplete:
            spf = dmarc = dkim = sts = "Uncertain"
        table_rows += f"""
        <tr data-grade="{grade}" data-severity="{severity}">
            <td class="domain-cell"><a href="/domain/{domain}">{domain}</a></td>
            <td><span class="grade-badge {grade_class}">{grade}</span></td>
            <td class="score-cell">{score}</td>
            <td><span class="status-badge {sev_class}">{severity}</span></td>
            <td>{spf}</td><td>{dmarc}</td><td>{dkim}</td><td>{sts}</td>
        </tr>"""
        if r.get("notes"):
            table_rows += f'<tr><td colspan="8">Notes: {r["notes"]}</td></tr>'

    downloads = '<a href="/download/latest?kind=csv" class="btn btn-secondary" style="font-size:.85rem;padding:8px 16px;">Download CSV</a>'
    if md_file:
        downloads += ' <a href="/download/latest?kind=md" class="btn btn-secondary" style="font-size:.85rem;padding:8px 16px;">&#128196; Markdown</a>'

    report_section = f"""
    <!-- Batch Scan Report -->
    <div class="section-card" style="margin-top:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <h2 style="margin:0;">&#128203; Latest Batch Scan Report</h2>
            <div style="display:flex;gap:8px;align-items:center;">
                <span style="color:var(--text-secondary);font-size:.85rem;">{total} domains &#183; {_escape(csv_file.name)}</span>
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

/* Featured demo domain button &#8212; stands out from regular quick domains */
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
    script = """
<script>
let isScanning = false;

function showAutoFixOverlay(message) {
    const overlay = document.getElementById('autoFixOverlay');
    const text = document.getElementById('autoFixStatus');
    const bar = document.getElementById('autoFixProgress');
    if (overlay) overlay.style.display = 'flex';
    if (text) text.textContent = message || 'Applying DNS fixes...';
    if (bar) bar.style.width = '18%';
}

function updateAutoFixOverlay(message, pct) {
    const text = document.getElementById('autoFixStatus');
    const bar = document.getElementById('autoFixProgress');
    if (text && message) text.textContent = message;
    if (bar && typeof pct === 'number') bar.style.width = Math.max(10, Math.min(100, pct)) + '%';
}

function hideAutoFixOverlay() {
    const overlay = document.getElementById('autoFixOverlay');
    const bar = document.getElementById('autoFixProgress');
    if (overlay) overlay.style.display = 'none';
    if (bar) bar.style.width = '0%';
}

// Quick domain suggestions
const quickDomains = [
    'google.com', 'microsoft.com', 'cloudflare.com', 'github.com',
    'gov.uk', 'ncsc.gov.uk', 'proton.me', 'fastmail.com'
];

// The pre-configured demo domain for auto-fix testing
const demoDomain = __DEMO_DOMAIN__;
const demoModeEnabled = __DEMO_MODE_ENABLED__;

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

// Perform the scan &#8212; scans each domain individually so the UI shows
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

            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 45000);
            let response;
            try {
                response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        domains: [domain],
                        save_to_db: saveDb,
                        remediation: remediation
                    }),
                    signal: controller.signal
                });
            } catch (fetchErr) {
                clearTimeout(timer);
                if (fetchErr.name === 'AbortError') {
                    allResults.push({ domain: domain, error: 'Scan timed out &#8212; domain may not exist. Check for typos and try again.' });
                    continue;
                }
                throw fetchErr;
            }
            clearTimeout(timer);
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
            ? 'Network error &#8212; is the server running? Check the terminal for errors.'
            : error.message;
        showToast(friendly, 'error', 8000);
    } finally {
        overlay.style.display = 'none';
        if (progressBar) { progressBar.style.width = '0%'; progressBar.textContent = ''; }
        isScanning = false;
    }
}

// Display scan results with enhanced explanations
function escapeDisplayData(value) {
    if (typeof value === 'string') {
        return value
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }
    if (Array.isArray(value)) return value.map(escapeDisplayData);
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value).map(([key, item]) => [key, escapeDisplayData(item)])
        );
    }
    return value;
}

function displayResults(data) {
    const container = document.getElementById('resultsContainer');
    const section = document.getElementById('resultsSection');

    let html = '';

    for (const [resultIndex, rawResult] of data.results.entries()) {
        const result = escapeDisplayData(rawResult);
        const domain = result.domain;
        const resultId = String(resultIndex);

        if (result.error) {
            html += `
            <div class="result-container" style="border-left:4px solid var(--danger,#ef4444);">
                <div class="result-header">
                    <div class="result-domain">${domain}</div>
                    <div class="result-grade f">ERR</div>
                </div>
                <div style="padding:1rem 1.5rem;color:var(--danger,#ef4444);font-weight:500;">
                    ${result.error}
                </div>
            </div>`;
            continue;
        }

        const scan = result.scan || {};
        const ev = result.evaluation || {};
        const remediation = result.remediation || [];
        const incomplete = scan.scan_incomplete === true || scan.scan_incomplete === 1 || scan.scan_incomplete === 'True';
        const grade = incomplete ? 'Incomplete' : (ev.grade || 'Not available');
        const score = incomplete ? 'Not available' : (ev.score ?? 'Not available');
        const gradeClass = grade.toLowerCase().replace('+', '-plus');
        const severityClass = (ev.severity || 'ok').toLowerCase();

        html += `
        <div class="result-container" id="result-${resultId}">
            <div class="result-header" data-action="toggle-details" data-target="${resultId}" data-result-index="${resultIndex}">
                <div class="result-domain">
                    <span class="expand-icon">&#9654;</span>
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
                <div class="result-stat clickable" data-action="score-breakdown" data-result-index="${resultIndex}">
                    <div class="result-stat-value">${score}</div>
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
            <div class="result-details" id="details-${resultId}" style="display: none;">
                <h3 style="margin: 20px 0 12px; color: var(--text-secondary);">&#128269; Observed Records</h3>
                <p>Record presence is not a validation result. Review the findings and recommendations.</p>
                ${incomplete ? '<p>Incomplete scan. Rescan before relying on these findings or applying automatic fixes.</p>' : ''}
                ${scan.notes ? `<p>Notes: ${scan.notes}</p>` : ''}
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
                    <h4 data-action="toggle-raw" data-target="${resultId}" data-result-index="${resultIndex}" style="cursor: pointer;">
                        &#128203; Raw DNS Data <span class="toggle-hint">(click to expand)</span>
                    </h4>
                    <div class="raw-data" id="raw-${resultId}" style="display: none;">
                        <pre>${JSON.stringify(scan, null, 2)}</pre>
                    </div>
                </div>
            </div>

            ${remediation.length > 0 ? `
            <div class="remediation-section">
                <h3 style="margin-bottom: 16px; color: var(--text-secondary);">&#128295; How to Fix (${remediation.length} recommendation${remediation.length > 1 ? 's' : ''})</h3>
                ${remediation.map((r, i) => `
                    <div class="remediation-item-enhanced ${(r.priority || 'info').toLowerCase()}">
                        <div class="remediation-header" data-action="toggle-remediation" data-target="rem-${resultId}-${i}" data-result-index="${resultIndex}">
                            <span class="remediation-priority-badge ${(r.priority || 'info').toLowerCase()}">${r.priority || 'INFO'}</span>
                            <span class="remediation-title">${r.description}</span>
                            <span class="expand-arrow">&#9660;</span>
                        </div>
                        <div class="remediation-body" id="rem-${resultId}-${i}" style="display: none;">
                            ${r.why ? `
                            <div class="remediation-why">
                                <strong>&#10067; Why is this important?</strong>
                                <p>${r.why}</p>
                            </div>
                            ` : ''}
                            ${r.how_to_fix ? `
                            <div class="remediation-fix">
                                <strong>&#128295; How to fix:</strong>
                                <p>${r.how_to_fix}</p>
                            </div>
                            ` : ''}
                            ${r.example ? `
                            <div class="remediation-example-box">
                                <strong>&#128221; Example DNS Record:</strong>
                                <code class="remediation-code">${r.example}</code>
                                <button class="copy-btn" data-action="copy-example" data-result-index="${resultIndex}" data-remediation-index="${i}">&#128203; Copy</button>
                            </div>
                            ` : ''}
                            ${r.rfc ? `
                            <div class="remediation-rfc">
                                <strong>&#128218; Reference:</strong> ${r.rfc}
                            </div>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
            ` : `
            <div class="${!incomplete && ev.violation_count === 0 ? 'all-good-banner' : 'severity-banner info'}">
                <span>${incomplete ? 'Scan incomplete. Recommendations are not reliable until a complete scan is available.' : ev.violation_count === 0 ? 'No issues were identified by these checks. This is not a guarantee of security.' : 'Recommendations were not requested or are unavailable. Review the reported issues.'}</span>
            </div>
            `}

            <!-- Action Buttons -->
            <div class="result-actions">
                <button class="action-btn secondary" data-action="rescan" data-result-index="${resultIndex}">&#128260; Rescan</button>
                ${!incomplete && ev.violation_count > 0 ? `<button class="action-btn primary" data-action="auto-fix" data-result-index="${resultIndex}" style="background:var(--warning);color:#000;">&#128295; Auto-Fix DNS</button>` : ''}
                <button class="action-btn secondary" data-action="history" data-result-index="${resultIndex}">&#128202; View History</button>
                <button class="action-btn primary" data-action="export" data-result-index="${resultIndex}">&#128229; Export Report</button>
            </div>
        </div>
        `;
    }

    container.innerHTML = html;

    // Bind behavior after rendering so untrusted DNS text is never embedded in
    // executable inline event attributes.
    container.querySelectorAll('[data-action]').forEach(element => {
        element.addEventListener('click', event => {
            event.stopPropagation();
            const action = element.dataset.action;
            const resultIndex = Number(element.dataset.resultIndex);
            const rawResult = data.results[resultIndex];
            if (!rawResult) return;
            const domain = rawResult.domain;

            if (action === 'toggle-details') toggleDetails(element.dataset.target);
            else if (action === 'score-breakdown') {
                if (rawResult.scan?.scan_incomplete) showToast('Incomplete scan: no reliable score is available.', 'warning');
                else showScoreBreakdown(domain, rawResult.evaluation?.score ?? 'Not available');
            }
            else if (action === 'toggle-raw') toggleRawData(element.dataset.target);
            else if (action === 'toggle-remediation') toggleRemediation(element.dataset.target);
            else if (action === 'copy-example') {
                const remediationIndex = Number(element.dataset.remediationIndex);
                const example = rawResult.remediation?.[remediationIndex]?.example || '';
                copyToClipboard(example);
            }
            else if (action === 'rescan') rescanDomain(domain);
            else if (action === 'auto-fix') autoFixFromScan(domain);
            else if (action === 'history') showHistory(domain);
            else if (action === 'export') exportDomainReport(domain, rawResult);
        });
    });

    section.style.display = 'block';
    section.scrollIntoView({ behavior: 'smooth' });

    // Auto-expand first result details
    const firstExpandable = container.querySelector('[data-action="toggle-details"]');
    if (firstExpandable) toggleDetails(firstExpandable.dataset.target);
}

function getSeverityIcon(severity) {
    const icons = {
        'CRITICAL': '&#128680;',
        'HIGH': '&#9888;&#65039;',
        'WARN': '&#9889;',
        'INFO': '&#8505;&#65039;',
        'OK': '&#9989;'
    };
    return icons[severity] || '\u2753';
}

function toggleDetails(domainId) {
    const details = document.getElementById('details-' + domainId);
    const result = document.getElementById('result-' + domainId);
    const icon = result.querySelector('.expand-icon');

    if (details.style.display === 'none') {
        details.style.display = 'block';
        icon.textContent = '\u25BC';
        result.classList.add('expanded');
    } else {
        details.style.display = 'none';
        icon.textContent = '\u25B6';
        result.classList.remove('expanded');
    }
}

function toggleRemediation(remId) {
    const body = document.getElementById(remId);
    const parent = body.parentElement;
    const arrow = parent.querySelector('.expand-arrow');

    if (body.style.display === 'none') {
        body.style.display = 'block';
        arrow.textContent = '\u25B2';
        parent.classList.add('expanded');
    } else {
        body.style.display = 'none';
        arrow.textContent = '\u25BC';
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
        showProgressPopup('Applying Auto-Fix DNS', 'Checking Cloudflare access for ' + domain + '...');
        showAutoFixOverlay('Checking Cloudflare access for ' + domain + '...');
        // Test Cloudflare first and get zone name for ownership check
        const cfRes = await fetch('/api/settings/test-cloudflare');
        const cfData = await cfRes.json();
        if (!cfData.ok) {
            hideProgressPopup();
            hideAutoFixOverlay();
            showToast('Cloudflare is not configured. Go to Settings and add your API Token and Zone ID first.', 'error', 8000);
            return;
        }
        // Frontend ownership check &#8212; block before sending the request
        const zone = (cfData.zone_name || '').toLowerCase();
        const dom = domain.toLowerCase();
        if (zone && dom !== zone && !dom.endsWith('.' + zone)) {
            hideProgressPopup();
            hideAutoFixOverlay();
            showToast('Cannot auto-fix "' + domain + '"\\nYour Cloudflare zone is "' + zone + '". You can only auto-fix domains within that zone.\\nGo to Settings to change your Cloudflare credentials.', 'error', 10000);
            return;
        }
        updateProgressPopup('Applying DNS fixes via Cloudflare API...');
        updateAutoFixOverlay('Applying DNS fixes via Cloudflare API...', 55);
        const res = await fetch('/api/apply-fix', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain })
        });
        const data = await res.json();
        if (!res.ok) {
            hideProgressPopup();
            hideAutoFixOverlay();
            showToast('Auto-Fix Blocked: ' + (data.detail || 'Unknown error.'), 'error', 8000);
            return;
        }
        updateProgressPopup('Finalising verification and refreshing results...');
        updateAutoFixOverlay('Finalising verification and refreshing results...', 92);
        let msg = '';
        if (data.applied && data.applied.length > 0) {
            msg += '\u2705 Fixes applied:\\n' + data.applied.map(f => '  \u2713 ' + f.type + ': ' + f.message).join('\\n');
        }
        if (data.failed && data.failed.length > 0) {
            msg += (msg ? '\\n\\n' : '') + '\u274C Failed:\\n' + data.failed.map(f => '  \u2717 ' + f.type + ': ' + f.message).join('\\n');
        }
        if (data.manual_actions && data.manual_actions.length > 0) {
            msg += (msg ? '\\n\\n' : '') + '&#128295; Manual steps still needed:\\n' + data.manual_actions.map(m => '  \u26A0 ' + m.type + ': ' + m.description).join('\\n');
        }
        if (data.verification) {
            msg += (msg ? '\\n\\n' : '') + '&#128269; Verification: ' + data.verification;
        }
        if (data.cf_verified && data.cf_verified.length > 0) {
            msg += (msg ? '\\n\\n' : '') + '\u2601\uFE0F Cloudflare API confirms:\\n' + data.cf_verified.map(v => '  \u2022 ' + v).join('\\n');
        }
        if (data.pre_fix_grade && data.grade && data.pre_fix_grade !== data.grade) {
            msg += '\\n&#128200; Grade: ' + data.pre_fix_grade + ' \u2192 ' + data.grade + ' (Score: ' + data.pre_fix_score + ' \u2192 ' + data.score + ')';
        } else if (data.grade) {
            msg += '\\n&#128202; Grade: ' + data.grade + ' | Score: ' + data.score;
        }
        if (!msg && data.grade) {
            msg = 'Current grade: ' + data.grade + ' (Score: ' + data.score + ')\\nNo auto-fixable issues found.';
            if (data.violations > 0) msg += '\\n\\n\u26A0 ' + data.violations + ' issue(s) detected but they require manual configuration.';
            else msg += ' Domain looks good!';
        } else if (!msg) {
            msg = 'No issues found &#8212; domain looks good!';
        }
        const hasFailures = (data.failed && data.failed.length > 0) || ['incomplete', 'failed'].includes(data.verification_status);
        const hasApplied = (data.applied && data.applied.length > 0);
        hideProgressPopup();
        updateAutoFixOverlay('Done.', 100);
        setTimeout(() => hideAutoFixOverlay(), 500);
        showToast(msg, hasFailures ? 'warning' : hasApplied ? 'success' : 'info', 15000);
        // Auto-rescan after fixes to refresh displayed results
        if (hasApplied) {
            setTimeout(() => rescanDomain(domain), 5000);
        }
    } catch(e) {
        hideProgressPopup();
        hideAutoFixOverlay();
        showToast('Auto-fix error: ' + e.message, 'error', 8000);
    }
}

async function resetDemoDomain(restore = false) {
    const btn = restore
        ? document.getElementById('restoreDemoBtn')
        : document.getElementById('resetDemoBtn');
    const resetBtn = document.getElementById('resetDemoBtn');
    const restoreBtn = document.getElementById('restoreDemoBtn');
    const original = btn ? btn.innerHTML : '';
    const actionLabel = restore ? 'restore' : 'reset';
    const confirmMsg = restore
        ? 'Restore ' + demoDomain + ' to the strong DNS state now?'
        : 'This will intentionally re-break ' + demoDomain + ' DNS records for another live auto-fix test.\\n\\nProceed?';

    if (!confirm(confirmMsg)) return;

    if (resetBtn) resetBtn.disabled = true;
    if (restoreBtn) restoreBtn.disabled = true;
    if (btn) btn.innerHTML = restore ? '&#9203; Restoring Demo&#8230;' : '&#9203; Resetting Demo&#8230;';

    showProgressPopup(
        restore ? 'Restoring Demo DNS' : 'Resetting Demo DNS',
        'Applying Cloudflare changes and validating DNS state...'
    );

    try {
        updateProgressPopup('Submitting demo ' + actionLabel + ' request...');
        const res = await fetch('/api/demo/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: demoDomain, restore: restore })
        });
        const data = await res.json();
        if (!res.ok) {
            hideProgressPopup();
            showToast('Demo ' + actionLabel + ' failed: ' + (data.detail || 'Unknown error.'), 'error', 10000);
            return;
        }

        updateProgressPopup('Server-side verification complete. Refreshing live score...');
        addQuickDomain(demoDomain);
        const expectedScore = (data.scan && typeof data.scan.score === 'number') ? data.scan.score : null;
        const refreshed = await refreshDemoResultUntilStable(demoDomain, restore, expectedScore);

        let msg = data.message || ('Demo ' + actionLabel + ' complete.');
        if (refreshed && refreshed.evaluation) {
            msg += '\\nCurrent grade: ' + (refreshed.evaluation.grade || 'F') + ' (' + (refreshed.evaluation.score || 0) + '/100, ' + (refreshed.evaluation.severity || 'OK') + ')';
        } else if (data.scan && data.scan.grade) {
            msg += '\\nCurrent grade: ' + data.scan.grade + ' (' + data.scan.score + '/100, ' + data.scan.severity + ')';
        } else {
            msg += '\\nScan ' + demoDomain + ' to verify the current state.';
        }
        hideProgressPopup();
        showToast(msg, 'success', 12000);
    } catch (e) {
        hideProgressPopup();
        showToast('Demo ' + actionLabel + ' error: ' + e.message, 'error', 10000);
    } finally {
        if (resetBtn) resetBtn.disabled = false;
        if (restoreBtn) restoreBtn.disabled = false;
        if (btn) btn.innerHTML = original;
    }
}

function sleepMs(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function refreshDemoResultUntilStable(domain, restore, expectedScore) {
    const waits = [0, 2500, 4500, 7000, 10000];
    let best = null;

    for (let i = 0; i < waits.length; i++) {
        if (waits[i] > 0) await sleepMs(waits[i]);
        updateProgressPopup('Refreshing DNS scan (' + (i + 1) + '/' + waits.length + ')...');

        try {
            const res = await fetch('/api/rescan/' + encodeURIComponent(domain), { method: 'POST' });
            const data = await res.json();
            if (!res.ok || !data || !data.evaluation) continue;

            const current = {
                domain: data.domain || domain,
                scan: data.scan || {},
                evaluation: data.evaluation || {},
                remediation: data.remediation || []
            };

            if (!best) {
                best = current;
            } else {
                const bestScore = Number(best.evaluation?.score || 0);
                const currentScore = Number(current.evaluation?.score || 0);
                if ((!restore && currentScore < bestScore) || (restore && currentScore > bestScore)) {
                    best = current;
                }
            }

            displayResults({ status: 'success', count: 1, results: [best] });

            const score = Number(current.evaluation?.score || 0);
            if (expectedScore !== null) {
                if ((!restore && score <= expectedScore) || (restore && score >= expectedScore)) {
                    return best;
                }
            }
        } catch (e) {
            // Keep retrying until attempts are exhausted.
        }
    }

    return best;
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
&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;&#9472;
Total Score: ${score}/100

Scoring System:
&#8226; Start with 100 points
&#8226; CRITICAL issues: -40 points each
&#8226; HIGH issues: -25 points each
&#8226; WARN issues: -10 points each
&#8226; INFO issues: -2 points each

Grade Thresholds:
&#8226; A+ (95-100): Excellent
&#8226; A  (85-94): Very Good
&#8226; B  (75-84): Good
&#8226; C  (60-74): Fair
&#8226; D  (40-59): Poor
&#8226; F  (0-39): Fail
    `;
    alert(breakdown);
}

function renderCheckEnhanced(name, present, detail, ruleId) {
    const status = present ? 'pass' : 'fail';
    const icon = present ? '&#10003;' : '&#10007;';
    return `
        <div class="check-item ${status}" onclick="showCheckInfo('${name}', ${present}, '${ruleId}')" style="cursor: pointer;">
            <span class="check-name">${name}</span>
            <span class="check-status ${status}">${icon} ${present ? 'Record found' : 'Not found'} ${detail}</span>
            <span class="check-hint">Click for info</span>
        </div>
    `;
}

async function showCheckInfo(name, present, ruleId) {
    if (present) {
        alert(name + ' record found\\n\\nRecord presence does not prove that this control is valid or correctly configured. Review the scan findings.');
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

// Set up quick-domain buttons
document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('quickDomains');
    if (container) {
        // Read-only example; the live reset/restore workflow is retired.
        if (demoModeEnabled) {
            const demoBtn = document.createElement('button');
            demoBtn.className = 'quick-domain demo-domain';
            demoBtn.appendChild(document.createTextNode('\u2B50 ' + demoDomain + ' '));
            const demoLabel = document.createElement('small');
            demoLabel.textContent = '(Read-only example)';
            demoBtn.appendChild(demoLabel);
            demoBtn.title = 'Read-only scan example; review recommendations before making any DNS changes';
            demoBtn.onclick = () => addQuickDomain(demoDomain);
            container.appendChild(demoBtn);
        }

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
    return (
        script.replace("__DEMO_DOMAIN__", json.dumps(DEMO_DOMAIN))
        .replace(
            "__DEMO_MODE_ENABLED__",
            "true" if _is_enabled(os.environ.get("NORTHFLUX_DEMO_MODE")) else "false",
        )
    )


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

    body = await json_object(request)

    domains = body.get("domains", [])
    if not domains:
        raise HTTPException(status_code=400, detail="No domains provided")

    if isinstance(domains, str):
        domains = [domains]
    if not isinstance(domains, list):
        raise HTTPException(status_code=400, detail="domains must be a list of domain names")

    # Limit to prevent abuse
    if len(domains) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 domains per request")

    save_to_db = _is_enabled(body.get("save_to_db"), default=True)
    manage_domains = _is_enabled(body.get("manage_domains"), default=False)
    show_remediation = _is_enabled(body.get("remediation"), default=True)

    results = []
    persist_entries = []
    db = None
    data_generation = None

    if (save_to_db or manage_domains) and not HAS_DB:
        raise HTTPException(status_code=503, detail="Database not available")
    if save_to_db or manage_domains:
        try:
            db = get_database()
            data_generation = db.get_data_generation()
        except Exception:
            logger.exception("Could not prepare scan persistence")
            raise HTTPException(status_code=500, detail="Could not prepare scan storage")

    for raw_domain in domains:
        domain, d_err = _sanitize_domain(raw_domain)
        if d_err:
            results.append({"domain": "(invalid)", "error": d_err, "saved": False})
            continue

        try:
            # Run blocking DNS scan in thread pool with an overall
            # timeout so mistyped domains don't hang the UI.
            try:
                scan_result = await asyncio.wait_for(
                    asyncio.to_thread(scan_domain, domain, False),
                    timeout=SCAN_TIMEOUT,
                )
            except asyncio.TimeoutError:
                results.append({
                    "domain": domain,
                    "error": f"Scan timed out after {int(SCAN_TIMEOUT)}s &#8212; domain may not exist. Check for typos and try again.",
                    "saved": False,
                })
                continue

            scan_notes = scan_result.get("notes", "")
            if "Domain not found" in scan_notes or "Invalid domain" in scan_notes:
                results.append({"domain": domain, "error": scan_notes, "saved": False})
                continue

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

            payload = {
                "domain": domain,
                "scan": scan_result,
                "evaluation": evaluation,
                "remediation": remediation_list,
                "saved": False,
            }
            results.append(payload)
            persist_entries.append((domain, scan_result, evaluation, payload))

        except Exception:
            logger.exception("Scan failed for %s", domain)
            results.append(
                {
                    "domain": domain,
                    "error": "The scan could not be completed. Check the domain and try again.",
                    "saved": False,
                }
            )

    persistence_applied = True
    if db and persist_entries:
        persistence_applied = db.write_scan_results(
            [(domain, scan, evaluation) for domain, scan, evaluation, _ in persist_entries],
            notes=f"Dashboard scan of {len(domains)} domain(s)",
            expected_generation=data_generation,
            save_history=save_to_db,
            manage_domains=manage_domains,
            update_managed=manage_domains,
            managed_notes="Added via scan",
        )
    for _domain, _scan, _evaluation, payload in persist_entries:
        payload["saved"] = bool(save_to_db and persistence_applied)

    ok = [r for r in results if "error" not in r]
    status = "success" if len(ok) == len(results) else "partial" if ok else "error"
    return {
        "status": status,
        "count": len(results),
        "results": results,
        "persistence_skipped": bool(
            (save_to_db or manage_domains) and not persistence_applied
        ),
    }


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
    body = await json_object(request)
    domain, error = _sanitize_domain(body.get("domain"))
    if error:
        raise HTTPException(status_code=400, detail=error)
    requested = body.get("fix_types")
    if requested is not None and (
        not isinstance(requested, list)
        or not requested
        or any(not isinstance(item, str) or item not in {
            "SPF", "DMARC", "DKIM", "TLS-RPT", "MTA-STS", "MTA-STS-HTTPS",
        } for item in requested)
    ):
        raise HTTPException(status_code=400, detail="fix_types must be a non-empty list of supported fixes")
    # Provider requests, DNS scans and propagation waits are synchronous. Keep
    # them off the event loop so sign-in, health and other pages remain usable.
    return await asyncio.to_thread(_apply_fix_sync, domain, requested)


@_serialise_domain_remediation
def _apply_fix_sync(domain: str, requested_fix_types: Optional[List[str]]) -> Dict:
    """Run one already-validated remediation request in a worker thread."""
    if not HAS_DNS_FIX:
        raise HTTPException(status_code=501, detail="DNS fix module not available")

    # Capture cancellation state before slow provider reads, and never proceed
    # with potentially stale credentials if the settings refresh fails.
    try:
        persistence_db = get_database() if HAS_DB else None
        data_generation = persistence_db.get_data_generation() if persistence_db else None
        if persistence_db:
            _apply_cf_settings(persistence_db)
    except Exception:
        logger.exception("Could not load current remediation settings")
        raise HTTPException(status_code=503, detail="Current remediation settings could not be loaded")

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

    # OWNERSHIP CHECK: refuse to modify DNS for domains outside the configured zone
    owned, ownership_msg = cf.verify_domain_ownership(domain)
    if not owned:
        raise HTTPException(status_code=403, detail=ownership_msg)

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

        if persistence_db and persistence_db.get_data_generation() != data_generation:
            failed_fixes.append({
                "type": fix_type, "success": False,
                "message": "Remediation cancelled because the operator changed scan data or removed a domain.",
                "priority": "WARN",
            })
            break

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
    verification_status = "not_run"
    history_saved = False
    cf_verified = []  # records confirmed via Cloudflare API
    if applied_fixes:
        import time
        time.sleep(2)  # brief pause for Cloudflare edge propagation

        # --- Cloudflare API verification (instant, no DNS cache) ---
        try:
            for fix in applied_fixes:
                ft = fix.get("type", "")
                if ft == "SPF":
                    rec = cf.get_txt_record(domain)
                    if rec and "-all" in rec.get("content", ""):
                        cf_verified.append(f"SPF: {rec['content']}")
                elif ft == "DMARC":
                    rec = cf.get_txt_record(f"_dmarc.{domain}")
                    if rec:
                        cf_verified.append(f"DMARC: {rec['content']}")
                elif ft == "MTA-STS":
                    rec = cf.get_txt_record(f"_mta-sts.{domain}")
                    if rec:
                        cf_verified.append(f"MTA-STS DNS: {rec['content']}")
                elif ft == "TLS-RPT":
                    rec = cf.get_txt_record(f"_smtp._tls.{domain}")
                    if rec:
                        cf_verified.append(f"TLS-RPT: {rec['content']}")
        except Exception:
            pass

        # --- DNS-based verification scan ---
        # Retry a few times so live demos are less likely to show stale
        # DNS cache immediately after fixes are applied.
        try:
            pre_score = pre_fix_eval.get("score", 0)
            post_scan = None
            attempts = [0, 8, 18, 30, 45, 60]  # cumulative wait for DNS propagation

            def _strong_demo_state(scan: Dict) -> bool:
                return (
                    str(scan.get("spf_all") or "").strip().lower() == "-all"
                    and str(scan.get("dmarc_policy") or "").strip().lower() == "reject"
                    and int(scan.get("dmarc_pct") or 0) >= 100
                    and bool(scan.get("mta_sts_present"))
                )

            for idx, wait_s in enumerate(attempts):
                if wait_s > 0:
                    time.sleep(wait_s if idx == 1 else wait_s - attempts[idx - 1])
                cur_scan = scan_domain(domain, check_starttls=False)
                cur_scan["domain"] = domain
                cur_eval = evaluate(cur_scan)
                cur_score = cur_eval.get("score", 0)
                # Keep the latest observation, including regressions/timeouts.
                # Choosing the highest score hides a later failure.
                post_scan = cur_scan
                post_fix_eval = cur_eval
                if not cur_scan.get("scan_incomplete") and cur_score > pre_score and _strong_demo_state(cur_scan):
                    break

            post_score = post_fix_eval.get("score", 0)
            if post_scan.get("scan_incomplete"):
                verification_status = "incomplete"
                verification_note = (
                    "Changes were submitted, but the latest verification scan was incomplete. "
                    "No post-change grade is available. Retry the scan before relying on these changes."
                )
            elif post_score > pre_score:
                verification_status = "observed"
                verification_note = (
                    f"Score improved from {pre_score} to {post_score} "
                    f"(Grade {pre_fix_eval.get('grade', '?')} to {post_fix_eval.get('grade', '?')}). "
                    "The latest public scan observed an improvement; review the individual records."
                )
            elif post_score == pre_score and cf_verified:
                verification_status = "pending"
                verification_note = (
                    "Cloudflare currently reports these records: "
                    + "; ".join(cf_verified)
                    + ". The public scan score is unchanged; cached DNS answers can take longer to update."
                )
            elif post_score == pre_score:
                verification_status = "pending"
                verification_note = (
                    "DNS changes submitted to Cloudflare but the verification "
                    "scan score is unchanged. Review the records and rescan after cached DNS answers expire."
                )
            else:
                verification_status = "observed"
                verification_note = (
                    f"The latest verification score is lower: {pre_score} to {post_score}. "
                    "Review the new findings and DNS records before making further changes."
                )
            # Persist the actual latest observation, not only favourable results.
            if persistence_db:
                try:
                    history_saved = persistence_db.write_scan_results(
                        [(domain, post_scan, post_fix_eval)],
                        notes="Post-fix verification",
                        expected_generation=data_generation,
                        save_history=True,
                        update_managed=True,
                    )
                    if not history_saved:
                        verification_note += (
                            " The verification result was not saved because scan data "
                            "was cleared during remediation."
                        )
                except Exception:
                    logger.exception("Could not persist post-fix verification for %s", domain)
        except Exception:
            logger.exception("Post-fix verification scan failed for %s", domain)
            verification_status = "failed"
            verification_note = "Changes were submitted, but post-fix verification failed. No post-change grade is available. Review server logs and rescan."

    # Use post-fix evaluation if available, otherwise pre-fix
    final_eval = post_fix_eval if post_fix_eval else pre_fix_eval

    # Determine accurate status
    if applied_fixes and not failed_fixes and not manual_actions:
        status = "success"
    elif applied_fixes and not failed_fixes and manual_actions:
        status = "partial"
    elif applied_fixes and failed_fixes:
        status = "partial"
    elif not applied_fixes and not failed_fixes:
        status = "manual_review" if manual_actions else "no_action"
    else:
        status = "failed"

    uncertain = bool(scan_result.get("scan_incomplete")) or verification_status in {"incomplete", "failed"}
    if applied_fixes and uncertain:
        status = "partial"

    return {
        "status": status,
        "domain": domain,
        "applied": applied_fixes,
        "failed": failed_fixes,
        "manual_actions": manual_actions,
        "grade": None if uncertain else final_eval.get("grade", ""),
        "score": None if uncertain else final_eval.get("score", 0),
        "violations": final_eval.get("violation_count", 0),
        "pre_fix_grade": None if scan_result.get("scan_incomplete") else pre_fix_eval.get("grade", ""),
        "pre_fix_score": None if scan_result.get("scan_incomplete") else pre_fix_eval.get("score", 0),
        "verification": verification_note,
        "verification_status": verification_status,
        "history_saved": history_saved,
        "cf_verified": cf_verified,
        "cloudflare_zone": msg,
    }


@app.post("/api/demo/reset", dependencies=[Depends(require_token)])
async def api_demo_reset(request: Request):
    """The legacy live-DNS weakening exercise is deliberately unavailable."""
    if _is_production() or not _is_enabled(os.environ.get("NORTHFLUX_DEMO_MODE")):
        raise HTTPException(status_code=404, detail="Demo mode is not enabled")
    raise HTTPException(
        status_code=410,
        detail=(
            "Live DNS demo reset/restore has been retired for safety. "
            "Use offline sample scenarios; use the guarded remediation workflow "
            "only with an authorised test zone and a recovery plan."
        ),
    )


@app.get("/api/fix-status", dependencies=[Depends(require_token)])
def api_fix_status():
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
    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response
    demo_mode_enabled = _is_enabled(os.environ.get("NORTHFLUX_DEMO_MODE"))
    demo_display = "block" if demo_mode_enabled else "none"
    demo_example = f"{DEMO_DOMAIN} (demo), " if demo_mode_enabled else ""
    demo_help = (
        f" <strong>{DEMO_DOMAIN}</strong> is a read-only example, not a live DNS-reset test."
        if demo_mode_enabled
        else ""
    )
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NorthFlux Security - Scan Domains</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#129514;</text></svg>">
    {_css()}
    {_auth_js()}
    {_test_css()}
</head>
<body>
    <div class="container">
        <!-- Professional Navigation Bar -->
        <nav class="top-nav">
            <a href="/" class="nav-brand">
                <span class="nav-brand-icon">&#128737;&#65039;</span>
                <span>NorthFlux</span>
            </a>
            <div class="nav-links">
                <a href="/" class="nav-link">&#128202; Dashboard</a>
                <a href="/domains" class="nav-link">&#127760; My Domains</a>
                <a href="/test" class="nav-link active">&#128269; Scan</a>
                <a href="/generator" class="nav-link">&#128736;&#65039; Generator</a>
                <a href="/settings" class="nav-link">&#9881;&#65039; Settings</a>
            </div>
        </nav>
        
        <header>
            <div class="logo-area">
                <div class="logo">&#128269;</div>
                <div>
                    <h1>Domain Security Scan</h1>
                    <p class="subtitle">Analyse and defend email authentication for any domain</p>
                </div>
            </div>
        </header>
        
        <div class="help-box">
            <h3>&#128737;&#65039; How It Works</h3>
            <p>
                Enter any domain below and NorthFlux Security will check its
                <strong>SPF</strong>, <strong>DMARC</strong>, <strong>DKIM</strong>, 
                <strong>MTA-STS</strong>, and <strong>TLS-RPT</strong> configurations. 
                You&#8217;ll get a security grade, score, and actionable remediation recommendations.
            </p>
        </div>
        
        <!-- Retired live-DNS demonstration notice -->
        <div class="demo-guide" style="display:{demo_display}; background:rgba(234,179,8,0.10); border:1px solid rgba(234,179,8,0.4); border-radius:12px; padding:20px 24px; margin-bottom:24px;">
            <h3 style="margin:0 0 10px; color:#fde68a;">Read-only Demonstration</h3>
            <p style="margin:0 0 8px; color:#e2e8f0; line-height:1.6;">
                Live-DNS reset and restore are retired. This page cannot prepare a weakened zone or restore a previous DNS configuration.
                Use read-only scans of domains you are authorised to assess; no particular state is assumed for <strong>{DEMO_DOMAIN}</strong>.
            </p>
            <ol style="margin:8px 0 0; padding-left:20px; color:#cbd5e1; line-height:1.8;">
                <li>Enter an authorised domain and press <strong>Scan Domain</strong>.</li>
                <li>Review the findings and any incomplete-check notes. Current generated recommendations require manual review.</li>
                <li>Before publishing changes, confirm provider-specific values and keep an approved recovery plan.</li>
                <li>After separately reviewed changes, rescan and inspect the evidence; a higher score is not proof of successful mail delivery.</li>
            </ol>
            <p style="margin:10px 0 0; color:#94a3b8; font-size:0.85rem;">
                Do not use a public zone for destructive demonstrations. Historical scripts retain an offline preview only, not a rollback mechanism.
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
                <input type="text" id="domainInput" placeholder="e.g., {demo_example}google.com, cloudflare.com">
                <small>Enter a domain name without http:// or www.{demo_help}</small>
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
                &#128269; Scan Domain
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
                &#128640; Start Batch Scan
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
        <div class="scanning-overlay" id="autoFixOverlay" style="display:none;">
            <div class="scanning-modal" style="max-width:560px;">
                <div class="scanning-spinner"></div>
                <p id="autoFixStatus">Applying DNS fixes...</p>
                <div style="width:100%;background:rgba(255,255,255,0.12);border-radius:8px;overflow:hidden;margin-top:12px;height:14px;">
                    <div id="autoFixProgress" style="height:100%;width:0%;background:linear-gradient(90deg,#f59e0b,#60a5fa);transition:width .35s ease;"></div>
                </div>
                <small style="display:block;margin-top:10px;color:#cbd5e1;">Please wait &#8212; this can take 10-60 seconds while DNS updates propagate.</small>
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
    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response
    """Detailed view for a specific domain &#8212; pulls from DB, falls back to CSV."""
    domain, domain_error = _sanitize_domain(domain)
    if domain_error:
        raise HTTPException(status_code=400, detail=domain_error)
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

    # Legacy CSV fallback is only available without database support. Never
    # resurrect deleted history (or mask a database failure) from old exports.
    if not result and not HAS_DB:
        csv_file, _ = _latest_pair()
        if csv_file:
            rows = load_csv(csv_file)
            for row in rows:
                if row.get("domain", "").lower() == domain.lower():
                    result = row
                    break

    if not result:
        # Navigation is read-only; an explicit action starts a scan.
        return RedirectResponse(url=f"/scan?domain={domain}", status_code=303)

    result = _escape_record(_saved_scan_evidence(result))

    # Normalise &#8212; DB stores integers (0/1), CSV stores strings ("True"/"False")
    def _bool(val):
        if val is None:
            return False
        if isinstance(val, bool):
            return val
        if isinstance(val, int):
            return val == 1
        return str(val).strip().lower() in ("true", "1", "yes")

    incomplete = _bool(result.get("scan_incomplete"))
    grade = "Incomplete" if incomplete else result.get("grade") or "Not available"
    grade_class = grade.lower().replace("+", "-plus")
    score = "Not available" if incomplete or result.get("score") is None else result["score"]
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
        ("Blacklists", str(result.get("rbl_listings", "")) == "0",
         "No listings found by these checks" if str(result.get("rbl_listings", "")) == "0" else f"Listings: {result.get('rbl_listings', 'Not available')}"),
    ]

    checks_html = ""
    for name, present, details in checks:
        status = "Uncertain" if incomplete else (
            "No listings found" if name == "Blacklists" and present else
            "Review listings" if name == "Blacklists" else
            "Record found" if present else "Not found"
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
                    <h2>&#128200; Scan History</h2>
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Date</th><th>Grade</th><th>Score</th><th>Severity</th><th>Violations</th></tr></thead>
                            <tbody>"""
                for h in history:
                    h = _escape_record(_saved_scan_evidence(h))
                    h_incomplete = _bool(h.get("scan_incomplete"))
                    scan_date = (h.get("scanned_at") or "")[:16].replace("T", " ")
                    h_grade = "Incomplete" if h_incomplete else h.get("grade") or "Not available"
                    h_gc = h_grade.lower().replace("+", "-plus")
                    history_html += f"""
                                <tr>
                                    <td>{scan_date}</td>
                                    <td><span class="grade-badge {h_gc}" style="font-size:0.8rem;padding:2px 8px;">{h_grade}</span></td>
                                    <td>{'Not available' if h_incomplete or h.get('score') is None else h['score']}</td>
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
                    h = _saved_scan_evidence(h)
                    chart_labels.append((h.get("scanned_at") or "")[:16].replace("T", " "))
                    chart_scores.append(None if _bool(h.get("scan_incomplete")) else h.get("score"))
                labels_json = json.dumps(chart_labels).replace("<", "\\u003c")
                scores_json = json.dumps(chart_scores)
                timeline_chart_html = f"""
                <div class="section-card" style="margin-bottom: 24px;">
                    <h2>&#128202; Score Timeline</h2>
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
                    managed_badge = '<span style="background:var(--accent);color:#000;padding:4px 12px;border-radius:12px;font-size:0.8rem;font-weight:600;margin-left:12px;">MANAGED</span>'
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
    <title>NorthFlux Security - {domain}</title>
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
                <div class="logo" style="font-size: 1.5rem;">&#127760;</div>
                <div>
                    <h1>{domain}{managed_badge}</h1>
                    <p class="subtitle">Last scanned: {scanned_at}</p>
                </div>
            </div>
            <span class="grade-badge {grade_class}" style="font-size:2rem; padding: 12px 24px;">{grade}</span>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon score">&#128202;</div>
                <div class="stat-value">{score}</div>
                <div class="stat-label">Security Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon {"high" if severity == "HIGH" else "warn" if severity == "WARN" else "domains"}">&#9889;</div>
                <div class="stat-value">{severity}</div>
                <div class="stat-label">Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon warn">&#128276;</div>
                <div class="stat-value">{violation_count}</div>
                <div class="stat-label">Violations</div>
            </div>
        </div>

        <div class="detail-actions">
            <button class="btn btn-primary" id="rescanBtn" onclick="rescanThisDomain()">&#128260; Rescan Now</button>
            <button class="btn btn-secondary" id="autoFixBtn" {'disabled' if incomplete else ''} onclick="fixDomain()" style="background:var(--warning);color:#000;border-color:var(--warning);">&#128295; Auto-Fix DNS</button>
            <a href="/api/report/pdf/{domain}" class="btn btn-secondary" style="background:var(--accent);color:#000;border-color:var(--accent);">&#128196; Download PDF Report</a>
            <a href="/domains" class="btn btn-secondary">&#8592; Back to My Domains</a>
        </div>

        <div class="section-card" style="margin-bottom: 24px;">
            <h2>&#128269; Observed Records</h2>
            <p>Finding a record does not prove it is valid or correctly configured. Review the findings below.</p>
            <p>{'This scan is incomplete. Rescan before relying on its findings or applying automatic fixes.' if incomplete else ''} {result.get('notes') or ''}</p>
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
            <h2>&#128221; Violations & Recommendations</h2>
            <p style="margin-bottom: 12px;"><strong>Issues:</strong> {result.get("violations") or "None"}</p>
            <p><strong>Advice:</strong> {result.get("advice") or "No recommendation recorded. Review the scan evidence."}</p>
        </div>

        {_footer_html()}
    </div>

    <script>
    async function fixDomain() {{
        if ({'true' if incomplete else 'false'}) {{
            alert('This scan is incomplete. Rescan before applying automatic fixes.');
            return;
        }}
        if (!confirm('Auto-Fix will attempt to update DNS records for {domain} via Cloudflare.' + String.fromCharCode(10,10) + 'Proceed?')) return;
        try {{
            showProgressPopup('Applying Auto-Fix DNS', 'Checking Cloudflare access for {domain}...');
            const cfRes = await fetch('/api/settings/test-cloudflare');
            const cfData = await cfRes.json();
            if (!cfData.ok) {{
                hideProgressPopup();
                alert('Cloudflare is not configured.\\nGo to Settings to add your API Token and Zone ID.');
                return;
            }}
            // Frontend ownership check
            const zone = (cfData.zone_name || '').toLowerCase();
            const dom = '{domain}'.toLowerCase();
            if (zone && dom !== zone && !dom.endsWith('.' + zone)) {{
                hideProgressPopup();
                alert('&#9940; Cannot auto-fix "{domain}"' + String.fromCharCode(10,10) + 'Your Cloudflare zone is "' + zone + '".' + String.fromCharCode(10) + 'You can only auto-fix domains within that zone.' + String.fromCharCode(10,10) + 'Go to Settings if you need to change your Cloudflare credentials.');
                return;
            }}
            updateProgressPopup('Applying DNS fixes via Cloudflare API...');
            const res = await fetch('/api/apply-fix', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{domain: '{domain}'}})
            }});
            const data = await res.json();
            if (!res.ok) {{
                hideProgressPopup();
                alert('&#9940; Auto-Fix Blocked\\n\\n' + (data.detail || 'Unknown error.'));
                return;
            }}
            updateProgressPopup('Finalising verification and preparing summary...');
            let msg = '';
            if (data.applied && data.applied.length > 0)
                msg += '\u2705 Fixes applied:\\n' + data.applied.map(f => '  \u2713 ' + f.type + ': ' + f.message).join('\\n');
            if (data.failed && data.failed.length > 0)
                msg += (msg ? '\\n\\n' : '') + '\u274C Failed:\\n' + data.failed.map(f => '  \u2717 ' + f.type + ': ' + f.message).join('\\n');
            if (data.manual_actions && data.manual_actions.length > 0)
                msg += (msg ? '\\n\\n' : '') + '&#128295; Manual steps still needed:\\n' + data.manual_actions.map(m => '  \u26A0 ' + m.type + ': ' + m.description).join('\\n');
            if (data.verification)
                msg += (msg ? '\\n\\n' : '') + '&#128269; Verification: ' + data.verification;
            if (data.cf_verified && data.cf_verified.length > 0)
                msg += (msg ? '\\n\\n' : '') + '\u2601\uFE0F Cloudflare API confirms:\\n' + data.cf_verified.map(v => '  \u2022 ' + v).join('\\n');
            if (data.pre_fix_grade && data.grade && data.pre_fix_grade !== data.grade)
                msg += '\\n&#128200; Grade: ' + data.pre_fix_grade + ' \u2192 ' + data.grade + ' (Score: ' + data.pre_fix_score + ' \u2192 ' + data.score + ')';
            else if (data.grade)
                msg += '\\n&#128202; Grade: ' + data.grade + ' | Score: ' + data.score;
            if (!msg && data.grade) {{
                msg = 'Current grade: ' + data.grade + ' (Score: ' + data.score + ')\\nNo auto-fixable issues found.';
                if (data.violations > 0) msg += '\\n\\n\u26A0 ' + data.violations + ' issue(s) detected but they require manual configuration.';
                else msg += ' Domain looks good!';
            }} else if (!msg) {{
                msg = 'No issues found &#8212; domain looks good!';
            }}
            hideProgressPopup();
            alert(msg);
            // Reload the page to show updated results
            if (data.applied && data.applied.length > 0) {{
                setTimeout(() => location.reload(), 5000);
            }}
        }} catch(e) {{
            hideProgressPopup();
            alert('Error: ' + e.message);
        }}
    }}

    async function rescanThisDomain() {{
        const btn = document.getElementById('rescanBtn');
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '&#9203; Rescanning&#8230;';
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
            <span class="nav-brand-icon">&#128737;&#65039;</span>
            <span>NorthFlux</span>
        </a>
        <div class="nav-links">
            <a href="/" class="{_cls('dashboard')}">&#128202; Dashboard</a>
            <a href="/domains" class="{_cls('domains')}">&#127760; My Domains{badge}</a>
            <a href="/test" class="{_cls('scan')}">&#128269; Scan</a>
            <a href="/generator" class="{_cls('generator')}">&#128736;&#65039; Generator</a>
            <a href="/settings" class="{_cls('settings')}">&#9881;&#65039; Settings</a>
        </div>
    </nav>
    """


def _footer_html() -> str:
    """Consistent footer across all pages."""
    return """
    <footer>
        <div style="margin-bottom: 16px;">
            <strong style="font-size: 1.1rem; color: var(--text-primary);">NorthFlux Security</strong>
            <span style="color: var(--accent);"> &#183; </span>
            <span>Automated Email Authentication & Cyber Defence System</span>
        </div>
        <p>Created and maintained by Leon Chapman</p>
        <p style="margin-top: 8px;">Self-hosted beta &#183; Operator-controlled monitoring and remediation</p>
        <p style="margin-top: 6px; font-size: 0.75rem; color: var(--text-dim);">Public DNS, HTTPS &amp; SMTP posture checks &middot; Operator-controlled instance storage &middot; <a href="/privacy" style="color: var(--accent);">Privacy Summary</a></p>
    </footer>
    """


@app.get("/domains", response_class=HTMLResponse, dependencies=[Depends(require_token)])
def domains_page():
    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response
    """Managed domains page \u2014 the core of the SME experience."""
    # Get managed domains and alerts
    domains_list = []
    alerts = []
    monitoring_enabled = False
    if HAS_DB:
        try:
            db = get_database()
            domains_list = db.get_managed_domains()
            alerts = db.get_alerts(unacknowledged_only=True, limit=20)
            monitoring_enabled = _is_enabled(
                db.get_setting("monitoring_enabled", "false")
            )
        except Exception:
            pass

    monitoring_status = "Enabled" if monitoring_enabled else "Off"
    monitoring_dot_style = (
        "" if monitoring_enabled else "background:var(--text-muted);box-shadow:none;"
    )

    # Build domain cards
    domain_cards = ""
    if domains_list:
        for d in domains_list:
            domain_value = str(d.get("domain") or "")
            domain_value, domain_error = _sanitize_domain(domain_value)
            if domain_error:
                logger.warning("Skipping invalid managed domain in database: %s", domain_error)
                continue
            domain_text = _escape(domain_value)
            grade_order = ["A+", "A", "B", "C", "D", "F"]
            incomplete = _is_enabled(d.get("last_scan_incomplete"))
            raw_grade = str(d.get("last_grade") or "").upper()
            grade = "Incomplete" if incomplete else raw_grade if raw_grade in grade_order else "Not scanned"
            try:
                score = max(0, min(100, int(d["last_score"]))) if not incomplete and d.get("last_score") is not None else None
            except (TypeError, ValueError):
                score = None
            score_label = f"{score}/100" if score is not None else "Not available"
            grade_class = grade.lower().replace("+", "-plus") if grade in grade_order else "info"
            prev_grade = str(d.get("previous_grade") or "").upper()
            drift = ""
            if grade in grade_order and prev_grade in grade_order and prev_grade != grade:
                old_i = grade_order.index(prev_grade)
                new_i = grade_order.index(grade) if grade in grade_order else 5
                if new_i > old_i:
                    drift = f'<span style="color:var(--danger);font-size:0.8rem;">&#9660; was {prev_grade}</span>'
                elif new_i < old_i:
                    drift = f'<span style="color:var(--success);font-size:0.8rem;">&#9650; was {prev_grade}</span>'

            last_scan = d.get("last_scan_at") or "Never"
            if last_scan != "Never":
                last_scan = last_scan[:16].replace("T", " ")
            last_scan = _escape(last_scan)

            domain_cards += f"""
            <div class="domain-card" data-domain="{domain_text}">
                <div class="domain-card-header">
                    <div>
                        <div class="domain-card-name">{domain_text}</div>
                        <div class="domain-card-meta">Last scanned: {last_scan} {drift}</div>
                    </div>
                    <div class="domain-card-grade">
                        <span class="grade-badge {grade_class}" style="font-size:1.4rem;padding:8px 16px;">{grade}</span>
                        <div style="text-align:center;margin-top:4px;font-size:0.8rem;color:var(--text-muted);">{score_label}</div>
                    </div>
                </div>
                <div class="domain-card-actions">
                    <button class="action-btn primary" onclick="rescanManaged(this.closest('.domain-card').dataset.domain)">&#128260; Rescan</button>
                    <button class="action-btn secondary auto-fix" {'disabled' if incomplete else ''} onclick="fixDomain(this.closest('.domain-card').dataset.domain)">&#128295; Auto-Fix</button>
                    <a href="/domain/{domain_text}" class="action-btn secondary">&#128203; Details</a>
                    <button class="action-btn secondary" onclick="removeDomain(this.closest('.domain-card').dataset.domain)" style="margin-left:auto;color:var(--danger);">&#10005; Remove</button>
                </div>
            </div>"""
    else:
        domain_cards = """
        <div class="section-card" style="text-align:center; padding: 48px;">
            <div style="font-size: 2.5rem; margin-bottom: 16px;">&#127760;</div>
            <h3 style="margin-bottom: 12px;">No Domains Onboarded</h3>
            <p style="color:var(--text-secondary); margin-bottom: 24px;">
                Add your organisation's domain to track its security posture. Scheduled monitoring remains off until you enable it in Settings.
            </p>
        </div>"""

    # Build alerts section
    alerts_html = ""
    if alerts:
        alerts_html = '<div class="alerts-section"><h2>&#9889; Active Alerts</h2>'
        for a in alerts:
            sev_cls = (a.get("severity") or "info").lower()
            alert_message = _escape(a.get("message", ""))
            alert_details = _escape(a.get("details", ""))
            alerts_html += f"""
            <div class="alert-item {sev_cls}">
                <div class="alert-content">
                    <strong>{alert_message}</strong>
                    <span style="color:var(--text-muted);font-size:0.8rem;margin-left:8px;">{(a.get('created_at') or '')[:16].replace('T',' ')}</span>
                    {f'<div style="color:var(--text-secondary);font-size:0.85rem;margin-top:4px;">{alert_details}</div>' if alert_details else ''}
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
    <title>NorthFlux Security - My Domains</title>
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
                <div class="logo">&#127760;</div>
                <div>
                    <h1>My Domains</h1>
                    <p class="subtitle">Manage and defend your organisation's email domains</p>
                </div>
            </div>
            <div class="header-right">
                <div class="live-indicator">
                    <span class="live-dot" style="{monitoring_dot_style}"></span>
                    <span>Scheduled Monitoring {monitoring_status}</span>
                </div>
            </div>
        </header>

        {alerts_html}

        <div class="add-domain-form">
            <div class="form-field">
                <label for="newDomain">Add Domain</label>
                <input type="text" id="newDomain" placeholder="e.g., yourcompany.com">
            </div>
            <button class="btn btn-primary" onclick="addDomain(this)" style="height:46px;">+ Add Domain</button>
        </div>

        <div id="domainsList">
            {domain_cards}
        </div>

        <!-- Fix Modal -->
        <div class="fix-overlay" id="fixOverlay" onclick="if(event.target===this)this.style.display='none'">
            <div class="fix-modal">
                <h2 style="margin-bottom:16px;">&#128295; Auto-Fix DNS Records</h2>
                <p id="fixStatus" style="color:var(--text-secondary);margin-bottom:16px;">Analysing domain...</p>
                <div style="width:100%;height:12px;border-radius:8px;background:#0f172a;overflow:hidden;border:1px solid rgba(148,163,184,0.25);margin:0 0 14px;">
                    <div id="fixProgressBar" style="height:100%;width:8%;background:linear-gradient(90deg,#3b82f6,#60a5fa);transition:width .35s ease;"></div>
                </div>
                <div id="fixResults"></div>
                <button class="btn btn-secondary" onclick="document.getElementById('fixOverlay').style.display='none'" style="margin-top:16px;">Close</button>
            </div>
        </div>

        {_footer_html()}
    </div>

    <script>
    function escapeHtml(value) {{
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }}

    async function addDomain(btn) {{
        btn = btn || document.querySelector('.add-domain-form .btn-primary');
        const domain = document.getElementById('newDomain').value.trim();
        if (!domain) {{ alert('Please enter a domain'); return; }}
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
            const res = await fetch('/api/managed-domains/' + encodeURIComponent(domain), {{method: 'DELETE'}});
            if (!res.ok) throw new Error('Failed');
            location.reload();
        }} catch(e) {{
            alert('Error: ' + e.message);
        }}
    }}

    async function rescanManaged(domain) {{
        const card = Array.from(document.querySelectorAll('[data-domain]'))
            .find(el => el.dataset.domain === domain);
        const btn = card ? card.querySelector('.action-btn.primary') : null;
        if (btn) {{ btn.disabled = true; btn.textContent = '\u23F3 Scanning...'; }}
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
            const incomplete = Boolean(data.scan?.scan_incomplete);
            const grade = incomplete ? 'Incomplete' : (ev.grade || 'Not available');
            const score = incomplete ? null : ev.score;
            const gradeClass = grade.toLowerCase().replace('+', '-plus');
            if (card) {{
                const gradeBadge = card.querySelector('.grade-badge');
                if (gradeBadge) {{
                    gradeBadge.textContent = grade;
                    gradeBadge.className = 'grade-badge ' + gradeClass;
                }}
                const scoreEl = card.querySelector('.domain-card-grade div');
                if (scoreEl) scoreEl.textContent = score == null ? 'Not available' : score + '/100';
                const fixBtn = card.querySelector('.auto-fix');
                if (fixBtn) fixBtn.disabled = incomplete;
                const metaEl = card.querySelector('.domain-card-meta');
                if (metaEl) metaEl.textContent = 'Last scanned: ' + new Date().toISOString().slice(0,16).replace('T',' ');
                card.style.opacity = '1';
            }}
        }} catch(e) {{
            alert('Error: ' + e.message);
        }} finally {{
            if (btn) {{ btn.disabled = false; btn.textContent = '&#128260; Rescan'; }}
            if (card) card.style.opacity = '1';
        }}
    }}

    async function fixDomain(domain) {{
        const overlay = document.getElementById('fixOverlay');
        const status = document.getElementById('fixStatus');
        const results = document.getElementById('fixResults');
        const progress = document.getElementById('fixProgressBar');
        const setProgress = (v) => {{ if (progress) progress.style.width = Math.max(8, Math.min(100, v)) + '%'; }};
        overlay.style.display = 'flex';
        status.textContent = 'Checking Cloudflare access for ' + domain + '...';
        results.innerHTML = '';
        setProgress(15);

        try {{
            // Check if Cloudflare is configured and get zone name
            const cfRes = await fetch('/api/settings/test-cloudflare');
            const cfData = await cfRes.json();
            setProgress(35);
            if (!cfData.ok) {{
                setProgress(100);
                status.textContent = '\u26A0\uFE0F Cloudflare not connected';
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

            // Frontend ownership check &#8212; block before sending the fix request
            const zone = (cfData.zone_name || '').toLowerCase();
            const dom = domain.toLowerCase();
            if (zone && dom !== zone && !dom.endsWith('.' + zone)) {{
                setProgress(100);
                status.textContent = '\u26D4 Domain not in your Cloudflare zone';
                results.innerHTML = `
                    <div style="background:var(--danger-bg);padding:16px;border-radius:8px;margin-top:12px;">
                        <p><strong>Cannot auto-fix "${{escapeHtml(domain)}}"</strong></p>
                        <p style="color:var(--text-secondary);margin-top:8px;">
                            Your Cloudflare zone is <strong>"${{escapeHtml(zone)}}"</strong>. You can only
                            auto-fix domains within that zone (e.g. <strong>${{escapeHtml(zone)}}</strong>
                            or <strong>sub.${{escapeHtml(zone)}}</strong>).
                        </p>
                        <p style="color:var(--text-secondary);margin-top:8px;">
                            Go to <a href="/settings" style="color:var(--accent);">Settings</a>
                            to change your Cloudflare credentials, or scan a domain you control.
                        </p>
                    </div>`;
                return;
            }}

            status.textContent = 'Scanning ' + domain + ' and applying fixes...';
            setProgress(65);

            // Apply fixes
            const res = await fetch('/api/apply-fix', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{domain: domain}})
            }});
            const data = await res.json();
            setProgress(90);

            if (!res.ok) {{
                setProgress(100);
                // Server rejected the request (e.g. domain not in configured zone)
                status.textContent = '\u26D4 Auto-Fix Blocked';
                results.innerHTML = `
                    <div style="background:var(--danger-bg);padding:16px;border-radius:8px;margin-top:12px;">
                        <p><strong>${{escapeHtml(data.detail || 'Unable to apply fixes.')}}</strong></p>
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
                        <strong>&#9989; ${{escapeHtml(f.type)}}</strong> &#8212; ${{escapeHtml(f.message)}}</div>`;
                }});
                hasContent = true;
            }}
            if (data.failed && data.failed.length > 0) {{
                data.failed.forEach(f => {{
                    html += `<div style="background:var(--danger-bg);padding:12px;border-radius:6px;margin-bottom:8px;">
                        <strong>&#10060; ${{escapeHtml(f.type)}}</strong> &#8212; ${{escapeHtml(f.message)}}</div>`;
                }});
                hasContent = true;
            }}
            if (data.manual_actions && data.manual_actions.length > 0) {{
                html += `<div style="background:var(--bg-secondary);padding:12px;border-radius:6px;margin-bottom:8px;border-left:3px solid var(--warning);">
                    <strong>&#128295; Manual Steps Required</strong></div>`;
                data.manual_actions.forEach(m => {{
                    html += `<div style="background:var(--bg-tertiary);padding:12px;border-radius:6px;margin-bottom:8px;border-left:3px solid var(--warning);">
                        <strong>&#9888; ${{escapeHtml(m.type)}}</strong> &#8212; ${{escapeHtml(m.description)}}`;
                    if (m.steps) html += `<br><small style="color:var(--text-secondary);white-space:pre-line;margin-top:4px;display:block;">${{escapeHtml(m.steps)}}</small>`;
                    html += `</div>`;
                }});
                hasContent = true;
            }}

            if (data.verification) {{
                html += `<div style="padding:12px;border-radius:6px;margin-top:8px;background:var(--bg-secondary);border-left:3px solid var(--accent);">
                    &#128269; <strong>Verification:</strong> ${{escapeHtml(data.verification)}}</div>`;
            }}
            if (data.cf_verified && data.cf_verified.length > 0) {{
                html += `<div style="padding:12px;border-radius:6px;margin-top:8px;background:var(--bg-secondary);border-left:3px solid var(--success);">
                    &#9729;&#65039; <strong>Cloudflare API confirms:</strong><br>${{data.cf_verified.map(v => '&nbsp;&nbsp;&#8226; ' + escapeHtml(v)).join('<br>')}}</div>`;
            }}
            if (data.pre_fix_grade && data.grade && data.pre_fix_grade !== data.grade) {{
                html += `<div style="padding:12px;border-radius:6px;margin-top:8px;background:var(--success-bg);text-align:center;">
                    &#128200; <strong>Grade: ${{escapeHtml(data.pre_fix_grade)}} &#8594; ${{escapeHtml(data.grade)}}</strong> | Score: ${{escapeHtml(data.pre_fix_score)}} &#8594; ${{escapeHtml(data.score)}} | Issues: ${{escapeHtml(data.violations || 0)}}</div>`;
            }} else if (data.grade) {{
                html += `<div style="padding:12px;border-radius:6px;margin-top:8px;background:var(--bg-secondary);text-align:center;">
                    &#128202; <strong>Grade: ${{escapeHtml(data.grade)}}</strong> | Score: ${{escapeHtml(data.score)}} | Issues: ${{escapeHtml(data.violations || 0)}}</div>`;
            }}
            html += '</div>';
            setProgress(100);

            if (['incomplete', 'failed'].includes(data.verification_status)) {{
                status.textContent = 'Verification is incomplete or failed. Rescan before relying on these changes.';
            }} else if (data.failed && data.failed.length > 0) {{
                status.textContent = 'Some fixes failed. Review the results below.';
            }} else if (data.applied && data.applied.length > 0 && (!data.manual_actions || data.manual_actions.length === 0)) {{
                status.textContent = '\u2705 All fixes applied successfully!';
            }} else if (data.applied && data.applied.length > 0) {{
                status.textContent = '\u26A0\uFE0F Some fixes applied \u2014 manual steps still needed';
            }} else if (data.manual_actions && data.manual_actions.length > 0) {{
                status.textContent = '&#128295; No auto-fixes available \u2014 manual configuration required';
            }} else if (!hasContent && data.violations === 0) {{
                status.textContent = '\u2705 No fixes needed \u2014 domain looks good!';
            }} else if (!hasContent) {{
                status.textContent = '\u26A0\uFE0F Issues detected but no auto-fixes available';
            }} else {{
                status.textContent = '\u26A0\uFE0F Some fixes failed';
            }}

            results.innerHTML = html;
        }} catch(e) {{
            status.textContent = '\u274C Error: ' + e.message;
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
    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response
    """Interactive DNS record generator for SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI."""
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NorthFlux Security &#8212; DNS Record Generator</title>
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
                <div class="logo" style="font-size:1.5rem;">&#128736;&#65039;</div>
                <div>
                    <h1>DNS Record Generator</h1>
                    <p class="subtitle">Draft email security records for review before publishing</p>
                </div>
            </div>
        </header>

        <div class="gen-grid">
            <!-- SPF Generator -->
            <div class="gen-form">
                <h3>&#128274; SPF Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 7208 &#8212; Sender Policy Framework</p>
                <label>Domain</label>
                <input type="text" id="spf_domain" placeholder="example.com" oninput="genSPF()">
                <label>Email Provider Includes (comma-separated)</label>
                <input type="text" id="spf_includes" placeholder="_spf.google.com, spf.protection.outlook.com" oninput="genSPF()">
                <label>Additional IPs (comma-separated)</label>
                <input type="text" id="spf_ips" placeholder="203.0.113.10, 198.51.100.0/24" oninput="genSPF()">
                <label>Failure Policy</label>
                <select id="spf_all" onchange="genSPF()">
                    <option value="-all" selected>-all (Hardfail &#8212; recommended)</option>
                    <option value="~all">~all (Softfail)</option>
                    <option value="?all">?all (Neutral)</option>
                </select>
                <div class="gen-output" id="spf_out"><button class="copy-btn" onclick="copyRec('spf_out')">Copy</button></div>
            </div>

            <!-- DMARC Generator -->
            <div class="gen-form">
                <h3>&#128203; DMARC Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 7489 &#8212; Domain-based Message Authentication</p>
                <label>Domain</label>
                <input type="text" id="dmarc_domain" placeholder="example.com" oninput="genDMARC()">
                <label>Policy</label>
                <select id="dmarc_policy" onchange="genDMARC()">
                    <option value="reject">reject (Strongest &#8212; recommended)</option>
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
                <label>Legacy Percentage (pct)</label>
                <input type="number" id="dmarc_pct" value="100" min="0" max="100" oninput="genDMARC()">
                <p>Legacy compatibility only: RFC 9989 does not define pct sampling. Do not rely on this field to limit enforcement.</p>
                <div class="gen-output" id="dmarc_out"><button class="copy-btn" onclick="copyRec('dmarc_out')">Copy</button></div>
            </div>

            <!-- MTA-STS Generator -->
            <div class="gen-form">
                <h3>&#128272; MTA-STS Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 8461 &#8212; Mail Transfer Agent Strict Transport Security</p>
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
                <h3>&#128202; TLS-RPT Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 8460 &#8212; TLS Reporting</p>
                <label>Domain</label>
                <input type="text" id="tlsrpt_domain" placeholder="example.com" oninput="genTLSRPT()">
                <label>Report Email</label>
                <input type="text" id="tlsrpt_email" placeholder="tlsrpt@example.com" oninput="genTLSRPT()">
                <div class="gen-output" id="tlsrpt_out"><button class="copy-btn" onclick="copyRec('tlsrpt_out')">Copy</button></div>
            </div>

            <!-- BIMI Generator -->
            <div class="gen-form">
                <h3>&#127912; BIMI Record</h3>
                <p style="font-size:0.8rem;color:var(--text-dim);margin-bottom:8px;">RFC 9495 &#8212; Brand Indicators for Message Identification</p>
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
    function setGeneratedOutput(id, text) {{
        const el = document.getElementById(id);
        const button = document.createElement('button');
        button.className = 'copy-btn';
        button.textContent = 'Copy';
        button.addEventListener('click', () => copyRec(id));
        el.replaceChildren(button, document.createTextNode(text));
    }}

    function genSPF() {{
        const d = document.getElementById('spf_domain').value.trim() || 'example.com';
        const inc = document.getElementById('spf_includes').value.split(',').map(s=>s.trim()).filter(Boolean);
        const ips = document.getElementById('spf_ips').value.split(',').map(s=>s.trim()).filter(Boolean);
        const all = document.getElementById('spf_all').value;
        let parts = ['v=spf1'];
        ips.forEach(ip => parts.push(ip.includes(':') ? 'ip6:'+ip : 'ip4:'+ip));
        inc.forEach(i => parts.push('include:'+i));
        parts.push(all);
        const rec = parts.join(' ');
        setGeneratedOutput('spf_out', d + '. IN TXT "' + rec + '"');
    }}

    function genDMARC() {{
        const d = document.getElementById('dmarc_domain').value.trim() || 'example.com';
        const p = document.getElementById('dmarc_policy').value;
        const sp = document.getElementById('dmarc_sp').value;
        const rua = document.getElementById('dmarc_rua').value.trim();
        const ruf = document.getElementById('dmarc_ruf').value.trim();
        const pctText = document.getElementById('dmarc_pct').value.trim();
        const pct = pctText === '' ? 100 : Number(pctText);
        if (!Number.isInteger(pct) || pct < 0 || pct > 100) {{
            setGeneratedOutput('dmarc_out', 'Enter a whole percentage from 0 to 100. This legacy field does not guarantee sampling.');
            return;
        }}
        let parts = ['v=DMARC1', 'p=' + p];
        if (sp) parts.push('sp=' + sp);
        if (pct < 100) parts.push('pct=' + pct);
        if (rua) parts.push('rua=mailto:' + rua);
        if (ruf) parts.push('ruf=mailto:' + ruf);
        const rec = parts.join('; ');
        setGeneratedOutput('dmarc_out', '_dmarc.' + d + '. IN TXT "' + rec + '"');
    }}

    function genSTS() {{
        const d = document.getElementById('sts_domain').value.trim() || 'example.com';
        const mode = document.getElementById('sts_mode').value;
        const mx = document.getElementById('sts_mx').value.trim() || ('mail.' + d);
        const maxAge = document.getElementById('sts_maxage').value || '604800';
        const id = new Date().toISOString().slice(0,10).replace(/-/g,'');
        setGeneratedOutput('sts_dns_out', 'DNS TXT Record:\\n_mta-sts.' + d + '. IN TXT "v=STSv1; id=' + id + '"');
        setGeneratedOutput('sts_policy_out', 'Policy File (https://mta-sts.' + d + '/.well-known/mta-sts.txt):\\nversion: STSv1\\nmode: ' + mode + '\\nmx: ' + mx + '\\nmax_age: ' + maxAge);
    }}

    function genTLSRPT() {{
        const d = document.getElementById('tlsrpt_domain').value.trim() || 'example.com';
        const email = document.getElementById('tlsrpt_email').value.trim() || ('tlsrpt@' + d);
        setGeneratedOutput('tlsrpt_out', '_smtp._tls.' + d + '. IN TXT "v=TLSRPTv1; rua=mailto:' + email + '"');
    }}

    function genBIMI() {{
        const d = document.getElementById('bimi_domain').value.trim() || 'example.com';
        const logo = document.getElementById('bimi_logo').value.trim();
        const vmc = document.getElementById('bimi_vmc').value.trim();
        setGeneratedOutput('bimi_out', 'default._bimi.' + d + '. IN TXT "v=BIMI1; l=' + (logo || 'https://' + d + '/logo.svg') + '; a=' + (vmc || '') + '"');
    }}

    function copyRec(id) {{
        const el = document.getElementById(id);
        const text = el.innerText.replace('Copy', '').trim();
        navigator.clipboard.writeText(text).then(() => {{
            if (typeof showToast === 'function') showToast('Copied to clipboard!', 'success');
        }});
    }}

    // Fill the generator with the default values
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
    spa_response = _spa_index_response()
    if spa_response is not None:
        return spa_response
    """Application settings page &#8212; Cloudflare credentials, monitoring config."""
    settings = {}
    if HAS_DB:
        try:
            db = get_database()
            settings = db.get_all_settings()
        except Exception:
            pass

    production_mode = _is_production()
    env_token = (os.environ.get("CF_API_TOKEN", "") or "").strip()
    env_api_key = (os.environ.get("CF_API_KEY", "") or "").strip()
    cf_token_set = bool(env_token or (settings.get("cf_api_token") and not production_mode))
    cf_api_key_set = bool(env_api_key or (settings.get("cf_api_key") and not production_mode))
    cf_token_source = "runtime environment" if env_token else "local settings"
    cf_api_key_source = "runtime environment" if env_api_key else "local settings"
    credential_inputs_disabled = "disabled" if production_mode else ""

    zone_id = _escape(os.environ.get("CF_ZONE_ID") or settings.get("cf_zone_id", ""))
    account_id = _escape(os.environ.get("CF_ACCOUNT_ID") or settings.get("cf_account_id", ""))
    cf_email = "" if production_mode else _escape(settings.get("cf_email", ""))
    interval = settings.get("monitor_interval", "24")
    org_name = _escape(settings.get("org_name", ""))
    alert_email = _escape(settings.get("alert_email", ""))
    monitoring_enabled = _is_enabled(settings.get("monitoring_enabled", "false"))
    automatic_remediation = _is_enabled(settings.get("automatic_remediation", "false"))
    clear_on_start = _is_enabled(settings.get("clear_on_start", "false"))

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

    cf_badge = '<span class="status-chip ready">Configured, not verified</span>' if (cf_token_set or cf_api_key_set) and zone_id else '<span class="status-chip not-connected">Not configured</span>'

    _cf_token_current = (
        f'<div class="current-value">Configured via {cf_token_source}</div>'
        if cf_token_set
        else ""
    )
    _cf_apikey_current = (
        f'<div class="current-value">Configured via {cf_api_key_source}</div>'
        if cf_api_key_set
        else ""
    )
    _credential_guidance = (
        '<small>Production secrets are read from CF_API_TOKEN, CF_API_KEY, and CF_EMAIL.</small>'
        if production_mode
        else ""
    )

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NorthFlux Security - Settings</title>
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
                <div class="logo">&#9881;&#65039;</div>
                <div>
                    <h1>Settings</h1>
                    <p class="subtitle">Configure NorthFlux Security for your organisation</p>
                </div>
            </div>
            <div>
                {cf_badge}
            </div>
        </header>

        <div class="settings-grid">

            <!-- Organisation -->
            <div class="settings-card">
                <h3>&#127970; Organisation</h3>
                <p class="card-desc">Identity details used in reports and the dashboard header.</p>
                <div class="form-row">
                    <label for="orgName">Organisation Name</label>
                    <input type="text" id="orgName" value="{org_name}" placeholder="e.g., Example Company IT">
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
                <h3>&#128260; Monitoring Schedule</h3>
                <p class="card-desc">Automatic background rescans of managed domains with drift detection alerts.</p>
                <div class="form-row">
                    <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                        <input type="checkbox" id="monitoringEnabled" {"checked" if monitoring_enabled else ""} style="width:18px;height:18px;">
                        Enable scheduled monitoring
                    </label>
                    <small>Disabled by default. Enable after adding domains you are authorised to monitor.</small>
                </div>
                <div class="form-row">
                    <label for="monitorInterval">Scan Interval</label>
                    <select id="monitorInterval">
                        <option value="6" {"selected" if interval == "6" else ""}>Every 6 hours</option>
                        <option value="12" {"selected" if interval == "12" else ""}>Every 12 hours</option>
                        <option value="24" {"selected" if interval == "24" else ""}>Every 24 hours (recommended)</option>
                        <option value="48" {"selected" if interval == "48" else ""}>Every 48 hours</option>
                        <option value="168" {"selected" if interval == "168" else ""}>Weekly</option>
                    </select>
                    <small>How often NorthFlux Security rescans your domains and checks for grade changes</small>
                </div>
                <div class="form-row" style="margin-top:16px;">
                    <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
                        <input type="checkbox" id="automaticRemediation" {"checked" if automatic_remediation else ""} style="width:18px;height:18px;">
                        Allow automatic DNS remediation
                    </label>
                    <small>Compatibility setting, disabled by default. Current generated recommendations require manual review and do not trigger DNS writes.</small>
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
                <h3>&#9729;&#65039; Cloudflare Integration {cf_badge}</h3>
                <p class="card-desc">
                    Cloudflare is optional for read-only scans. Configured credentials support connection checks and separately reviewed integrations, not automatic enforcement from generated recommendations.
                    Local-development credentials are stored in plaintext in the local database; production credentials come from the protected runtime environment.
                    Credentials are sent to Cloudflare over HTTPS to authenticate provider requests. A saved credential is not proof of access; Test Connection checks read access only, not write permission.
                </p>

                <!-- Token creation guide -->
                <details style="margin-bottom:20px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px 18px;">
                    <summary style="cursor:pointer;font-weight:600;font-size:0.88rem;color:var(--accent);">&#128214; How to create a Cloudflare API token</summary>
                    <div style="margin-top:12px;font-size:0.84rem;color:var(--text-secondary);line-height:1.7;">
                        <ol style="padding-left:18px;margin:8px 0;">
                            <li>Go to <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener" class="quick-link" style="display:inline;">dash.cloudflare.com/profile/api-tokens</a></li>
                            <li>Click <strong>Create Token</strong></li>
                            <li>Use <strong>Create Custom Token</strong> (not a template)</li>
                            <li>Add these permissions:
                                <div style="margin:8px 0 4px 0;">
                                    <span class="perm-tag" style="background:var(--success-bg);border-color:var(--success);color:var(--success);">Zone : DNS : Edit</span>
                                    <span style="font-size:0.75rem;color:var(--text-muted);margin:0 4px;">&#8212; Required for SPF, DMARC, DKIM, TLS-RPT, MTA-STS DNS</span>
                                </div>
                                <div style="margin:4px 0;">
                                    <span class="perm-tag" style="background:var(--success-bg);border-color:var(--success);color:var(--success);">Zone : Zone : Read</span>
                                    <span style="font-size:0.75rem;color:var(--text-muted);margin:0 4px;">&#8212; Required for zone verification</span>
                                </div>
                                <div style="margin:4px 0;">
                                    <span class="perm-tag" style="background:var(--warning-bg);border-color:var(--warning);color:var(--warning);">Account : Workers Scripts : Edit</span>
                                    <span style="font-size:0.75rem;color:var(--text-muted);margin:0 4px;">&#8212; Needed for MTA-STS HTTPS policy auto-hosting via Worker</span>
                                </div>
                            </li>
                            <li>Under <strong>Zone Resources</strong>, select your domain</li>
                            <li>Under <strong>Account Resources</strong>, select your account</li>
                            <li>Click <strong>Continue to summary</strong> &#8594; <strong>Create Token</strong></li>
                            <li>Copy the token and paste it below</li>
                        </ol>
                    </div>
                </details>

                <div class="settings-grid" style="margin-bottom:0;gap:16px;">
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfToken">API Token</label>
                        <div class="input-group">
                            <input type="password" id="cfToken" placeholder="{"Token configured" if cf_token_set else "Paste your Cloudflare API token"}" autocomplete="off" {credential_inputs_disabled}>
                            <button class="toggle-vis" onclick="toggleTokenVis()" title="Show/hide token" type="button" {credential_inputs_disabled}>&#128065;&#65039;</button>
                        </div>
                        {_cf_token_current}
                        <small>
                            <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener" class="quick-link">
                                &#128279; Create token on Cloudflare
                            </a>
                        </small>
                    </div>
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfZone">Zone ID</label>
                        <div class="input-group">
                            <input type="text" id="cfZone" value="{zone_id}" placeholder="32-character hex string" autocomplete="off">
                        </div>
                        <small>Cloudflare dashboard &#8594; your domain &#8594; Overview &#8594; right sidebar &#8594; Zone ID</small>
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
                            <input type="password" id="cfApiKey" placeholder="{"Key configured" if cf_api_key_set else "Only needed if Worker routes fail with your token"}" autocomplete="off" {credential_inputs_disabled}>
                        </div>
                        {_cf_apikey_current}
                        <small>Optional. Used only when your API token cannot create Cloudflare Worker routes.</small>
                    </div>
                    <div class="form-row" style="margin-bottom:0;">
                        <label for="cfEmail">Cloudflare Account Email <span style="color:var(--text-muted);font-weight:400;font-size:0.8rem;">(optional fallback)</span></label>
                        <div class="input-group">
                            <input type="email" id="cfEmail" value="{cf_email}" placeholder="Email used with the optional Global API Key" autocomplete="off" {credential_inputs_disabled}>
                        </div>
                        <small>Only needed if you also use the optional Global API Key.</small>
                    </div>
                </div>
                {_credential_guidance}
                <div class="btn-row" style="margin-top:16px;">
                    <button class="btn btn-secondary" onclick="testCloudflare()" style="padding:10px 20px;">&#129514; Test Connection</button>
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
                <h3>&#128230; Data &amp; Export</h3>
                <p class="card-desc">Download your scan data and settings for backup or migration.</p>
                <div class="btn-row" style="flex-direction:column;gap:10px;">
                    <button class="btn btn-secondary" onclick="exportSettings()" style="width:100%;text-align:left;padding:12px 16px;">
                        &#128203; Export Settings as JSON
                    </button>
                    <a href="/download/latest?kind=csv" class="btn btn-secondary" style="width:100%;text-align:left;padding:12px 16px;text-decoration:none;display:block;">
                        &#128202; Download Latest Scan CSV
                    </a>
                    <a href="/download/latest?kind=md" class="btn btn-secondary" style="width:100%;text-align:left;padding:12px 16px;text-decoration:none;display:block;">
                        &#128196; Download Latest Scan Markdown
                    </a>
                    <hr style="border-color:rgba(255,255,255,0.08);margin:8px 0;">
                    <button class="btn btn-secondary" onclick="clearAllData()" style="width:100%;text-align:left;padding:12px 16px;color:#ef4444;">
                        &#128465;&#65039; Clear All Scan Data
                    </button>
                </div>
                <div class="test-result" id="clearDataResult"></div>
            </div>

            <!-- System Info -->
            <div class="settings-card">
                <h3>&#8505;&#65039; System Information</h3>
                <p class="card-desc">NorthFlux Security instance details and module status.</p>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Version</div>
                        <div class="info-value">{PRODUCT_VERSION}</div>
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
                <button class="btn btn-primary" onclick="saveSettings()" style="padding:12px 28px;">&#128190; Save All Settings</button>
                <span class="save-status" id="saveStatus">&#10003; Settings saved</span>
            </div>
            <div style="color:var(--text-muted);font-size:0.8rem;">
                Changes take effect immediately
            </div>
        </div>

        {_footer_html()}
    </div>

    <script>
    function escapeHtml(value) {{
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }}

    function toggleTokenVis() {{
        const inp = document.getElementById('cfToken');
        const btn = inp.parentElement.querySelector('.toggle-vis');
        if (inp.type === 'password') {{
            inp.type = 'text';
            btn.textContent = '&#128274;';
            btn.title = 'Hide token';
        }} else {{
            inp.type = 'password';
            btn.textContent = '&#128065;\uFE0F';
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
            monitoring_enabled: document.getElementById('monitoringEnabled').checked ? 'true' : 'false',
            automatic_remediation: document.getElementById('automaticRemediation').checked ? 'true' : 'false',
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
                tokenInput.placeholder = 'Token saved \u2014 enter new value to change';
            }}
            if (apiKeyInput.value) {{
                apiKeyInput.value = '';
                apiKeyInput.placeholder = 'Key saved \u2014 enter new value to change';
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
        result.innerHTML = '<span style="opacity:0.7;">Testing connection&#8230;</span>';
        permBox.style.display = 'none';
        try {{
            const res = await fetch('/api/settings/test-cloudflare');
            const data = await res.json();
            if (data.ok) {{
                let info = '&#9989; <strong>Connected</strong> &#8212; Zone: <code>' + escapeHtml(data.zone_name) + '</code>';
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
                const tick = '<span style="color:var(--success);font-weight:700;">&#10003;</span>';
                const cross = '<span style="color:var(--danger);font-weight:700;">&#10007;</span>';
                let html = '';
                html += '<div>' + (p.zone_read ? tick : cross) + ' <span class="perm-tag">Zone : Zone : Read</span> Zone verification</div>';
                html += '<div>' + (p.dns_read ? tick : cross) + ' <span class="perm-tag">Zone : DNS : Read</span> DNS records readable; write permission not tested</div>';
                html += '<div>' + (p.workers ? tick : cross) + ' <span class="perm-tag">Account : Workers Scripts : Read</span> Script listing only; deployment not tested';
                if (!p.workers) {{
                    html += ' <span style="color:var(--warning);font-size:0.78rem;margin-left:6px;">&#8212; update your token to enable this</span>';
                }}
                html += '</div>';
                permList.innerHTML = html;

                if (data.features && data.features.length) {{
                    featList.innerHTML = '<strong>Read-only checks:</strong> ' + data.features.map(escapeHtml).join(', ');
                }} else {{
                    featList.innerHTML = 'No resource read access confirmed. Check token permissions in Cloudflare before applying changes.';
                }}
                permBox.style.display = 'block';
            }} else {{
                result.className = 'test-result fail';
                result.textContent = '❌ ' + data.message;
                permBox.style.display = 'none';
            }}
        }} catch(e) {{
            result.className = 'test-result fail';
            result.textContent = '❌ Connection failed: ' + e.message;
            permBox.style.display = 'none';
        }}
    }}

    async function exportSettings() {{
        try {{
            const res = await fetch('/api/settings');
            const data = await res.json();
            // Add export metadata
            data.exported_at = new Date().toISOString();
            data.version = '{PRODUCT_VERSION}';
            const blob = new Blob([JSON.stringify(data, null, 2)], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'northflux_settings_' + new Date().toISOString().slice(0,10) + '.json';
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
                result.textContent = '\\u2705 ' + data.message;
            }} else {{
                result.className = 'test-result fail';
                result.textContent = '\\u274c ' + (data.detail || 'Clear failed');
            }}
        }} catch(e) {{
            result.className = 'test-result fail';
            result.textContent = '\\u274c Error: ' + e.message;
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


@app.get("/assets/{asset_path:path}", include_in_schema=False)
def react_asset(asset_path: str):
    """Serve a fingerprinted React asset without allowing path traversal."""
    assets_root = (FRONTEND_DIST / "assets").resolve()
    candidate = (assets_root / asset_path).resolve()
    try:
        candidate.relative_to(assets_root)
    except ValueError:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not _react_frontend_available() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Asset not found")
    return FileResponse(
        candidate,
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.get("/{spa_path:path}", include_in_schema=False)
def react_spa_fallback(spa_path: str):
    """Return the SPA for browser deep links, never for API-like paths."""
    reserved = {
        "api", "download", "health", "ready", "docs", "redoc", "openapi.json"
    }
    first_segment = spa_path.split("/", 1)[0]
    if first_segment in reserved:
        raise HTTPException(status_code=404, detail="Not found")
    response = _spa_index_response()
    if response is None:
        raise HTTPException(status_code=404, detail="Not found")
    return response
