# NorthFlux Security

NorthFlux Security is a self-hosted platform for assessing and improving a domain's email security posture. It checks SPF, DKIM, DMARC, MTA-STS, TLS-RPT, STARTTLS, MX routing, BIMI, and mail-server blocklists; explains weaknesses; tracks results; and can apply supported DNS changes through Cloudflare for authorised zones.

The current release is a tested, single-operator self-hosted release candidate. Its browser experience is a React and TypeScript application backed by FastAPI JSON APIs. NorthFlux still has the operational limits documented below, so deployment owners should validate it against their own availability, retention, and change-control requirements before relying on it.

NorthFlux began as an independent home project under the **AuroraEdge** name and later became Leon Chapman's Belfast Metropolitan College final-year project. The current repository continues that work as a practical, maintained email security product.

## What it does

- Scans public DNS, HTTPS policy endpoints, and SMTP transport security.
- Scores each domain from 0–100 and assigns a grade with actionable findings.
- Stores scan history, managed domains, settings, and alerts in SQLite.
- Generates PDF, CSV, and Markdown reports.
- Supports scheduled monitoring and security-posture drift alerts.
- Builds draft DNS records from operator-provided settings, with examples for common mail providers.
- Applies supported Cloudflare DNS fixes after ownership checks.
- Provides a responsive React dashboard and a command-line interface.

Safety-sensitive behaviour is opt-in. Adding a managed domain does not change DNS by default, scheduled monitoring is disabled by default, automatic remediation requires a separate setting, and production mode requires authentication.

## Technology

| Area | Implementation |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Frontend | React 19, TypeScript, Vite, React Router, TanStack Query |
| Storage | SQLite with WAL mode |
| Network checks | dnspython, Requests, sockets/TLS |
| Reports | ReportLab, Matplotlib, CSV, Markdown |
| Integration | Cloudflare API |
| Quality | pytest, Vitest, Testing Library, Playwright, axe-core, GitHub Actions |
| Deployment | Windows launcher, manual Python setup, Docker Compose |

## Architecture

```text
React browser app ----> FastAPI JSON API
                              |
CLI --------------------------+
                              |
                              +--> scanner.py ------> public DNS / HTTPS / SMTP
                              +--> rules.py --------> findings, score, grade, remediation
                              +--> database.py -----> SQLite state and history
                              +--> dns_fix.py ------> authorised Cloudflare DNS changes
                              +--> analysis.py -----> reports and charts
```

FastAPI serves the compiled single-page application and its fingerprinted local assets in production. Authentication, CSRF enforcement, scanning, persistence, reporting, scheduling, and optional remediation remain server-side. A deprecated server-rendered interface remains available only as a development fallback while backend routes are separated from the large `dashboard.py` module.

See [Architecture](docs/ARCHITECTURE.md) for the detailed component and data flow.

## Quick start with Docker

Requirements:

- Docker Engine with Compose v2
- Internet access for live DNS, HTTPS, and SMTP checks

Clone the repository, create an untracked `.env`, and start the hardened single-instance service:

```powershell
git clone https://github.com/L-chapman/AuroraEdge-FYP.git NorthFlux-Security
cd NorthFlux-Security
@'
DASH_TOKEN=replace-with-a-random-value-at-least-32-characters
NORTHFLUX_PUBLIC_ORIGIN=https://security.example.com
'@ | Set-Content .env
docker compose up --build -d
```

Replace the example token and origin before starting. The image builds the React application in a Node stage, copies only the compiled assets into the non-root Python runtime, and checks `/ready`. The loopback URL `http://127.0.0.1:8080/health` is suitable for a host-side health check, but production sign-in uses a `Secure` session cookie and therefore requires an HTTPS reverse proxy. Open the configured external HTTPS origin rather than the loopback HTTP port. See [Deployment](docs/DEPLOYMENT.md) for a complete production path.

Cloudflare credentials are optional. Supply production credentials through protected environment or secret-manager configuration; do not commit them or place them in the frontend build.

## Manual development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
$env:NORTHFLUX_SERVE_REACT = "true"

Push-Location frontend
npm ci
npm run build
Pop-Location

python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

Manual React development requires Node.js 22.12 or newer. Run FastAPI on port `8000`, then run `npm run dev` in `frontend/`; Vite serves on `127.0.0.1:5173` and proxies application requests to FastAPI. On Windows, `START.bat` creates the Python environment, installs locked frontend dependencies when needed, builds the React application, and starts the local dashboard.

For an authenticated local instance:

```powershell
$env:DASH_TOKEN = "use-a-random-value-at-least-32-characters-long"
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

The browser redirects to `/login` and exchanges the configured token for an HttpOnly session cookie. API clients may use `Authorization: Bearer <token>`.

## Docker Compose

The Compose service binds to `127.0.0.1:8080`, persists state, reports, and logs in Docker-managed volumes, runs as a non-root user with a read-only root filesystem, and checks `/ready`. Put a TLS reverse proxy in front before exposing the service beyond the host.

See [Deployment](docs/DEPLOYMENT.md) for production-mode configuration, backups, reverse-proxy expectations, and rollback guidance.

## Command line

With the virtual environment active and `PYTHONPATH` set to `src`:

```powershell
# Scan one domain
python -m app.cli --domain example.com

# Include remediation guidance
python -m app.cli --domain example.com --remediation

# Scan a file of domains
python -m app.cli --domains domains.txt
```

`--apply-fix` can change DNS. Use it only for a domain you own or are explicitly authorised to manage, and configure Cloudflare credentials first.

## Configuration

| Variable | Purpose | Production guidance |
|---|---|---|
| `NORTHFLUX_ENV` | Runtime mode | Set to `production` outside local development |
| `NORTHFLUX_PORT` | Host port published by the standard Compose deployment | Defaults to `8080`; the container still listens on `8080` |
| `DASH_TOKEN` | Dashboard and API access token | Required in production; use a random secret of at least 32 characters |
| `NORTHFLUX_PUBLIC_ORIGIN` | Canonical browser origin for CSRF validation | Set to the external HTTPS origin when proxy headers are unavailable |
| `NORTHFLUX_LOG_LEVEL` | Log verbosity | `INFO` is the normal default |
| `NORTHFLUX_STATE_DIR` | SQLite state directory | Defaults to `state/`; point it at persistent private storage |
| `NORTHFLUX_REPORTS_DIR` | Generated report directory | Defaults to `reports/`; point it at persistent private storage |
| `NORTHFLUX_LOGS_DIR` | Runtime and DNS audit log directory | Defaults to `logs/`; point it at persistent private storage |
| `NORTHFLUX_SERVE_REACT` | Enable the compiled React application | Defaults to enabled in production; set `true` for a source-based development build |
| `NORTHFLUX_FRONTEND_DIST` | Compiled Vite output directory | Defaults to `frontend/dist`; normally leave unchanged |
| `CF_API_TOKEN` | Cloudflare scoped API token | Use a secret manager or protected service environment |
| `CF_ZONE_ID` | Authorised Cloudflare zone | Required for DNS remediation |
| `CF_ACCOUNT_ID` | Cloudflare account | Required for Worker deployment |
| `CF_API_KEY` / `CF_EMAIL` | Legacy Cloudflare authentication | Avoid unless a required operation cannot use an API token |

The legacy `AURORAEDGE_LOG_LEVEL` variable is accepted for one compatibility release. The application does not automatically load `.env` files; Compose loads its own `.env`, while manual and service deployments should provide environment variables through the operating system or service manager.

## Safe operating defaults

- Scan history is preserved across restarts.
- Demo mode is disabled unless `NORTHFLUX_DEMO_MODE=true` is supplied.
- Scheduled monitoring is disabled until enabled in Settings.
- Automatic remediation is disabled independently of monitoring.
- Production mode refuses to start without a `DASH_TOKEN` of at least 32 characters.
- Production mode refuses to start without a compiled React application.
- Production mode expects Cloudflare secrets from the runtime environment rather than the settings API.
- Cloudflare changes are restricted to the configured and verified zone and recorded in the audit log.
- The supported production image contains only locally built frontend assets. Its CSP permits scripts, styles, fonts, images, and API connections from the application origin (plus `data:` images), not third-party frontend CDNs.

The controlled legacy demo domain is `auroraedge.co.uk`. Its name is retained because it is an external DNS zone; it should only be reset or remediated using the authorised demo workflow.

## Verification

The current deterministic test baseline is:

```text
439 Python tests passed
57 frontend unit/component tests passed
```

Run the full suite:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m pytest -q
```

Run the offline system smoke test:

```powershell
python verify_system.py --offline
```

Run the frontend checks and production build:

```powershell
Push-Location frontend
npm ci
npm run typecheck
npm run lint
npm run test:coverage
npm run build
Pop-Location
```

The Playwright suite covers nine operator journeys in desktop Chromium, Firefox, WebKit, and a Pixel 7 mobile profile. It starts a disposable FastAPI instance with deterministic scans and no Cloudflare integration:

```powershell
Push-Location frontend
npx playwright install chromium firefox webkit
npm run test:e2e
Pop-Location
```

Tests cover the rules engine, scanner fallbacks, SPF recursion, database behaviour, API routes, authentication, Cloudflare ownership enforcement, input validation, XSS, SQL injection, path traversal, security headers, stress cases, remediation logic, responsive navigation, accessibility checks, and the principal operator workflows. Deterministic tests do not prove availability of external DNS, SMTP, HTTPS, or Cloudflare services.

## Project structure

```text
.
├── src/app/                 Application code
├── frontend/                React/TypeScript application and browser tests
├── tests/                   Automated test suite
├── docs/                    Architecture, deployment, operations, and history
├── scripts/                 Demo, experiment, and packaging tools
├── reports/                 Generated report output (runtime, not committed)
├── state/                   Local SQLite state (runtime, not committed)
├── logs/                    Runtime and audit logs (runtime, not committed)
├── Dockerfile
├── compose.yaml
├── START.bat
└── verify_system.py
```

## Security and scope

NorthFlux reads public DNS and public-facing transport information. DNS remediation is restricted to explicitly configured Cloudflare zones. Operators remain responsible for obtaining authorisation and reviewing proposed changes before enabling automatic remediation.

Do not expose the development server directly to the public Internet. Use production mode, a long authentication token, HTTPS at a reverse proxy, protected environment secrets, restricted network access, and tested backups. The current shared-token, single-worker, SQLite design is intended for a small single-operator deployment; it is not a multi-tenant identity or horizontally scaled service.

See [Security policy](SECURITY.md) and [Privacy and data handling](docs/PRIVACY.md).

## Documentation

- [Documentation index](docs/INDEX.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Testing guide](docs/TESTING.md)
- [Integrations](docs/INTEGRATIONS.md)
- [Privacy and operating boundaries](docs/PRIVACY.md)
- [Historical academic material](docs/academic/README.md)

## Project status and licence

NorthFlux Security is a personal, non-commercial project under active development. It has no claimed commercial customers or production users. The source is publicly viewable, but no open-source licence has been selected yet; normal copyright restrictions therefore apply.
