# NorthFlux Security

NorthFlux Security is a self-hosted platform for assessing and improving a domain's email security posture. It checks SPF, DKIM, DMARC, MTA-STS, TLS-RPT, STARTTLS, MX routing, BIMI, and mail-server blocklists; explains weaknesses; tracks results; and can apply supported DNS changes through Cloudflare for authorised zones.

The current release is a tested self-hosted beta. The scanner and reporting workflows are mature, while authentication, deployment, operations, and code structure are being strengthened for long-running business use.

NorthFlux began as an independent home project under the **AuroraEdge** name and later became Leon Chapman's Belfast Metropolitan College final-year project. The current repository continues that work as a practical, maintained email security product.

## What it does

- Scans public DNS, HTTPS policy endpoints, and SMTP transport security.
- Scores each domain from 0–100 and assigns a grade with actionable findings.
- Stores scan history, managed domains, settings, and alerts in SQLite.
- Generates PDF, CSV, and Markdown reports.
- Supports scheduled monitoring and security-posture drift alerts.
- Generates recommended DNS records for common mail providers.
- Applies supported Cloudflare DNS fixes after ownership checks.
- Provides both a FastAPI dashboard and a command-line interface.

Safety-sensitive behaviour is opt-in. Adding a managed domain does not change DNS by default, scheduled monitoring is disabled by default, automatic remediation requires a separate setting, and production mode requires authentication.

## Technology

| Area | Implementation |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Frontend | Server-rendered HTML, CSS, and JavaScript |
| Storage | SQLite with WAL mode |
| Network checks | dnspython, Requests, sockets/TLS |
| Reports | ReportLab, Matplotlib, CSV, Markdown |
| Integration | Cloudflare API |
| Quality | pytest, GitHub Actions |
| Deployment | Windows launcher, manual Python setup, Docker Compose |

## Architecture

```text
Browser / CLI
      |
      v
FastAPI dashboard and API
      |
      +--> scanner.py ------> public DNS / HTTPS / SMTP
      +--> rules.py --------> findings, score, grade, remediation
      +--> database.py -----> SQLite state and history
      +--> dns_fix.py ------> authorised Cloudflare DNS changes
      +--> analysis.py -----> reports and charts
```

The current dashboard remains a large module and is the main maintainability target. Its routes, services, templates, styles, and scripts will be separated incrementally behind the existing test suite.

See [Architecture](docs/ARCHITECTURE.md) for the detailed component and data flow.

## Quick start on Windows

Requirements:

- Python 3.10 or newer
- Internet access for live DNS, HTTPS, and SMTP checks
- PowerShell or Command Prompt

Clone the repository and run the launcher:

```powershell
git clone https://github.com/L-chapman/AuroraEdge-FYP.git NorthFlux-Security
cd NorthFlux-Security
.\START.bat
```

The launcher creates a virtual environment, installs the declared dependencies, and opens the dashboard on an available local port between `8080` and `8085`.

Cloudflare credentials are optional. The launcher does not ask for or persist secrets. Supply them through environment variables or configure them from the authenticated settings page during local development.

## Manual development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

For an authenticated local instance:

```powershell
$env:DASH_TOKEN = "use-a-random-value-at-least-32-characters-long"
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

The browser redirects to `/login` and exchanges the configured token for an HttpOnly session cookie. API clients may use `Authorization: Bearer <token>`.

## Docker Compose

Create a local `.env` file for Compose with at least a long random dashboard token:

```dotenv
DASH_TOKEN=replace-with-a-random-value-at-least-32-characters
```

Then build and start the service:

```powershell
docker compose up --build -d
```

The Compose service binds to `127.0.0.1:8080`, persists state, reports, and logs in Docker-managed volumes, runs as a non-root user, and checks `/ready`. Put a TLS reverse proxy in front before exposing the service beyond the host.

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
| `DASH_TOKEN` | Dashboard and API access token | Required in production; use a random secret of at least 32 characters |
| `NORTHFLUX_PUBLIC_ORIGIN` | Canonical browser origin for CSRF validation | Set to the external HTTPS origin when proxy headers are unavailable |
| `NORTHFLUX_LOG_LEVEL` | Log verbosity | `INFO` is the normal default |
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
- Production mode expects Cloudflare secrets from the runtime environment rather than the settings API.
- Cloudflare changes are restricted to the configured and verified zone and recorded in the audit log.

The controlled legacy demo domain is `auroraedge.co.uk`. Its name is retained because it is an external DNS zone; it should only be reset or remediated using the authorised demo workflow.

## Verification

The current baseline is:

```text
412 passed, 0 failed
Python 3.12.10
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

Tests cover the rules engine, scanner fallbacks, SPF recursion, database behaviour, API routes, authentication, Cloudflare ownership enforcement, input validation, XSS, SQL injection, path traversal, security headers, stress cases, and remediation logic.

## Project structure

```text
.
├── src/app/                 Application code
├── tests/                   Automated test suite
├── docs/                    Architecture, deployment, operations, and history
├── scripts/                 Demo, experiment, and packaging tools
├── reports/                 Generated report output
├── state/                   Local SQLite state (runtime)
├── logs/                    Runtime and audit logs
├── Dockerfile
├── compose.yaml
├── START.bat
└── verify_system.py
```

## Security and scope

NorthFlux reads public DNS and public-facing transport information. DNS remediation is restricted to explicitly configured Cloudflare zones. Operators remain responsible for obtaining authorisation and reviewing proposed changes before enabling automatic remediation.

Do not expose the development server directly to the public Internet. Use production mode, a long authentication token, HTTPS at a reverse proxy, protected environment secrets, restricted network access, and tested backups.

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
