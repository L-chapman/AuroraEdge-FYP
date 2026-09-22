# NorthFlux Security architecture

NorthFlux Security is a single-instance FastAPI application with a React browser client, CLI, SQLite persistence, scheduled scanning, report generation, and an optional Cloudflare integration. The production container builds the frontend separately and runs only Python plus the compiled static assets.

## System context

```text
Operator browser                 Operator CLI
       |                              |
       v                              |
React single-page application         |
       |                              |
       +------ same-origin JSON ------+
                      |
                      v
          NorthFlux FastAPI application
              |         |          |
              v         v          v
          Public DNS  HTTPS/SMTP  SQLite
                                   |
                                   v
                        reports, alerts, settings

Optional authorised write path:
NorthFlux -> Cloudflare API -> verified DNS zone
```

The application reads public security signals for any valid domain. DNS writes require configured credentials, a successful Cloudflare connection, and confirmation that the requested domain belongs to the configured zone.

## Components

### `scanner.py`

Performs DNS, HTTPS, SMTP STARTTLS, and blocklist checks. It returns raw observations and avoids assigning business meaning to them.

### `rules.py`

Turns scanner observations into findings, severity, score, grade, explanations, and remediation recommendations. This separation allows the rules engine to be tested with deterministic inputs.

### `frontend/`

Contains the React 19 and TypeScript application built by Vite. React Router owns browser navigation; TanStack Query owns server-state refresh and invalidation; React Hook Form and Zod validate interactive forms. The application covers sign-in, overview, single and batch scanning, managed domains, domain detail and history, settings, DNS record generation, privacy, and error states.

The API client uses same-origin credentials, reads the non-HttpOnly CSRF companion cookie for state-changing requests, and converts server errors into a consistent UI error shape. It does not store the operator token in `localStorage` or `sessionStorage`.

### `dashboard.py` and `api_models.py`

`dashboard.py` hosts the FastAPI application, authentication, API and compatibility routes, scheduled monitoring, static-asset serving, and the deprecated server-rendered development fallback. `api_models.py` defines the typed `/api/v1` response models used by the React bootstrap and dashboard flows.

In production, or when `NORTHFLUX_SERVE_REACT=true`, FastAPI serves `frontend/dist/index.html`, fingerprinted files below `/assets`, and the SPA entry point for non-reserved deep links. API, download, health, readiness, and documentation paths are never swallowed by the SPA fallback. `NORTHFLUX_FRONTEND_DIST` can point to another compiled output directory.

The dashboard module is still the main architecture debt. The frontend extraction creates a stable API boundary, but the remaining server routes and services should continue to move into smaller routers and service modules behind the existing tests.

### `database.py`

Stores scans, results, managed domains, alerts, and settings in SQLite with WAL mode. NorthFlux uses `state/northflux.db` for new installations and detects the legacy `state/auroraedge.db` so an existing installation does not lose its history during the rename.

### `dns_fix.py`

Integrates with Cloudflare for authorised changes. The write layer checks zone ownership, selects TXT records by protocol prefix, refuses ambiguous duplicate records, retains existing DMARC tags when changing policy, and records actions in an audit log. DKIM changes require provider-supplied values and remain manual.

### `cli.py`

Provides single and batch scanning, report output, and explicit remediation commands for terminal workflows.

### `analysis.py`

Calculates aggregate statistics and generates report charts and summaries.

### `runtime_paths.py`

Centralises project-relative defaults and optional `NORTHFLUX_STATE_DIR`, `NORTHFLUX_REPORTS_DIR`, and `NORTHFLUX_LOGS_DIR` overrides. This lets containers, services, and tests isolate mutable state without changing the process working directory.

## Request flow

```text
browser route
    |
React request + session/CSRF handling
    |
FastAPI validation and authorisation
    |
scan public services -> evaluate rules -> optionally store result/report
    |
JSON response -> query cache -> accessible UI state
    |
optional, separately confirmed and authorised Cloudflare write
```

Viewing domain details is read-only. A scan is performed only through an explicit scan, rescan, or managed-domain onboarding request. A scan and managed-domain enrolment are separate choices, and DNS management requires a separate per-request opt-in in addition to the global setting.

## Runtime and persistence

The web application runs as one process with one worker. The background monitor lives inside that process, and SQLite is the shared persistence layer. Running multiple workers would create duplicate schedulers and independent in-process locks, so horizontal scaling is not supported by the current architecture.

Persistent paths and their environment overrides are:

- `state/` (`NORTHFLUX_STATE_DIR`) for SQLite
- `reports/` (`NORTHFLUX_REPORTS_DIR`) for generated evidence
- `logs/` (`NORTHFLUX_LOGS_DIR`) for application and DNS audit logs

Relative overrides remain project-relative; absolute overrides are supported. Docker Compose mounts all three paths and treats the rest of the container filesystem as read-only.

## Authentication

Local development may run without a token on loopback. Production mode requires a `DASH_TOKEN` of at least 32 characters at startup. Browser login creates a unique server-side session with a 12-hour expiry, an HttpOnly, Secure, SameSite session cookie, and per-session CSRF protection. Rotating `DASH_TOKEN` invalidates existing browser sessions. API clients can use a bearer token. Query-string token authentication is retained only for legacy local-development links and is disabled in production.

The React client first checks `/api/v1/auth/session`; login exchanges the configured token for the cookie session and logout revokes it. The shared-token design is suitable for a small single-operator deployment. Named users, password hashing, role-based access, and a persistent multi-worker session store are future requirements for multi-user use.

## Frontend delivery and browser policy

The official production image always compiles the frontend and copies only `frontend/dist` into the runtime image. Node.js, `node_modules`, source maps, test evidence, and frontend tooling are absent from that runtime. HTML is not cached; fingerprinted assets use long-lived immutable caching.

When the compiled React application is available, responses use a self-hosted Content Security Policy: scripts, styles, fonts, and API connections are restricted to the application origin; images are restricted to the application origin and `data:`; objects and frames are denied. The React application does not depend on external browser fonts, scripts, styles, analytics, or CDNs.

The deprecated server-rendered interface remains available as a development fallback and has a less restrictive policy because it still contains inline resources and a Chart.js CDN reference. It is not the supported production frontend. A source-based deployment must run `npm ci` and `npm run build` and either use production mode or set `NORTHFLUX_SERVE_REACT=true`.

## Safety boundaries

- Startup preserves scan history by default.
- Demo mode is an explicit environment setting and is unavailable in production.
- Scheduled monitoring is disabled by default.
- Automatic remediation is a separate explicit opt-in.
- Adding a managed domain performs a read-only scan; DNS management requires both the global setting and explicit opt-in on that request.
- Cloudflare writes are limited to the verified zone.
- Multiple same-protocol TXT records cause the write to stop for manual review.
- Production secrets are expected through the runtime environment.

## Refactor boundaries

The dashboard will be separated along behaviour already visible in the routes:

```text
src/app/
├── main.py
├── routers/
│   ├── auth.py
│   ├── scans.py
│   ├── domains.py
│   ├── settings.py
│   └── reports.py
├── services/
│   ├── monitoring.py
│   ├── remediation.py
│   └── reporting.py
```

The React migration has already separated presentation from server behaviour. The next extraction should isolate authentication and configuration, followed by monitoring and remediation. Legacy templates can then be retired after an agreed rollback window.

## Known constraints

- The FastAPI dashboard module remains monolithic even though the production UI is separate.
- Cloudflare secrets stored through the local-development settings page are plaintext in SQLite; production blocks secret updates through that API.
- The deprecated development fallback still needs inline resources and a third-party chart script; only the compiled React path has the strict self-hosted CSP.
- Scheduler leadership and database coordination support only one process.
- SQLite backup and schema migration tooling need further automation.
- Shared-token authentication has no named-user attribution or role-based access control.
- Automated browser tests use deterministic scans and intentionally disable Cloudflare, so live network availability and authorised DNS changes require separate controlled validation.
