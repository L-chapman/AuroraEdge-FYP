# NorthFlux Security architecture

NorthFlux Security is a single-instance FastAPI application with a browser dashboard, CLI, SQLite persistence, scheduled scanning, report generation, and an optional Cloudflare integration.

## System context

```text
Operator browser / CLI
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

### `dashboard.py`

Hosts the FastAPI application, routes, authentication, scheduled monitoring, server-rendered HTML, CSS, and JavaScript. At more than 6,000 lines it is the primary architecture debt. It will be split incrementally into routers, services, templates, and static assets while route behaviour remains protected by tests.

### `database.py`

Stores scans, results, managed domains, alerts, and settings in SQLite with WAL mode. NorthFlux uses `state/northflux.db` for new installations and detects the legacy `state/auroraedge.db` so an existing installation does not lose its history during the rename.

### `dns_fix.py`

Integrates with Cloudflare for authorised changes. The write layer checks zone ownership, selects TXT records by protocol prefix, refuses ambiguous duplicate records, retains existing DMARC tags when changing policy, and records actions in an audit log. DKIM changes require provider-supplied values and remain manual.

### `cli.py`

Provides single and batch scanning, report output, and explicit remediation commands for terminal workflows.

### `analysis.py`

Calculates aggregate statistics and generates report charts and summaries.

## Request flow

```text
input domain
    |
validate and normalise
    |
scan public services
    |
evaluate rules
    |
store result and emit report
    |
display findings and proposed actions
    |
optional explicit, authorised Cloudflare write
```

## Runtime and persistence

The web application runs as one process with one worker. The background monitor lives inside that process, and SQLite is the shared persistence layer. Running multiple workers would create duplicate schedulers and independent in-process locks, so horizontal scaling is not supported by the current architecture.

Persistent paths are:

- `state/` for SQLite
- `reports/` for generated evidence
- `logs/` for application and DNS audit logs

Docker Compose mounts all three paths and treats the container filesystem as read-only.

## Authentication

Local development may run without a token on loopback. Production mode requires a `DASH_TOKEN` of at least 32 characters at startup. Browser login creates a unique server-side session with a 12-hour expiry, an HttpOnly, Secure, SameSite session cookie, and per-session CSRF protection. Rotating `DASH_TOKEN` invalidates existing browser sessions. API clients can use a bearer token. Query-string token authentication is retained only for legacy local-development links and is disabled in production.

The shared-token design is suitable for a small single-operator deployment. Named users, password hashing, role-based access, and a persistent multi-worker session store are future requirements for multi-user use.

## Safety boundaries

- Startup preserves scan history by default.
- Demo mode is an explicit environment setting and is unavailable in production.
- Scheduled monitoring is disabled by default.
- Automatic remediation is a separate explicit opt-in.
- Adding a managed domain performs a read-only scan unless automatic remediation is enabled.
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
├── templates/
└── static/
```

The first extraction should isolate authentication and configuration, followed by monitoring and remediation. Templates and static assets can then move without mixing that change with business logic.

## Known constraints

- The dashboard module remains monolithic.
- Cloudflare secrets stored through the local-development settings page are plaintext in SQLite; production blocks secret updates through that API.
- The Content Security Policy still permits inline scripts and styles until templates and assets are extracted.
- Scheduler leadership and database coordination support only one process.
- SQLite backup and schema migration tooling need further automation.
