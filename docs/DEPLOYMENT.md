# NorthFlux Security deployment

This guide covers two different needs: trying NorthFlux on your own computer, and keeping it running as a private service. A local launch does not make a server safe to expose to the Internet.

For a lasting installation, the supported design is one Docker container for one operator, using a shared access token rather than individual accounts and roles. NorthFlux runs scheduled checks inside the application and stores its data in a local SQLite database. Run exactly one application worker and one container against the same stored data; multiple copies are not supported.

This guide is an installation and validation procedure, not a claim that your server has been deployed or tested. The [release evidence](RELEASE_EVIDENCE.md) identifies revision-specific checks; the [function audit](FUNCTION_AUDIT.md) and [deep-debug review](DEEP_DEBUG_REVIEW.md) preserve earlier reviews. Live production and Cloudflare changes require separate, authorised validation.

## Try it on Windows or Linux

Install Python 3.10 or newer and Node.js 22.12 or newer, including npm. Linux also needs Python's `venv` support, often supplied by the distribution's `python3-venv` package. You need Internet access for the first dependency installation and live domain checks, and a writable project folder. A minimum version is not a claim that every newer version or operating system has been tested; see [Testing](TESTING.md) for the evidence.

From the downloaded or cloned project folder:

```powershell
# Windows PowerShell
.\START.bat
```

```bash
# Linux
sh ./start.sh
```

The launcher prepares a private Python environment, installs the declared dependencies, builds the React interface, and starts the local service. Stop it with Ctrl+C. Files created during setup and use are kept out of Git. The local launch has no sign-in requirement unless you supply `DASH_TOKEN`; use it only on your own trusted computer.

Before reusing setup, it compares the installed Python package inventory with the last successful setup and checks the frontend dependency tree. Missing or changed packages trigger preparation again; Python imports and dependency consistency are checked before a new setup is accepted. This catches common damaged-environment problems, but it is not a malware scan or a complete Python dependency lock. The interface is rebuilt on every launch so a source update does not leave the old UI running.

For a machine without a desktop browser, use `python start.py --no-browser --port 8080` (or `python3` on Linux). `--setup-only` installs and builds without starting the server. `--smoke-test` starts a short, isolated check of the built interface and storage readiness, with temporary data and Cloudflare credentials removed, then stops. These are local review tools, not a production service manager. Inherited production mode is rejected by the ordinary local launcher; use the production setup below instead.

The local application is reached at `http://127.0.0.1:8080`; it is not available to other computers. If the port is already in use, choose another with `--port`, rather than stopping an unrelated program. If Python, Node, or npm cannot be found, reopen the terminal after installing them. An interrupted package download can normally be retried by rerunning the launcher. If a `.venv` came from another operating system or is broken, follow the launcher's advice to rename it as a backup before trying again. Do not disable firewall, certificate, or security checks to make installation succeed.

For a fictional presentation instead of live domain checks, use the [isolated browser showcase](screenshots/README.md). It is a local development harness, not a production deployment or a service to expose publicly. The retired DNS-reset scripts are no longer included.

## Production prerequisites

- Docker Engine with Compose v2
- A private host or VM with persistent storage
- An HTTPS reverse proxy for access beyond the same computer (a trusted front-end service that handles encrypted browser connections)
- A long random dashboard token
- Optional least-privilege Cloudflare credentials for provider reads or separately reviewed integrations

The Docker build prepares the React interface in a separate build stage. Node.js is not required on the deployment host and is not present in the final image. Docker must be configured to run Linux containers, including on Windows. A source-based deployment without Docker additionally requires Node.js 22.12 or newer to create `frontend/dist`.

### Outbound scan access

The scanner queries public DNS and connects only to checked public addresses for MTA-STS HTTPS and optional SMTP STARTTLS probes. Private, loopback and special-purpose destinations are rejected, including hostnames that mix public and private answers. Connections use the checked address rather than resolving the hostname again at connection time.

Scan work has time limits. MTA-STS policies must be a small plain-text HTTPS response with a valid server certificate; redirects are not followed and the scan fetch does not inherit HTTP proxy environment settings. SMTP STARTTLS checks observe transport capability and negotiated encryption, not certificate identity or successful mail delivery. Internal-only mail systems and networks that require an outbound HTTP proxy are not supported by these direct scan probes.

If DNS, HTTPS or SMTP access is blocked, expect an **Incomplete** warning and no saved grade. Resolve the network restriction or review the domain manually; do not weaken the address or certificate checks. A retry that completes is still a configuration assessment, not proof of every email-security property.

## Configure

Create `.env` beside `compose.yaml`:

```dotenv
DASH_TOKEN=replace-with-a-random-value-at-least-32-characters
NORTHFLUX_PORT=8080
NORTHFLUX_LOG_LEVEL=INFO
# Set this when the reverse proxy does not preserve the external origin:
# NORTHFLUX_PUBLIC_ORIGIN=https://security.example.com
```

Generate a token with a password manager or a cryptographically secure tool. Do not commit `.env`.

If a Cloudflare connection is required, supply a scoped API token and zone ID through the host's protected service environment or secret manager. Current generated recommendations require manual review and do not trigger writes, even when the retained automatic-remediation setting is enabled. Compose variable support is provided for a small private deployment, but environment variables may be visible to host administrators and container-inspection commands.

## Start

```bash
docker compose up --build -d
docker compose ps
```

The service listens on `127.0.0.1:8080` by default. Its liveness endpoint is `/health`; `/ready` also checks SQLite and writable runtime directories. Production mode requires the compiled React application and fails closed at startup when it is missing. The image contains `frontend/dist`, but not Node.js, `node_modules`, source maps, test output, or frontend build tooling.

If deploying from a source checkout instead of the image, prepare both the Python environment and the interface first. This Linux example starts the service using that prepared environment, not the system Python:

```bash
python3 start.py --setup-only
NORTHFLUX_ENV=production \
DASH_TOKEN='replace-with-a-random-value-at-least-32-characters' \
PYTHONPATH=src \
.venv/bin/python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080 --workers 1
```

`NORTHFLUX_FRONTEND_DIST` may point to a different compiled Vite directory. `NORTHFLUX_SERVE_REACT` defaults to true in production and must be set to true when testing the production UI in development mode. Never place runtime secrets in Vite variables or frontend source: the compiled bundle is public to every authenticated or unauthenticated browser that can request its assets.

## Reverse proxy

Use Nginx, Caddy, Traefik, or an equivalent trusted proxy to provide HTTPS. Forward to `http://127.0.0.1:8080`, retain the original host and forwarding headers, and restrict direct access to the application port. The exact proxy and certificate setup depends on the host and domain; it is not included in the local launcher.

The production login cookie is marked `Secure`, so browser access must use HTTPS. NorthFlux checks the browser `Origin` and a per-session CSRF token on state-changing cookie-authenticated requests. Preserve `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto`, or set `NORTHFLUX_PUBLIC_ORIGIN` to the exact external HTTPS origin. Do not expose Uvicorn directly to the Internet.

Interactive API documentation and the OpenAPI document are disabled in production mode. Use a development instance on a trusted workstation when route exploration is required.

The compiled frontend is self-contained and does not load third-party scripts, styles, fonts, analytics, or CDNs in the browser. Its Content Security Policy restricts scripts, styles, fonts, and network connections to the application origin, permits only same-origin and `data:` images, and denies objects and framing. Do not relax this policy at the reverse proxy. HTML responses are not cached; fingerprinted `/assets` files use immutable caching.

Production Cloudflare secrets are read only from the runtime environment. During an upgrade, when a replacement environment value is present, NorthFlux removes the matching legacy plaintext token, global API key, or account email from the SQLite settings table. Back up the database before the first production migration.

## Persistent data

The Compose file uses Docker-managed volumes rather than host-folder ownership assumptions. These are persistent storage areas managed by Docker:

| Volume | Container path | Contents |
|---|---|---|
| `northflux-state` | `/app/state` | SQLite database and WAL files |
| `northflux-reports` | `/app/reports` | Generated CSV, Markdown, PDF, and chart output |
| `northflux-logs` | `/app/logs` | Application and DNS audit logs |

Non-Compose service deployments can place these paths elsewhere with `NORTHFLUX_STATE_DIR`, `NORTHFLUX_REPORTS_DIR`, and `NORTHFLUX_LOGS_DIR`. Relative values resolve from the project root; absolute values are recommended in service definitions. All three locations must be writable by the NorthFlux process and protected from other users.

Back up the three volumes together while the application container is stopped. Run the example below in a Linux shell on the Docker host. It writes the archive to a host `backups/` directory and does not modify the volumes:

```bash
mkdir -p backups
docker compose stop
docker run --rm \
  --volumes-from northflux-security:ro \
  --mount type=bind,src="$PWD/backups",dst=/backup \
  alpine:3.22 \
  tar -czf /backup/northflux-backup.tar.gz -C /app state reports logs
docker compose start
```

Keep the archive encrypted and access-controlled because it may contain domain metadata, public reporting addresses, and operational history. Test restoration into separate volumes before relying on the backup. `docker compose down` preserves the named volumes; do not add `--volumes` unless permanent data removal is explicitly intended.

If upgrading from an earlier bind-mount deployment, stop the old container, back up `state/`, `reports/`, and `logs/`, then copy that data into the named volumes before starting the React migration release. Do not point two containers at the same SQLite database.

## Updates and rollback

Before updating:

1. Record the running Git revision or image tag.
2. Back up persistent data.
3. Build and run backend, frontend, browser, and container tests for the target revision.
4. Build an immutable image tag rather than replacing the only known-good tag.
5. Rebuild and restart the single container.
6. Confirm `/health`, `/ready`, sign-in, the strict CSP, and React deep-link navigation, then perform a read-only domain scan.

The React migration does not require a separate frontend data store: the UI consumes the existing FastAPI-backed SQLite data. To roll back, stop the service, deploy the previously recorded image or revision against the backed-up volumes, and verify readiness and sign-in. Restore the backup only if the older application cannot safely read the upgraded data; restoring unnecessarily discards newer scans and settings.

The deep-debug update adds incomplete-scan flags without deleting existing rows. New incomplete scans keep their observations but have no stored score or grade and are excluded from score averages. Older rows retain their original results because earlier versions did not record this distinction; the migration does not revalidate them. Run fresh scans before relying on old evidence. An older application may not understand the new warnings, so verify rollback behaviour on a separate copy first.

The deprecated server-rendered interface remains available only when development mode leaves `NORTHFLUX_SERVE_REACT` disabled. It retains inline resources and a third-party chart dependency and is not available as a production rollback strategy; roll back to a tested image instead.

## Safe remediation rollout

Monitoring is disabled by default. Current generated DNS recommendations are manual-review only. Older stored remediation preferences remain for compatibility, but the current interface does not offer them as active automation. Recommended rollout:

1. Add one domain you own or are explicitly authorised to manage.
2. Run read-only scans and review the proposed records.
3. Confirm the configured Cloudflare zone and the token's permissions in Cloudflare. NorthFlux's connection test reads data; it does not prove DNS write permission.
4. Confirm provider-specific values, sender coverage and mail-server readiness before testing a manual fix on a controlled record.
5. Verify both provider state and actual mail behaviour, and keep a tested recovery path.
6. Enable read-only monitoring if required. A retained legacy remediation flag does not make current recommendations automatic.

An incomplete scan never authorises an automatic fix. Failed or ambiguous prerequisite DNS reads also stop a proposed change. New SPF records require an operator-confirmed list of sending services; NorthFlux does not assume a mail provider. DKIM remains manual because provider-specific selector targets and public keys cannot be inferred safely from MX records alone.

The automated suite does not perform live DNS writes or deploy MTA-STS Workers. The guarded low-level methods are retained for separately reviewed integrations, not the generated-recommendation workflow. Use a controlled zone and an approved rollback plan for any such checks, and inspect both the provider state and the audit log afterwards. See [Integrations](INTEGRATIONS.md) for credential scope and deployment limits.

Monitoring alerts are shown inside NorthFlux; outbound email and webhook notifications are not implemented. A legacy saved email address is not a delivery configuration. The active dashboard refreshes saved data every 60 seconds; that display refresh is separate from the configured monitoring interval and does not launch scans.

## Configuration reference

Environment variables are settings supplied to the running application. Keep secret values in the protected service configuration, not in source code. Compose reads its own `.env` file; the Python application and local launcher do not automatically read `.env` during a manual launch.

| Variable | What it controls | Guidance |
|---|---|---|
| `NORTHFLUX_ENV` | Local or production mode | Use `production` for a lasting server installation |
| `NORTHFLUX_PORT` | Host port for Compose or the local launcher | Defaults to `8080`; the container still listens on `8080`. The launcher also accepts `--port`. |
| `DASH_TOKEN` | Secret used to sign in and access the API | Required in production; use a random value of at least 32 characters |
| `NORTHFLUX_PUBLIC_ORIGIN` | Public browser address used by anti-forgery checks | Set to the exact external HTTPS origin if the proxy cannot supply it |
| `NORTHFLUX_LOG_LEVEL` | How much detail is logged | `INFO` is the normal default |
| `NORTHFLUX_STATE_DIR` | Database folder | Defaults to `state/`; use private, persistent storage |
| `NORTHFLUX_REPORTS_DIR` | Generated report folder | Defaults to `reports/`; use private, persistent storage |
| `NORTHFLUX_LOGS_DIR` | Application and DNS audit log folder | Defaults to `logs/`; use private, persistent storage |
| `NORTHFLUX_SERVE_REACT` | Whether to serve the compiled React interface | Enabled automatically in production and by the local launcher |
| `NORTHFLUX_FRONTEND_DIST` | Location of the compiled interface | Defaults to `frontend/dist`; normally leave unchanged |
| `NORTHFLUX_DEMO_MODE` | Legacy demonstration behaviour | Disabled by default and unavailable in production; not needed for normal setup |
| `CF_API_TOKEN` | Scoped Cloudflare credential | Use a secret manager or protected service environment; optional for read-only scans |
| `CF_ZONE_ID` | Cloudflare zone authorised for changes | Required for DNS fixes |
| `CF_ACCOUNT_ID` | Cloudflare account | Required for Worker deployment |
| `CF_API_KEY` / `CF_EMAIL` | Legacy Cloudflare sign-in method | Prefer a scoped API token |
| `NORTHFLUX_PYTHON` | Python executable used by the launch wrappers and browser tests | Optional; use an exact executable path, without surrounding quotes or extra arguments. Paths containing spaces are supported. |

The old `AURORAEDGE_LOG_LEVEL` setting is retained for compatibility. Absolute storage paths are recommended in service definitions. Restart the service after changing environment settings, and do not pass secret values in a public screenshot or bug report.
