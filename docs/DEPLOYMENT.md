# NorthFlux Security deployment

This guide describes the supported single-instance Docker deployment. NorthFlux currently embeds its scheduler and uses SQLite, so run exactly one application worker and one container against a given state volume.

## Prerequisites

- Docker Engine with Compose v2
- A private host or VM with persistent storage
- A TLS reverse proxy for any access beyond localhost
- A long random dashboard token
- Optional least-privilege Cloudflare credentials for authorised remediation

The supported Docker build compiles the React application in an isolated Node.js stage. Node.js is not required on the deployment host and is not present in the final image. A source-based deployment without Docker additionally requires Node.js 22.12 or newer to create `frontend/dist`.

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

If remediation is required, supply a scoped Cloudflare API token and zone ID through the host's protected service environment or secret manager. Compose variable support is provided for a small private deployment, but environment variables may be visible to host administrators and container-inspection commands.

## Start

```bash
docker compose up --build -d
docker compose ps
```

The service listens on `127.0.0.1:8080` by default. Its liveness endpoint is `/health`; `/ready` also checks SQLite and writable runtime directories. Production mode requires the compiled React application and fails closed at startup when it is missing. The image contains `frontend/dist`, but not Node.js, `node_modules`, source maps, test output, or frontend build tooling.

If deploying from a source checkout instead of the image, build the frontend before starting FastAPI:

```bash
cd frontend
npm ci
npm run build
cd ..
NORTHFLUX_ENV=production \
DASH_TOKEN='replace-with-a-random-value-at-least-32-characters' \
PYTHONPATH=src \
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080 --workers 1
```

`NORTHFLUX_FRONTEND_DIST` may point to a different compiled Vite directory. `NORTHFLUX_SERVE_REACT` defaults to true in production and must be set to true when testing the production UI in development mode. Never place runtime secrets in Vite variables or frontend source: the compiled bundle is public to every authenticated or unauthenticated browser that can request its assets.

## Reverse proxy

Terminate HTTPS at Nginx, Caddy, Traefik, or an equivalent trusted proxy. Forward to `http://127.0.0.1:8080`, retain the original host and forwarding headers, and restrict direct access to the application port.

The production login cookie is marked `Secure`, so browser access must use HTTPS. NorthFlux checks the browser `Origin` and a per-session CSRF token on state-changing cookie-authenticated requests. Preserve `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto`, or set `NORTHFLUX_PUBLIC_ORIGIN` to the exact external HTTPS origin. Do not expose Uvicorn directly to the Internet.

Interactive API documentation and the OpenAPI document are disabled in production mode. Use a development instance on a trusted workstation when route exploration is required.

The compiled frontend is self-contained and does not load third-party scripts, styles, fonts, analytics, or CDNs in the browser. Its Content Security Policy restricts scripts, styles, fonts, and network connections to the application origin, permits only same-origin and `data:` images, and denies objects and framing. Do not relax this policy at the reverse proxy. HTML responses are not cached; fingerprinted `/assets` files use immutable caching.

Production Cloudflare secrets are read only from the runtime environment. During an upgrade, when a replacement environment value is present, NorthFlux removes the matching legacy plaintext token, global API key, or account email from the SQLite settings table. Back up the database before the first production migration.

## Persistent data

The Compose file uses Docker-managed volumes so the non-root application user receives correctly owned storage on Linux, Windows, and macOS:

| Volume | Container path | Contents |
|---|---|---|
| `northflux-state` | `/app/state` | SQLite database and WAL files |
| `northflux-reports` | `/app/reports` | Generated CSV, Markdown, PDF, and chart output |
| `northflux-logs` | `/app/logs` | Application and DNS audit logs |

Non-Compose service deployments can place these paths elsewhere with `NORTHFLUX_STATE_DIR`, `NORTHFLUX_REPORTS_DIR`, and `NORTHFLUX_LOGS_DIR`. Relative values resolve from the project root; absolute values are recommended in service definitions. All three locations must be writable by the NorthFlux process and protected from other users.

Back up the three volumes together while the application container is stopped. The command below writes the archive to a host `backups/` directory and does not modify the volumes:

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

The deprecated server-rendered interface remains available only when development mode leaves `NORTHFLUX_SERVE_REACT` disabled. It retains inline resources and a third-party chart dependency and is not available as a production rollback strategy; roll back to a tested image instead.

## Safe remediation rollout

Monitoring and automatic remediation are separate settings and are disabled by default. Recommended rollout:

1. Add one domain you own or are explicitly authorised to manage.
2. Run read-only scans and review the proposed records.
3. Confirm the configured Cloudflare zone and token permissions.
4. Test a manual fix on a controlled record.
5. Enable monitoring.
6. Enable automatic remediation only after the audit log and recovery path have been verified.

DKIM remains manual because provider-specific selector targets and public keys cannot be inferred safely from MX records alone.
