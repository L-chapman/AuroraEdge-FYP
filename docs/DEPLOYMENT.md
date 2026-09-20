# NorthFlux Security deployment

This guide describes the supported single-instance Docker deployment. NorthFlux currently embeds its scheduler and uses SQLite, so run exactly one application worker and one container against a given state volume.

## Prerequisites

- Docker Engine with Compose v2
- A private host or VM with persistent storage
- A TLS reverse proxy for any access beyond localhost
- A long random dashboard token
- Optional least-privilege Cloudflare credentials for authorised remediation

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

The service listens on `127.0.0.1:8080` by default. Its liveness endpoint is `/health`; `/ready` also checks SQLite and writable runtime directories.

## Reverse proxy

Terminate HTTPS at Nginx, Caddy, Traefik, or an equivalent trusted proxy. Forward to `http://127.0.0.1:8080`, retain the original host and forwarding headers, and restrict direct access to the application port.

The production login cookie is marked `Secure`, so browser access must use HTTPS. NorthFlux checks the browser `Origin` and a per-session CSRF token on state-changing cookie-authenticated requests. Preserve `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto`, or set `NORTHFLUX_PUBLIC_ORIGIN` to the exact external HTTPS origin. Do not expose Uvicorn directly to the Internet.

Interactive API documentation and the OpenAPI document are disabled in production mode. Use a development instance on a trusted workstation when route exploration is required.

Production Cloudflare secrets are read only from the runtime environment. During an upgrade, when a replacement environment value is present, NorthFlux removes the matching legacy plaintext token, global API key, or account email from the SQLite settings table. Back up the database before the first production migration.

## Persistent data

The Compose file uses Docker-managed volumes so the non-root application user receives correctly owned storage on Linux, Windows, and macOS:

| Volume | Container path | Contents |
|---|---|---|
| `northflux-state` | `/app/state` | SQLite database and WAL files |
| `northflux-reports` | `/app/reports` | Generated CSV, Markdown, PDF, and chart output |
| `northflux-logs` | `/app/logs` | Application and DNS audit logs |

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

If upgrading from an earlier bind-mount deployment, stop the old container, back up `state/`, `reports/`, and `logs/`, then copy that data into the named volumes before starting NorthFlux 3.2. Do not point two containers at the same SQLite database.

## Updates and rollback

Before updating:

1. Record the running Git revision or image tag.
2. Back up persistent data.
3. Build and run tests for the target revision.
4. Rebuild and restart the container.
5. Confirm both `/health` and `/ready`, then perform a read-only domain scan.

To roll back, stop the service, check out or retag the previous revision, restore data if a schema change requires it, rebuild, and verify readiness.

## Safe remediation rollout

Monitoring and automatic remediation are separate settings and are disabled by default. Recommended rollout:

1. Add one domain you own or are explicitly authorised to manage.
2. Run read-only scans and review the proposed records.
3. Confirm the configured Cloudflare zone and token permissions.
4. Test a manual fix on a controlled record.
5. Enable monitoring.
6. Enable automatic remediation only after the audit log and recovery path have been verified.

DKIM remains manual because provider-specific selector targets and public keys cannot be inferred safely from MX records alone.
