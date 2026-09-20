# NorthFlux Security integrations

## Cloudflare

Cloudflare is optional and is used only for supported DNS remediation and MTA-STS Worker deployment. Read-only scanning works without it.

Prefer a scoped API token limited to the specific authorised zone. Typical DNS remediation requires zone read and DNS edit access. Worker deployment requires additional account-level permissions and should use a separate token when practical.

Production deployments should inject credentials through the service environment or a secret manager:

```text
CF_API_TOKEN
CF_ZONE_ID
CF_ACCOUNT_ID
```

The production settings API rejects attempts to persist the API token or global key. Local-development settings remain stored in SQLite without encryption, so they should only be used on a protected developer machine.

Before any write, NorthFlux verifies that the target is the configured zone or one of its subdomains. The TXT write layer selects records by protocol prefix and stops when duplicate SPF, DMARC, or other same-protocol records make the intended target ambiguous.

DKIM is not generated automatically. MX records can suggest a provider but cannot safely reveal tenant-specific public keys or selector targets; obtain the exact values from the mail provider's administration console.

## Reverse proxy

Use a TLS reverse proxy for production access. Forward to the loopback-bound Compose port, restrict direct access, and retain the original host and forwarding information. See [Deployment](DEPLOYMENT.md).

## Prometheus and Grafana

Metrics are planned but are not part of the current release. `/health` provides liveness and `/ready` checks the database and runtime storage. Do not describe the application as Prometheus-integrated until a metrics endpoint and dashboard are implemented and tested.

## Mail systems

NorthFlux observes public MX and STARTTLS behaviour. It does not require access to mailboxes or message content. Any Postfix, OpenDMARC, or provider-side configuration remains an operator-controlled task outside the application.
