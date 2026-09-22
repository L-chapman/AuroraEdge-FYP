# NorthFlux Security integrations

## Cloudflare

Cloudflare is optional and is used only for supported DNS remediation and MTA-STS Worker deployment. Read-only scanning works without it.

The settings connection test makes read-only probes. A successful result confirms only what those reads establish; it does **not** prove that the token can edit DNS or deploy a Worker. Confirm permissions in Cloudflare and perform any live validation separately on an authorised test zone. The [deep-debug review](DEEP_DEBUG_REVIEW.md) does not claim a live Cloudflare write or deployment test.

Prefer a scoped API token limited to the specific authorised zone. Typical DNS remediation requires zone read and DNS edit access. Worker deployment requires additional account-level permissions. The current runtime accepts one `CF_API_TOKEN`, so strict credential separation requires deploying the Worker outside NorthFlux or temporarily supplying a separately scoped Worker token for an approved deployment and restoring the DNS-only runtime token afterwards. Do not leave broader Worker permissions attached to the normal remediation credential merely for convenience.

Production deployments should inject credentials through the service environment or a secret manager:

```text
CF_API_TOKEN
CF_ZONE_ID
CF_ACCOUNT_ID
```

The production settings API rejects attempts to persist the API token or global key. Local-development settings remain stored in SQLite without encryption, so they should only be used on a protected developer machine.

Before any write, NorthFlux verifies that the target is the configured zone or one of its subdomains. A failed prerequisite read is an error, not evidence that a record is absent. The TXT write layer selects records by protocol prefix and stops when incomplete lookups or duplicate same-protocol records make the intended target ambiguous.

Incomplete scans produce manual review advice, with no automatic fix. When SPF is missing, first identify every authorised sender and obtain each provider's instructions; NorthFlux does not invent a default sending provider. DKIM is not generated automatically. MX records can suggest a provider but cannot safely reveal tenant-specific public keys or selector targets; obtain the exact values from the mail provider's administration console.

MTA-STS Worker deployment checks observed MX names and existing host/route records before changing anything. Conflicting records or routes require manual review; the fallback does not delete an existing DNS record to force a binding. This is a multi-step provider operation, not an atomic transaction. A failed deployment can still need operator inspection of changes already accepted by Cloudflare. Keep the original configuration and a rollback plan, and verify both the served HTTPS policy and DNS after an authorised deployment.

## Reverse proxy

Use a TLS reverse proxy for production access. Forward to the loopback-bound Compose port, restrict direct access, and retain the original host and forwarding information. See [Deployment](DEPLOYMENT.md).

## Prometheus and Grafana

Metrics are planned but are not part of the current release. `/health` provides liveness and `/ready` checks the database and runtime storage. Do not describe the application as Prometheus-integrated until a metrics endpoint and dashboard are implemented and tested.

## Mail systems

NorthFlux observes public MX and STARTTLS behaviour. It does not require access to mailboxes or message content. Any Postfix, OpenDMARC, or provider-side configuration remains an operator-controlled task outside the application.

The scanner uses public DNS, checks destination addresses before connecting, and rejects private or special-purpose HTTPS/SMTP targets. Its MTA-STS fetch verifies HTTPS certificates, limits response size and time, does not follow redirects and does not inherit HTTP proxy settings. STARTTLS is a transport-capability check, not certificate-identity verification or a delivery test. These limits deliberately exclude internal-only mail infrastructure.

A lookup timeout, blocked connection, invalid policy or ambiguous essential record can make a scan **Incomplete**. Review its notes and retry after resolving the cause. A record being found is not the same as every policy setting being safe, and a completed scan does not discover every possible DKIM selector or prove successful inbox delivery.
