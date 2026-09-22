# Security policy

NorthFlux Security scans public email-security infrastructure and can modify DNS for an explicitly configured Cloudflare zone. Treat any deployment with remediation enabled as an administrative security system.

## Supported version

Security fixes are applied to the latest revision on the default branch. No long-term support release exists yet.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or security-advisory feature for this repository. Do not include credentials, API tokens, private DNS data, or personal information in a public issue.

Include the affected revision, reproduction steps, impact, and any suggested mitigation. Reports will be assessed before technical details are published.

## Deployment expectations

- Set `NORTHFLUX_ENV=production` and a random `DASH_TOKEN` of at least 32 characters.
- Terminate HTTPS at a trusted reverse proxy.
- Bind the application to a private interface and restrict network access.
- Supply Cloudflare credentials through a protected runtime environment or secret manager.
- Grant the Cloudflare token only the permissions and zone access it needs.
- Keep automatic remediation disabled until changes have been tested on an authorised zone.
- Back up the state, reports, and logs volumes together and test restoration.
- Run a single application worker until scheduler and database coordination are externalised.

The project is undergoing a security hardening and modularisation programme. It should be reviewed for the organisation's own risk model before business deployment.
