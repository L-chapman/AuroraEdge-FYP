# Security policy

NorthFlux Security scans public email-security infrastructure. Current generated recommendations require manual review and do not trigger DNS writes. Guarded low-level methods can modify an explicitly configured Cloudflare zone through separately reviewed integrations; treat deployments exposing those methods and credentials as administrative security systems.

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
- Keep the retained automatic-remediation compatibility setting disabled; current recommendations are manual-review only. Test any separately reviewed write integration on an authorised controlled zone with a recovery plan.
- Back up the state, reports, and logs volumes together and test restoration.
- Run a single application worker until scheduler and database coordination are externalised.

The project is undergoing a security hardening and modularisation programme. It should be reviewed for the organisation's own risk model before business deployment.
