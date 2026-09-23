# A tour of NorthFlux Security

NorthFlux helps an operator answer a practical question: **is this domain's public email configuration doing what it should, and what needs attention?**

It brings the checks, explanations, scan history, and draft DNS recommendations into one self-hosted application. Self-hosted means the operator runs the service and keeps its stored results on their own computer or server. It is a configuration assessment tool, not a mailbox scanner, spam filter, or guarantee that email cannot be forged.

## What a reviewer can try

Start with the [local setup](../README.md), then follow this short route:

1. Open **Scan** and check a domain you own or are authorised to assess. A scan reads public information; it does not automatically add the domain to monitoring or change its DNS.
2. Read the grade, individual findings, and suggested next steps. If a check cannot finish reliably, NorthFlux shows **Incomplete**, explains why and withholds a grade. A completed grade summarises the implemented rules; it is not a security certification.
3. Add an authorised domain under **Domains** to keep it in the managed list. Open its detail page to review its results and stored history.
4. Open **Generator** to prepare email-security records. Review the values before copying anything into your DNS provider.
5. Open **Settings**. Scheduled monitoring is off by default. The retained automatic-remediation setting is a compatibility control: current generated recommendations require manual review and do not trigger writes. You do not need Cloudflare credentials for the read-only tour.

Use **Sign out** when finished with an authenticated session. Never use a real Cloudflare token in a public demonstration.

## The checks, without the alphabet soup

DNS is a domain's public directory of records. Email providers use those records to work out where mail goes and which senders to trust.

| Check | The question it helps answer |
|---|---|
| MX | Where should mail for this domain be delivered? |
| SPF | Which servers are allowed to send mail for this domain? |
| DKIM | Can the tool find published email-signing records? Discovery checks known selectors, so a missing result does not prove every possible signing record is absent. |
| DMARC | What should a receiving mail provider do when sender checks fail? |
| MTA-STS | Does the domain publish a policy for encrypted delivery between mail servers? |
| TLS-RPT | Is there a published address for reports about encrypted-delivery problems? |
| STARTTLS | When explicitly checked, does a public mail server offer encrypted transport? |
| BIMI and blocklists | Are supporting brand records present, and do checked mail-server addresses appear on the queried public blocklists? |

Public DNS, network restrictions, mail-server behaviour, and third-party services can affect results. NorthFlux cannot infer provider-specific DKIM keys, prove inbox delivery, or inspect a provider's private configuration.

“Record found” means the relevant check found a record, not that every policy setting is safe. STARTTLS checks whether encrypted transport can be negotiated; it is not proof of the server's identity or successful delivery. Private network destinations are deliberately excluded from the scanner's direct connections.

If a scan is incomplete, its warning stays visible in saved history and PDF reports. This prevents a timeout being mistaken for a missing record that should be created. Resolve the cause in the scan notes and run a fresh check before making changes. Even after a complete scan, current generated recommendations require manual review; NorthFlux cannot infer whether enforcement changes are safe for your senders and mail servers.

## What is involved behind the interface

The engineering is more than displaying a scan response. The application must handle slow networks, uncertain results, repeated requests, stored history, and potentially consequential DNS changes.

| Design problem | How the project handles it | Where to inspect it |
|---|---|---|
| Separate observations from conclusions | The scanner collects evidence; the rules engine turns it into findings and advice. The rules can be tested without a live domain. | [Scanner](../src/app/scanner.py), [rules](../src/app/rules.py) |
| Keep uncertainty visible | Failed or ambiguous checks remain ungraded in the interface and saved history. Generated recommendations require manual review, not automatic enforcement. | [Scanner](../src/app/scanner.py), [database](../src/app/database.py), [DNS write layer](../src/app/dns_fix.py) |
| Keep a responsive, consistent interface | React pages share a typed request client, reusable form controls, loading states, and error handling. Late responses do not undo sign-out or replace a settings draft. | [Frontend source](../frontend/src/), [browser journeys](../frontend/e2e/operator-journeys.spec.ts) |
| Keep concurrent work from corrupting history | Database access is coordinated, related changes are saved together, and stale scans are prevented from restoring data after it has been cleared. | [Database](../src/app/database.py), [application](../src/app/dashboard.py), [tests](../tests/) |
| Protect operator access | Sign-in creates an expiring server session. Browser requests that change data need a separate anti-forgery check; the access token is not saved in browser storage. | [API models](../src/app/api_models.py), [application](../src/app/dashboard.py), [security policy](../SECURITY.md) |
| Avoid unintended DNS changes | Scanning and monitoring do not publish generated recommendations. Guarded low-level writes remain for separately reviewed integrations; they check the configured Cloudflare zone, preserve unrelated records, stop on ambiguous records, and leave an audit log. | [DNS write layer](../src/app/dns_fix.py), [integrations](INTEGRATIONS.md) |
| Make builds inspectable and repeatable | Frontend dependencies are locked; Python dependencies are declared but not fully locked. Automated checks, a separate frontend build, and a restricted production container are part of the release workflow. | [Build workflow](../.github/workflows/ci.yml), [Dockerfile](../Dockerfile), [testing](TESTING.md) |

For the full component map, request flow, and storage design, continue to [Architecture](ARCHITECTURE.md).

## What the test evidence does—and does not—show

The [testing guide](TESTING.md) explains how to repeat the checks. The [deep-debug review](DEEP_DEBUG_REVIEW.md) records the release's findings and completed verification; older baseline results are labelled historical. Automated checks include backend behaviour, frontend logic, real browser journeys, security boundaries, container startup, and source-package hygiene. Reported frontend coverage percentages apply to selected logic modules, not every UI page or interaction.

Browser tests use controlled sample scans and disable Cloudflare writes. This makes failures repeatable and prevents a test run from changing a live domain. It does **not** verify every external DNS service, every network, or an operator's real Cloudflare permissions. The settings connection test only reads provider data; it cannot prove write permission. No live Cloudflare write or production deployment is claimed by the deep-debug release. Those need separate, authorised checks on the intended deployment.

## Honest release boundaries

This is a personal project with a substantial implemented and tested feature set. The supported design is one application instance for a single operator—not a hosted multi-customer service. It currently has a shared access token rather than individual accounts and roles. The server's main application module is still large and is a documented refactoring target.

A public server also needs HTTPS, protected storage, backups, and a tested recovery plan. A local launch working successfully is not the same as a production installation being ready. See [Deployment](DEPLOYMENT.md) for that distinction.

The repository is public for inspection. A reusable open-source licence has not yet been selected; do not assume public visibility grants unrestricted reuse. Historical AuroraEdge research and the development record are available in the [academic archive](academic/README.md).
