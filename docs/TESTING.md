# Testing NorthFlux Security

## Verified baseline

The current deterministic baseline is 439 passing Python tests and 57 passing frontend unit/component tests. These counts describe the checked-in suite at the React migration release candidate; they are not a guarantee against future defects or failures in external DNS, HTTPS, SMTP, or Cloudflare services.

## Backend suite

Activate the project virtual environment, set `PYTHONPATH` to `src`, and run:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m pytest -q
```

Tests cover scanning, rule evaluation, remediation advice, persistence, legacy and `/api/v1` contracts, authentication, session expiry and rotation behaviour, CSRF protection, Cloudflare ownership enforcement, secret-source handling and migration, TXT-record safety, input validation, XSS payloads, SQL injection probes, path traversal, React asset serving, SPA route boundaries, security headers, stress cases, and safe production defaults.

Run the offline smoke test separately:

```powershell
python verify_system.py --offline
```

The smoke test verifies imports, a deterministic sample scan, rule evaluation, remediation generation, and logging. It does not perform a live DNS write, verify TLS termination, or prove external service availability.

## Frontend unit and component suite

Install exactly the dependencies recorded in `frontend/package-lock.json`, then run the type, lint, coverage, and build gates:

```powershell
Push-Location frontend
npm ci
npm run typecheck
npm run lint
npm run test:coverage
npm run build
Pop-Location
```

Vitest and Testing Library cover the API client, domain validation and normalisation, DNS record generation, form interactions, error states, and edge cases such as IPv4 CIDR input, DMARC `pct=0`, and multiline MTA-STS MX entries. The deterministic client and record-generation modules have minimum coverage gates of 90% for lines, functions, and statements and 85% for branches. Route-level behaviour is covered by the browser suite instead of being counted as superficial unit coverage.

## Browser UI suite

The Playwright suite defines nine operator journeys in each of four projects: desktop Chromium, desktop Firefox, desktop WebKit, and a Pixel 7 mobile Chromium profile. A complete run therefore executes 36 browser tests. The journeys cover:

- invalid and valid sign-in, browser-storage handling, and sign-out;
- the empty dashboard and a serious/critical axe accessibility check;
- explicit single scans without silent monitoring enrolment;
- batch submission and the 20-domain limit;
- managed-domain enrolment, detail, rescan, and confirmed removal;
- DNS generator edge cases and keyboard-operable output;
- independent monitoring settings and destructive-action confirmation;
- CSRF rejection and the public privacy route; and
- narrow-screen navigation.

Install the Playwright-managed browsers once, then run the suite from `frontend/`:

```powershell
Push-Location frontend
npx playwright install chromium firefox webkit
npm run test:e2e
Pop-Location
```

On Linux CI, browser system packages are installed with `npx playwright install --with-deps chromium firefox webkit`. The test runner first creates a production frontend build, then starts `scripts/e2e_server.py` at `127.0.0.1:4173`. That server uses the ignored `frontend/.e2e-data/` state/report/log root, a deterministic fake scanner, an operator test token, blank Cloudflare environment values, and a disabled Cloudflare write layer. The root is cleaned at startup and shutdown. Browser tests therefore cannot modify a live DNS zone.

Playwright retains traces, screenshots, and video only on failure. GitHub Actions uploads that evidence for seven days when the UI job fails. A browser failing to launch because its operating-system dependencies are missing is an environment failure, not a passing product test; use the supported Linux CI job as the release gate after resolving any host-specific launch problem.

## Quality checks

```powershell
ruff check .
bandit -q -r src/app -lll
pip-audit -r requirements.txt
pip-audit -r requirements-dev.txt

Push-Location frontend
npm audit --audit-level=high
Pop-Location
```

The declared Python runtime/development and npm dependency sets reported no known vulnerabilities during the React migration audit. This is a point-in-time result; rerun both package-manager audits before each release and after dependency changes.

GitHub Actions runs Python on Windows and Linux with versions 3.10 and 3.12; checks frontend types, lint, coverage, build, and dependencies; scans the full Git history for secrets; runs all four Playwright projects on Linux; and tests the frontend, backend, and hardened production container stages. The final release job creates a source ZIP only after those jobs pass and checks that it excludes secrets, local environments, runtime data, dependencies, build output, and test evidence.

Container checks can also be run directly:

```powershell
docker build --target frontend-test --tag northflux-security:frontend-test .
docker build --target test --tag northflux-security:test .
docker build --target production --tag northflux-security:release-candidate .
```

The production smoke test should run read-only, with dropped capabilities and disposable writable mounts for `/tmp`, `/app/state`, `/app/reports`, and `/app/logs`. Confirm `/health`, `/ready`, the non-root runtime user, the compiled `frontend/dist/index.html`, and the absence of Node.js and `node_modules`.

## Manual operator checks

For a release candidate:

1. Start the application with a `DASH_TOKEN` and confirm unauthenticated pages redirect to `/login`.
2. Confirm an invalid token is rejected and a valid login creates an HttpOnly session cookie.
3. Scan a known public domain without Cloudflare credentials.
4. Restart and confirm scan history remains present.
5. Add an authorised managed domain and confirm onboarding does not change DNS.
6. Confirm monitoring and automatic remediation are independently disabled by default.
7. Verify `/health` and `/ready` return success.
8. Confirm the production CSP does not contain `unsafe-inline` and that browser assets load only from the application origin.
9. Generate CSV, Markdown, and PDF output and inspect it for unescaped input.
10. Back up and restore `state/`, `reports/`, and `logs/` on a disposable instance.

Live remediation tests are deliberately outside the deterministic suite. They must use a controlled Cloudflare zone owned by the operator, with least-privilege credentials and an approved rollback plan. Review the audit log and restore the original DNS state after the test.
