# Testing NorthFlux Security

## Start with the evidence

A passing test run is evidence for a particular version and environment—not a promise that software can never fail. NorthFlux uses repeatable tests for its own behaviour and separate checks for packaging, browsers, and deployment.

The recorded React migration baseline at `30360f0` passed **439 Python tests, 57 frontend tests, and 36 browser tests**. The [completed GitHub Actions run](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35769606519) is the evidence for that version. Newer changes need their own completed run; the [workflow history](https://github.com/L-chapman/AuroraEdge-FYP/actions/workflows/ci.yml) shows results for each pushed revision.

The current suite contains **472 Python tests and 68 frontend unit/component tests**. The browser suite defines 12 checks per browser profile: 48 on Linux's four profiles and 12 Chromium checks on Windows in CI. Counts describe the suite, not proof of a pass; use the matching revision's completed workflow as the release evidence.

| Layer | Environment and checks |
|---|---|
| Python application | Windows and Ubuntu Linux, Python 3.10 and 3.12 |
| React application | Types, code checks, unit/component tests, coverage, and production build |
| Browser journeys | Chromium on Windows; Chromium, Firefox, WebKit, and a Pixel 7 mobile Chromium profile on Linux |
| Fresh local launch | Windows and Ubuntu Linux, Python 3.12, Node.js 22.12 and 24, from a clean folder whose name contains spaces |
| Production container | Frontend and backend test stages, restricted non-root runtime, startup and writable-storage checks |
| Release hygiene | Dependency audits, full-history secret scan, working documentation links, and a clean source ZIP |

The fresh-launch matrix is part of the launch-polish workflow added after the recorded baseline above. Inspect the matching revision's result before treating it as verified. Linux distributions beyond the CI runner, macOS, every Windows configuration, ARM hardware, and all newer Python/Node versions are not independently certified by this matrix. A supported browser engine is not a test on every physical mobile device.

Missing browser system packages, a blocked mail-server port, or unavailable public DNS can cause a failure even when the code tests pass. Record the operating system, runtime versions, full error, and exact Git revision when reporting a problem; remove private data first.

## Quick installation check

From a fresh checkout with Python, Node.js, and npm available:

```powershell
# Windows
.\START.bat --smoke-test
```

```bash
# Linux
sh ./start.sh --smoke-test
```

This prepares the dependencies and compiled interface, starts the application briefly with temporary state and Cloudflare credentials removed, checks `/health`, `/ready`, and the React page, then stops. It does not scan a live domain or change DNS. The [deployment guide](DEPLOYMENT.md) explains prerequisites and troubleshooting.

## Backend suite

Follow [Contributing](../CONTRIBUTING.md) to install the development requirements. Activate the project environment, set `PYTHONPATH` to `src`, and run:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m pytest -q
```

On Linux, the equivalent is:

```bash
export PYTHONPATH="$PWD/src"
python -m pytest -q
```

Tests cover scanning, rule evaluation, remediation advice, persistence, legacy and `/api/v1` contracts, authentication, session expiry and rotation behaviour, CSRF protection, Cloudflare ownership enforcement, secret-source handling and migration, TXT-record safety, input validation, XSS payloads, SQL injection probes, path traversal, React asset serving, SPA route boundaries, security headers, stress cases, and safe production defaults.

Run the offline smoke test separately:

```powershell
python verify_system.py --offline
```

The smoke test verifies imports, a deterministic sample scan, rule evaluation, remediation generation, and logging. It does not perform a live DNS write, verify TLS termination, or prove external service availability.

## Frontend unit and component suite

Install exactly the dependencies recorded in `frontend/package-lock.json`, then check types, code rules, tests, coverage, and the compiled build. These commands work in either shell, starting in the project root:

```text
cd frontend
npm ci
npm run typecheck
npm run lint
npm run test:coverage
npm run build
cd ..
```

Vitest and Testing Library cover the API client, domain validation and normalisation, DNS record generation, form interactions, error states, and edge cases such as IPv4 CIDR input, DMARC `pct=0`, and multiline MTA-STS MX entries. The deterministic client and record-generation modules have minimum coverage gates of 90% for lines, functions, and statements and 85% for branches. Route-level behaviour is covered by the browser suite instead of being counted as superficial unit coverage.

## Browser UI suite

Playwright controls real browser engines to exercise the interface. The suite defines nine operator journeys plus three presentation/accessibility checks in each of four projects: desktop Chromium, desktop Firefox, desktop WebKit, and a Pixel 7 mobile Chromium profile. A complete four-profile run executes 48 browser tests. CI also runs the 12 Chromium checks on Windows. The journeys cover:

- invalid and valid sign-in, browser-storage handling, and sign-out;
- the empty dashboard and a serious/critical axe accessibility check;
- explicit single scans without silent monitoring enrolment;
- batch submission and the 20-domain limit;
- managed-domain enrolment, detail, rescan, and confirmed removal;
- DNS generator edge cases and keyboard-operable output;
- independent monitoring settings and destructive-action confirmation;
- CSRF rejection and the public privacy route; and
- narrow-screen navigation.

The presentation checks cover all main pages at 320px with reduced motion, keyboard dismissal of the mobile menu, and saved-result rendering without uncaught browser errors or application CSP violations. [Interface screenshots](screenshots/README.md) are generated from this same isolated test setup when explicitly requested.

Install the Playwright-managed browsers once, then run the suite from `frontend/`:

```text
cd frontend
npx playwright install chromium firefox webkit
npm run test:e2e
cd ..
```

On Linux CI, browser system packages are installed with `npx playwright install --with-deps chromium firefox webkit`. The test runner first creates a production frontend build, then starts `scripts/e2e_server.py` at `127.0.0.1:4173`. That server uses the ignored `frontend/.e2e-data/` state/report/log root, a deterministic fake scanner, an operator test token, blank Cloudflare environment values, and a disabled Cloudflare write layer. The root is cleaned at startup and shutdown. Browser tests therefore cannot modify a live DNS zone.

Playwright retains traces, screenshots, and video only on failure. GitHub Actions uploads that evidence for seven days when the UI job fails. A browser failing to launch because its operating-system dependencies are missing is an environment failure, not a passing product test; use the supported Linux CI job as the release gate after resolving any host-specific launch problem. In the migration's local Windows checks, Firefox could not launch (`spawn UNKNOWN`); all four browser projects passed on Linux CI. That local limitation must not be reported as a Windows Firefox pass.

## Quality checks

```text
python -m ruff check .
python -m bandit -q -r src/app -lll
python -m pip_audit -r requirements.txt
python -m pip_audit -r requirements-dev.txt

cd frontend
npm audit --audit-level=high
cd ..
```

The declared Python runtime/development and npm dependency sets reported no known vulnerabilities during the React migration audit. This is a point-in-time result; rerun both package-manager audits before each release and after dependency changes.

GitHub Actions runs the checks in the matrix above. The final release job creates a source ZIP only after the required jobs pass and checks that it excludes secrets, local environments, runtime data, dependencies, build output, and test recordings. `tests/test_documentation_links.py` also checks local links in the current guides and academic archive so a tidy-up cannot silently break the reading route.

Container checks can also be run directly:

```powershell
docker build --target frontend-test --tag northflux-security:frontend-test .
docker build --target test --tag northflux-security:test .
docker build --target production --tag northflux-security:release-candidate .
```

The production smoke test should run read-only, with dropped capabilities and disposable writable mounts for `/tmp`, `/app/state`, `/app/reports`, and `/app/logs`. Confirm `/health`, `/ready`, the non-root runtime user, the compiled `frontend/dist/index.html`, and the absence of Node.js and `node_modules`.

## Source packaging

Maintainers need **PowerShell 7 or newer** (`pwsh`) to build the source ZIP on Windows or Linux. Windows' built-in PowerShell 5.1 is not supported by the packaging script. PowerShell 7 is not needed to run the application.

From a clean Git checkout:

```text
pwsh -NoProfile -File scripts/create_submission_zip.ps1
```

This produces `dist/NorthFlux_Security.zip` and its SHA-256 checksum. It checks the working tree before replacing the previous package, and excludes local data, secrets, dependencies and generated output. The source ZIP includes setup files, not preinstalled dependencies; it has the same Python/Node requirements as a clone. `-AllowDirty` is for explicitly reviewed development snapshots only, not a clean release.

The frontend lockfile fixes its dependency tree. Python requirements include some version ranges and do not lock all transitive dependencies; fresh installations can resolve different compatible versions. Re-run the full checks when dependencies or runtime versions change.

## Manual operator checks

Automated tests do not replace checking a real deployment. For a release candidate:

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

For visual changes, also check the sign-in page, empty and populated overview, domain list, forms, and dialogs at desktop and narrow widths. Use only non-sensitive sample data. Check keyboard focus, readable contrast, loading/error states, and reduced-motion preferences. Record what was actually inspected; do not label an untested screen or operating system as passed.

Live remediation tests are deliberately outside the deterministic suite. They must use a controlled Cloudflare zone owned by the operator, with least-privilege credentials and an approved rollback plan. Review the audit log and restore the original DNS state after the test.
