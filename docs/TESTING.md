# Testing NorthFlux Security

## Automated suite

Activate the project virtual environment, set `PYTHONPATH` to `src`, and run:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m pytest -q
```

The NorthFlux 3.2 development baseline is 412 passing tests on Python 3.12. Tests cover scanning, rule evaluation, remediation advice, persistence, API routes, authentication, session expiry and rotation behaviour, CSRF protection, Cloudflare ownership enforcement, secret-source handling and migration, TXT-record safety, input validation, XSS payloads, SQL injection probes, path traversal, stress cases, and safe production defaults.

Run the offline smoke test separately:

```powershell
python verify_system.py --offline
```

The smoke test verifies imports, a deterministic sample scan, rule evaluation, remediation generation, and logging. It does not perform a live DNS write, verify TLS termination, or prove external service availability.

## Quality checks

```powershell
ruff check .
bandit -q -r src/app -lll
pip-audit -r requirements.txt
```

The declared runtime and development dependency sets reported no known vulnerabilities during the NorthFlux 3.2 release audit on 2026-09-20. This is a point-in-time result; rerun `pip-audit` before each release and after dependency changes.

GitHub Actions runs the suite on Windows and Linux with Python 3.10 and 3.12, reports coverage, runs the offline smoke test, checks high-severity static security findings, audits declared dependencies, and builds the container image.

## Manual operator checks

For a release candidate:

1. Start the application with a `DASH_TOKEN` and confirm unauthenticated pages redirect to `/login`.
2. Confirm an invalid token is rejected and a valid login creates an HttpOnly session cookie.
3. Scan a known public domain without Cloudflare credentials.
4. Restart and confirm scan history remains present.
5. Add an authorised managed domain and confirm onboarding does not change DNS.
6. Confirm monitoring and automatic remediation are independently disabled by default.
7. Verify `/health` and `/ready` return success.
8. Generate CSV, Markdown, and PDF output and inspect it for unescaped input.
9. Back up and restore `state/`, `reports/`, and `logs/` on a disposable instance.

Live remediation tests must use a controlled Cloudflare zone owned by the operator. Review the audit log and restore the original DNS state after the test.
