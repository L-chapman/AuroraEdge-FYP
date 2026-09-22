# Contributing

NorthFlux Security is currently maintained as a personal project. Small, reviewable contributions are welcome.

## Development setup

1. Install Python 3.10 or newer and Node.js 22.12 or newer.
2. Create a Python virtual environment and install `requirements-dev.txt` (which includes the runtime requirements).
3. Set `PYTHONPATH` to the repository's `src` directory.
4. Run `npm ci` in `frontend/` to install the locked browser-application dependencies.
5. Create a branch from the current default branch.
6. Run the backend and frontend quality gates before opening a pull request:

   ```powershell
   $env:PYTHONPATH = "$PWD\src"
   python -m pytest -q
   ruff check .
   bandit -q -r src/app -lll

   Push-Location frontend
   npm run typecheck
   npm run lint
   npm run test:coverage
   npm run build
   Pop-Location
   ```

7. For changes that affect browser workflows, install the Playwright-managed browsers and run `npm run test:e2e` from `frontend/`. The supported Linux CI browser job is the release gate for Chromium, Firefox, WebKit, and the Pixel 7 profile; see [the testing guide](docs/TESTING.md) for setup and evidence details.

Keep behavioural changes covered by focused tests. Preserve the safety boundaries around authentication, domain validation, Cloudflare zone ownership, credential masking, path handling, and DNS remediation.

Do not include credentials, runtime databases, generated reports, or private infrastructure details in commits.
