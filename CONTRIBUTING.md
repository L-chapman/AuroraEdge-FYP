# Contributing to NorthFlux Security

This is a personal project. Small, clearly explained contributions are welcome. Start with the [project tour](docs/PROJECT_TOUR.md) to understand the product and [architecture](docs/ARCHITECTURE.md) to find the relevant code. The repository is public for review, but an open-source licence has not yet been selected.

## Before making a change

Describe the problem, the expected behaviour, and how you reproduced it. For a security concern, use the private route in [SECURITY.md](SECURITY.md); do not publish an exploit, access token, or private domain data in an issue.

Create a branch from `master`. Keep unrelated cleanup separate from behaviour changes so a reviewer can follow the reasoning.

## Set up a development environment

Install Python 3.10 or newer and Node.js 22.12 or newer with npm. Linux also needs Python's `venv` support. The normal [local launcher](README.md) is the easiest way to try the application. To work on the code and run all Python checks, install the development requirements as follows.

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
$env:PYTHONPATH = "$PWD\src"
```

Linux shell:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
export PYTHONPATH="$PWD/src"
```

If the launcher already created `.venv`, reuse it rather than recreating it. On Windows, if script activation is restricted, call `.venv\Scripts\python.exe` directly instead of changing the machine's security policy.

In either shell, install the browser application's recorded dependencies:

```text
cd frontend
npm ci
cd ..
```

For live interface development, start the Python service with `python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8000`. In another terminal, enter `frontend/` and run `npm run dev`. The development browser address is `http://127.0.0.1:5173`; its application requests are forwarded to the Python service. Keep both services private to the same computer.

## Check your change

From the project root, with the Python environment active and `PYTHONPATH` set:

```text
python -m pytest -q
python verify_system.py --offline
python -m ruff check .
python -m bandit -q -r src/app -lll
```

From `frontend/`:

```text
npm run typecheck
npm run lint
npm run test:coverage
npm run build
```

If a change affects browser behaviour, run the Playwright checks as well. The [testing guide](docs/TESTING.md) explains browser installation, the Windows/Linux checks, dependency audits, and what is deliberately outside the automated suite.

Cover changed behaviour with focused tests. Check narrow-screen layout, keyboard use, error messages, and reduced-motion preferences when changing the interface. Preserve the safeguards around sign-in, domain validation, Cloudflare zone ownership, credentials, file paths, and DNS changes.

## Make review straightforward

Explain what changed, why, the tests you actually ran, and any remaining limits. Include before/after screenshots for visual changes using non-sensitive sample data. Update the relevant guide when commands or behaviour change. Historical academic documents belong under [docs/academic/](docs/academic/README.md), not among current setup instructions.

Never commit credentials, `.env`, runtime databases, generated reports, private infrastructure details, dependency folders, or test recordings. Review the changed files before pushing; a passing secret scan is an extra check, not a substitute for that review.
