# Contributing

NorthFlux Security is currently maintained as a personal project. Small, reviewable contributions are welcome.

## Development setup

1. Create a Python 3.10+ virtual environment.
2. Install `requirements-dev.txt` (which includes the runtime requirements).
3. Set `PYTHONPATH` to the repository's `src` directory.
4. Create a branch from the current default branch.
5. Run `python -m pytest -q`, `ruff check .`, and `bandit -q -r src/app -lll` before opening a pull request.

Keep behavioural changes covered by focused tests. Preserve the safety boundaries around authentication, domain validation, Cloudflare zone ownership, credential masking, path handling, and DNS remediation.

Do not include credentials, runtime databases, generated reports, or private infrastructure details in commits.
