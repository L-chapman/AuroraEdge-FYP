# Historical AuroraEdge 3.1 Release Notes

> **Historical record:** This document describes the April 2026 final-project snapshot, not the current NorthFlux Security release candidate. For current product status, version, tests, and release changes, use [`../README.md`](../README.md), [`../CHANGELOG.md`](../CHANGELOG.md), and [`TESTING.md`](TESTING.md).

## Release Snapshot

- Application version recorded in the April 2026 snapshot: **3.1**
- Dashboard/API route handlers: **36**
- Final automated test result rechecked on **2026-04-14** with `python -m pytest -q`: **397 passed, 0 skipped**
- Smoke-test script: `verify_system.py` now supports `--domain` and `--offline`
- Clean submission ZIP script: `scripts/create_submission_zip.ps1`

Stable release identifier:

- Submission tag: `submission-2026-04-14`
- Exact commit hash is recorded by Git history and the tag target after the final push. A file inside the commit cannot safely include its own final hash without changing that hash.

---

## Final Feature Set

- Public-domain email security scanning for SPF, DKIM, DMARC, MTA-STS, TLS-RPT, MX, blacklist status, and optional STARTTLS
- RFC-based rules engine with severity, score, grade, and remediation output
- FastAPI dashboard with test hub, managed domains, settings, alerts, downloads, and history views
- CLI workflow for single-domain scans, batch scans, report generation, remediation output, and optional fix application
- SQLite storage for scan history, settings, alerts, and managed domains
- Cloudflare-backed remediation for supported DNS fixes
- Provider-aware DKIM auto-configuration for supported providers only
- MTA-STS policy hosting through Cloudflare Workers
- Controlled demo reset and restore workflow for `auroraedge.co.uk`
- Audit logging for DNS changes
- Large automated test suite and smoke-test verification path

---

## Selected Evidence Files

These are the main files kept as final evidence for the dissertation and marking workflow:

- `README.md`
- `docs/TESTING_GUIDE.md`
- `docs/ARCHITECTURE.md`
- `docs/architecture_diagram.svg`
- `docs/VERIFICATION_REPORT.md`
- `docs/STATUS.md`
- `docs/COMPETITOR_ANALYSIS.md`
- `docs/PRIVACY_AND_ETHICS.md`
- `docs/SCAN_ANALYSIS.md`
- `docs/figures/`
- `reports/indexed/auroraedge_results_20260309_232838.csv`
- `reports/indexed/auroraedge_results_20260309_232838.md`
- `reports/indexed/auroraedge_results_20260319_151244.csv`
- `reports/indexed/auroraedge_results_20260319_151244.md`
- `verify_system.py`
- `scripts/demo_prep.py`
- `scripts/lab_experiment.py`

`reports/archive/` is kept in the repository as project history and stays in the clean submission copy so the packaged project matches the tracked source files.

---

## Packaging Note

For the final assessment copy, use:

```powershell
.\scripts\create_submission_zip.ps1
```

When run from the Git checkout, the generated ZIP follows the tracked project files so it stays aligned with the public repository. `.github/` is left out because it is only used for repository automation and is not needed for marking.

The generated ZIP excludes:

- `.github`
- `.venv`
- `.git`
- `.git (1)`
- `.pytest_cache`
- `.vscode`
- `__pycache__`
- runtime database files in `state/`
- `logs/`
- nested ZIP files

This keeps the submission tidy and avoids shipping local machine artefacts.

Submission package checklist:

- `README.md` so a marker can start the project quickly
- `docs/` so the design, testing, verification, and ethics material stays with the code
- `scripts/` for the demo menu, demo reset flow, lab script, and clean packaging workflow
- `src/` for the full implementation
- `tests/` so the final automated checks can be rerun
- `reports/` so the representative outputs and stored evidence stay aligned with the repository
- excludes local environments, Git internals, caches, logs, runtime state, and repository automation files

---

## Controlled Demo Workflow

For the authorised classroom demo, `auroraedge.co.uk` can be cycled through a repeatable reset, fix, and restore flow.

- `python scripts/demo_prep.py` resets SPF, DMARC, and MTA-STS to the known weak demo state.
- AuroraEdge can then scan and apply the supported Cloudflare fixes from the dashboard or the CLI.
- `python scripts/demo_prep.py --restore` returns the domain to the normal strong state after the demo.

This workflow is only for `auroraedge.co.uk` or another domain you own or are explicitly authorised to manage.

---

## Known Limitations

- Live scan results depend on current public DNS and HTTPS state, so results can change over time.
- STARTTLS checks depend on public MX availability and network reachability.
- Auto-fix is limited to Cloudflare-managed domains.
- DKIM auto-fix is limited to supported providers that AuroraEdge can identify safely.
- BIMI is reported but not auto-fixed.
- The local dashboard runs over localhost HTTP for development; production deployment should use TLS in front of it.

---

## Final Submission Notes

- The clean submission copy is meant for assessment and demonstration, not for production deployment.
- The repository remains the source-of-truth development history.
- The release artefacts above are the preferred evidence set for the dissertation write-up.
