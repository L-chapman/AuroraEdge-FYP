# Revision-specific verification evidence

This page separates completed runs from work in progress. Passing tests support
the revision and environments named below; they are not a security certificate
or a guarantee that every computer or input works.

## Independently verified starting revision

Source: [`b93e003974a753f0ac5f91ea57e5b80a79febe16`](https://github.com/L-chapman/AuroraEdge-FYP/tree/b93e003974a753f0ac5f91ea57e5b80a79febe16).
Date: 23 September 2026.
[Completed GitHub-only verification](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35810621797): **15 of 15 jobs passed**.

The workflow downloaded source from GitHub into separate hosted Windows and
Linux machines. It did not copy a developer's project files, state or provider
credentials. Python/Node were provisioned for the run; package-download caches
were allowed. This is a fresh source installation, not a bare-PC prerequisite
installer test or a Proxmox deployment.

| Check | Environment | Recorded result |
|---|---|---|
| Python suite and offline verification | Ubuntu 24.04, Python 3.10 and 3.12 | 739 passed for each Python version; offline verification passed |
| Python suite and offline verification | Windows Server 2025, Python 3.10 and 3.12 | 737 passed, 2 skipped for each version; offline verification passed |
| React logic/components | Ubuntu, Node 24 | 140 tests across 19 files; types, lint, production build and dependency audit passed |
| Public launchers | Ubuntu / Windows, Python 3.12, Node 22.12 and 24 | All four installations and startup checks passed from paths containing spaces |
| Browser journeys | Ubuntu: Chromium, Firefox, WebKit, mobile Chromium | 60 successful executions: 15 scenarios across four profiles |
| Browser journeys | Windows: Chromium | 15 successful executions of the same scenarios |
| Production container | Linux Docker test and production stages | 726 backend tests passed, 13 skipped; frontend tests/build and restricted non-root startup passed |
| Quality and packaging | Linux | Python checks/audits, full-history secret scan, source ZIP exclusions and checksum passed |

The Windows skip count matches the two platform-specific filename tests in the
source. The container count matches packaging/JavaScript checks whose developer
tools are intentionally absent there; those checks run in the full Linux job.
That run used `pytest -q`, so individual skip reasons were not printed. One
Starlette/AnyIO test-library deprecation warning was recorded; it did not fail
the run.

### What was executed

The [workflow at that revision](https://github.com/L-chapman/AuroraEdge-FYP/blob/b93e003974a753f0ac5f91ea57e5b80a79febe16/.github/workflows/ci.yml)
is the exact command record. It includes:

- `python -m pytest -q --cov=app --cov-report=term-missing` and
  `python verify_system.py --offline`.
- `npm ci`, type checking, lint, `npm run test:coverage`, production build and
  dependency audits.
- `START.bat` / `start.sh` with `--setup-only`, then `--smoke-test --port 18081`.
- Playwright's four Linux profiles and Windows `--project=chromium`.
- Docker frontend/backend/production builds and an isolated, read-only,
  non-root container with health/readiness checks.
- Release ZIP creation, forbidden-path checks and SHA-256 verification.

The startup check fetches the React HTML, JavaScript and stylesheet; separate
browser tests execute the interface. Browser tests replace external scan and
provider results with controlled fixtures. They do not prove live DNS writes,
mail delivery, certificate configuration on a deployed reverse proxy or a
visual review of every PDF.

### Coverage scope

Frontend coverage measures selected API-client, domain utility and DNS-generator
modules, not the whole frontend or product. The run's `frontend-coverage`
artifact contains its recorded report while retained by GitHub. Backend logs
include statement and branch misses; their rounded combined percentage must
not be presented as a whole-product completeness score.

See [Testing](TESTING.md) for repeatable commands and
[the dated function audit](FUNCTION_AUDIT.md) for earlier measured coverage.
Those earlier numbers remain historical and are not relabelled as this run.

## NF-01 / NF-02 review increment

Branch: `codex/nf-01-02-capability-evidence`, based on the revision above.
Implementation and validation are in progress. The starting run is **not**
evidence that these newer changes passed. Results for the exact reviewed code
revision will be added after execution; current pull-request checks remain the
gate before approval.

No live provider write, homelab deployment, public demo, real outbound
notification, macOS or ARM validation is claimed. Screenshots use the isolated
fixture server described in the [screenshot guide](screenshots/README.md).
A recording script is a demonstration plan, not an already recorded video.
