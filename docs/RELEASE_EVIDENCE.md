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

Implementation and screenshot source:
[`2e8b3c0ce204ffc821b5aae631fa30196e229355`](https://github.com/L-chapman/AuroraEdge-FYP/tree/2e8b3c0ce204ffc821b5aae631fa30196e229355).
Review: [pull request #7](https://github.com/L-chapman/AuroraEdge-FYP/pull/7),
branch `codex/nf-01-02-capability-evidence`, based on the revision above.
The source was committed after the local checks below, without intervening code
changes. Evidence/tracker updates may follow in documentation-only commits;
current pull-request checks still gate approval of the final head.

### Local checks, 23 September 2026

Separate checkout, Windows 11 Pro 10.0.26200 x64, Python 3.12.10 and Node 24.15.0.
Dependencies were installed into a new project virtual environment and with
`npm ci`; no global installation, normal database or inherited provider account
was used for tests.

| Check | Recorded result |
|---|---|
| Full Python suite with coverage | 743 passed, 5 skipped, 1 warning |
| Frontend logic/component coverage run | 146 passed across 20 files |
| Type checking, frontend lint and production build | Passed |
| Browser suite | 51 executions passed: 17 scenarios in Chromium, WebKit and mobile Chromium |
| Explicit final Chromium showcase capture | 1 scenario passed; all seven resulting images visually inspected |
| Offline verification, Ruff and high-severity Bandit gate | Passed |
| Runtime/development Python audits and frontend audit | No known vulnerabilities reported |
| Staged-source secret scan | No findings; full-history scanning is also a CI gate |

Commands used were the Python/frontend checks listed above and in
[Testing](TESTING.md), with `pytest -q -ra --cov=app --cov-report=term-missing`
to include skip reasons, and
`npx playwright test --project=chromium --project=webkit --project=mobile-chromium`
for the local browser matrix. The separate capture used
`NORTHFLUX_CAPTURE_SHOWCASE=true` and the command in the
[screenshot guide](screenshots/README.md). Source secret checking used
`git diff --cached --no-ext-diff | gitleaks stdin --redact --no-banner`.

Five Python skips were host limitations: three symlink cases unavailable on
this local Windows setup, one newline filename case, and one backslash filename
case. The warning is the existing Starlette/AnyIO blocking-portal deprecation.
The unrestricted local-directory secret scan also examined ignored installed
dependencies and reported 210 matches in third-party virtual-environment
fixtures/data. Those files are not source changes or part of the commit; the
staged-source scan passed. Do not mistake that directory scan for a clean scan
of every local file.

Measured backend statement coverage was **74.47%** (3,442 of 4,622 statements)
and branch coverage **64.20%** (1,031 of 1,606 branches). The combined rounded
terminal figure was 72%, not either of those separate measures. Selected-module
frontend coverage was 93.91% statements, 89.59% branches, 98% functions and
97.23% lines; it excludes most presentation modules and is not whole-frontend
coverage. The known logging coverage-identity issue remains NF-06 work.

Visual review caught and corrected an invalid example policy ID, an obscured
Settings connection-status badge and a scrolled full-page capture. The final
images show valid generator output, unobstructed Settings status and the
fictional-data notice. Automated browser interaction plus screenshot inspection
is not an exhaustive manual test of every application action. Local Firefox,
Linux and Docker execution is not claimed; the separate hosted matrix covers
those environments where specified by its completed results.

### Hosted checks for this increment

The [completed review workflow](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35813436909)
passed **all 15 jobs** on 23 September 2026. Job logs were checked for the counts
below. As a pull-request run, checkout used GitHub's temporary merge revision
`58522f45c4e003df7df618173ec5baf431f6c2fb`, combining the implementation revision
with the unchanged baseline. Both revisions have the same verified Git tree,
`c43a5221ad685e304333ed01df04c7b3b3118be8`; this is not an approved merge into
`master`.

| Check | Environment | Recorded result |
|---|---|---|
| Python and offline verification | Ubuntu 24.04, Python 3.10 / 3.12 | 748 passed for each version; offline checks passed |
| Python and offline verification | Windows Server 2025, Python 3.10 / 3.12 | 746 passed, 2 skipped for each version; offline checks passed |
| Frontend | Ubuntu, Node 24 | 146 passed across 20 files; types, lint, build and audit passed |
| Clean public launchers | Ubuntu / Windows, Node 22.12 / 24, Python 3.12 | All four setup/startup/React-asset checks passed |
| Browser journeys | Ubuntu: Chromium, Firefox, WebKit, mobile Chromium | 68 executions passed: 17 scenarios across four profiles |
| Browser journeys | Windows: Chromium | 17 executions of the same scenarios passed |
| Container | Linux Docker | 735 backend tests passed, 13 skipped; 146 frontend tests passed; restricted non-root production startup passed |
| Quality, secrets, release archive | Linux | Python quality/dependency gates, full-history secret scan, archive exclusions and SHA-256 check passed |

There were no failed jobs or browser retries (`retries: 0`). Skip categories
and the existing test-library warning are the same platform/tooling limitations
explained for the baseline; hosted `pytest -q` logs give aggregate counts rather
than individual skip reasons. Hosted Windows supports the symlink cases that
were skipped on the local Windows machine. Browser profile executions are not
68 distinct scenarios or tests on real phones/macOS devices.

The workflow's `northflux-security-source`, `frontend-coverage` and
`gitleaks-results.sarif` artifacts are available while retained by GitHub. The
archive is a review artifact, not a published release or an installed update.
The same source-only installation, mocked-network and prerequisite limitations
described above apply. No check or assertion was weakened to obtain these results.

No live provider write, homelab deployment, public demo, real outbound
notification, macOS or ARM validation is claimed. Screenshots use the isolated
fixture server described in the [screenshot guide](screenshots/README.md).
A recording script is a demonstration plan, not an already recorded video.

### Approved merge of NF-01 / NF-02

After owner approval, PR #7 was merged as
[`9e12eed5e98b1907548e648103743d9332bc4a14`](https://github.com/L-chapman/AuroraEdge-FYP/tree/9e12eed5e98b1907548e648103743d9332bc4a14).
The final reviewed head was `200d7f21301f6c88419ad57209fa84f29a64dc95`; its
[15 checks passed](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35813970959),
and the merged head's [15 post-merge checks also passed](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35831341540).
Both have Git tree `2930210863c90da4f0ae402283bd08eefc37589d`. The local master
checkout and clean master-folder source copy were synced with that approved
revision, retaining a verified recovery copy. No operational database was
migrated or replaced, and no GitHub release/tag or public deployment was made.

## First NF-03 extraction: local verification snapshot

Implementation/test revision:
[`e51d2d13a622dde27f5c580121db3bdd43db206a`](https://github.com/L-chapman/AuroraEdge-FYP/tree/e51d2d13a622dde27f5c580121db3bdd43db206a),
based on merged `9e12eed5e98b1907548e648103743d9332bc4a14`. Documentation-only
commits may follow it. This section records local execution, not a completed
hosted result. The pull request for
[`codex/nf-03-auth-state`](https://github.com/L-chapman/AuroraEdge-FYP/tree/codex/nf-03-auth-state)
records the final head and completed hosted workflow; check that head's results
before approval instead of treating earlier green runs as evidence for it.

On 23 September 2026, a separate Windows 11 x64 checkout used Python 3.12.10,
Node 24.15.0, the existing isolated development environment with unchanged
Python requirements, and a fresh `npm ci` in this checkout. Tests selected this
checkout's `src` and used temporary databases/network fixtures, not installed
application data.

| Local check | Actual result |
|---|---|
| Authentication characterization before extraction | 106 passed, 2 host-symlink skips across the new contract tests and existing authentication/API/request/stream suites |
| Same characterization set after extraction | 106 passed, 2 skipped |
| Expanded authentication and lifecycle set | 122 passed, 2 skipped |
| Full backend rerun with statement/branch coverage | 771 passed, 5 platform/permission skips, 1 existing deprecation warning |
| Frontend | 146 tests across 20 files; type check, lint and production build passed |
| Browser journeys | 51 executions passed: 17 scenarios in Chromium, WebKit and mobile Chromium |
| Offline verification, Ruff and high-severity Bandit gate | Passed |
| Staged implementation secret scan | No findings |

Commands used the same documented Python/frontend suites, including
`pytest -q -ra --cov=app --cov-report=term-missing` and
`npx playwright test --project=chromium --project=webkit --project=mobile-chromium`.
The five skips again cover three unavailable Windows symlink cases and two
platform-specific filename cases. No local Linux, Firefox, Docker or new
manual UI/screenshot review is claimed for this state-only extraction. The UI
and screenshot assets are unchanged; browser tests ran against the real compiled
React interface using the disposable fixture server.

Backend statement coverage was **75.19%** (3,497/4,651) and branch coverage
**65.07%** (1,045/1,606). The new state module's measured 63 statements and eight
branches were exercised, but that does not establish complete authentication
security. Selected-module frontend coverage remains 93.91% statements, 89.59%
branches, 98% functions and 97.23% lines. The separate logging coverage-identity
issue is still unresolved.

Independent read-only review found no introduced regression. Known limits are
explicit: authentication is single-process and lost on restart; failed-login
admission and failure recording are not one atomic operation; lifecycle shutdown
requests monitor cancellation without joining its cleanup. Concurrent store
tests check record integrity, not a hard five-request admission ceiling. These
are follow-up design/hardening items, not capabilities claimed by this refactor.
Routes, cookie settings, origin/CSRF checks, dynamic token reads, the scheduler,
database schema and provider behaviour were not changed.
