# Changelog

This project follows semantic versioning from the NorthFlux Security rename onward.

## 4.0.0 - Unreleased

- Completed a deep-debug pass with fail-first regressions and a [plain-language review](docs/DEEP_DEBUG_REVIEW.md) distinguishing fixed faults, measured coverage and launch limitations.
- Added bounded public-only scanner connections, HTTPS certificate checks, stricter policy parsing and explicit incomplete-scan handling throughout storage, React and reports.
- Made DNS prerequisites fail closed on failed/ambiguous reads and preserved conflicting infrastructure; removed guessed SPF/provider and DKIM automation.
- Stopped selecting the highest post-change scan score, preserved later regressions, and prevented incomplete verification from claiming success or a grade.
- Added monitoring cancellation checks after slow scans/provider reads and before fix callbacks, with tests for disabling/removing domains during work.
- Hardened request sizes/types, Unicode credential comparisons and atomic settings saves; moved slow manual remediation off the request event loop.
- Fixed stale authentication responses, domain-detail state, generated TXT/mailto edge cases, PDF overflow/missing evidence and CLI/report value handling.
- Strengthened installed-dependency checks and source archive safeguards, fixed browser-test Python paths with spaces, and removed duplicate feature-branch push/PR CI runs.
- Added one shared Windows/Linux local launcher with clear prerequisite checks, non-destructive environment handling, a custom port, and an isolated startup check.
- Added fresh-checkout startup CI on Windows and Linux with Node 22.12/24, plus Windows Chromium UI coverage.
- Refined the React interface with a local SVG identity, simpler explanations, restrained movement, readable text throughout transitions, keyboard navigation, and reduced-motion support.
- Fixed recoverable sign-out failures, malformed domain-route handling, misleading history-error states, and a validation-library CSP conflict without weakening browser security.
- Fixed settings-form initialisation and refresh races: saved values are present before editing, drafts survive refreshes, and controls are locked while saving.
- Fixed a WebKit click race caused by smooth page scrolling moving controls during a click; visual transitions remain enabled with reduced-motion support.
- The preceding launch-polish milestone expanded the suite to 472 Python and 72 frontend tests, with 12 browser checks per profile including 320px layout, keyboard and CSP regressions; the deep-debug review records the newer suite.
- Made source packaging preserve the last archive when checkout validation fails and explicitly require PowerShell 7.
- Added a plain-language project tour, clearer Windows/Linux setup and testing guidance, and a configuration reference separate from the main overview.
- Grouped the original academic documents, progress records, and figures in `docs/academic/archive/`, preserving the earlier work and repairing references.
- Added a documentation-link regression test covering both the current guides and the academic archive.
- Renamed the active product from AuroraEdge to NorthFlux Security.
- Preserved the AuroraEdge project history and legacy local database compatibility.
- Replaced the primary browser interface with a responsive React 19 and TypeScript single-page application built by Vite.
- Added authenticated `/api/v1` session, bootstrap, and dashboard contracts while retaining compatibility routes used by existing backend workflows.
- Added same-origin API handling with cookie sessions, per-session CSRF headers, structured error responses, and no token storage in browser local or session storage.
- Added accessible operator workflows for sign-in, overview, single and batch scans, managed domains, domain history, settings, DNS record generation, privacy, and not-found routes.
- Added production serving for local, fingerprinted frontend assets, safe SPA deep links, immutable asset caching, and a strict CSP without inline scripts, inline styles, or third-party frontend resources.
- Retained the previous server-rendered interface only as a deprecated development fallback; production fails closed without the compiled React application and rolls back through a previously tested image or revision.
- Changed startup to preserve scan history by default.
- Changed the clear-all action to remove generated reports with scan, managed-domain, and alert data while preserving application settings and logs.
- Made demo mode, scheduled monitoring, and automatic DNS remediation explicit opt-ins.
- Added production-mode authentication checks and browser session login.
- Added unique, expiring, revocable browser sessions with token-rotation invalidation, origin checks, and per-session CSRF protection.
- Added bounded login requests, failed-login throttling, output escaping, and stored-data validation for legacy rows.
- Removed plaintext Cloudflare credential capture from the Windows launcher.
- Stopped accepting Cloudflare secrets through the production settings API and added safe migration away from legacy database-stored credentials.
- Made TXT remediation preserve unrelated records and made DKIM remediation stop when a provider-specific target cannot be identified safely.
- Added a non-root Docker image, hardened Compose profile, and deployment guidance.
- Added isolated runtime path overrides for state, reports, and logs, including disposable browser-test storage.
- Added a multi-stage container build that tests and compiles the frontend separately and excludes Node.js and frontend dependencies from the production runtime.
- Added 57 Vitest unit/component tests with coverage gates and nine Playwright operator journeys across Chromium, Firefox, WebKit, and a Pixel 7 mobile profile.
- Expanded the Python baseline to 439 passing tests and added API-contract, concurrency, deletion-safety, and production frontend-serving coverage.
- Added liveness and writable-storage readiness probes, cross-platform CI, Ruff, Bandit, dependency auditing, full-history secret scanning, browser tests, container tests, and clean-release archive checks.
- Refreshed runtime and development dependencies; the declared dependency sets have no known vulnerabilities in the release audit performed on 2026-09-21.
- Labelled the retained vendor feature matrix and historical licensing and pricing comparisons as illustrative academic snapshots rather than current product claims.
- Reworked the main README around operators and developers.

Historical AuroraEdge releases are documented in the [academic archive](docs/academic/README.md).
