# Changelog

This project follows semantic versioning from the NorthFlux Security rename onward.

## 3.2.0 - Unreleased

- Renamed the active product from AuroraEdge to NorthFlux Security.
- Preserved the AuroraEdge project history and legacy local database compatibility.
- Changed startup to preserve scan history by default.
- Made demo mode, scheduled monitoring, and automatic DNS remediation explicit opt-ins.
- Added production-mode authentication checks and browser session login.
- Added unique, expiring, revocable browser sessions with token-rotation invalidation, origin checks, and per-session CSRF protection.
- Added bounded login requests, failed-login throttling, output escaping, and stored-data validation for legacy rows.
- Removed plaintext Cloudflare credential capture from the Windows launcher.
- Stopped accepting Cloudflare secrets through the production settings API and added safe migration away from legacy database-stored credentials.
- Made TXT remediation preserve unrelated records and made DKIM remediation stop when a provider-specific target cannot be identified safely.
- Added a non-root Docker image, hardened Compose profile, and deployment guidance.
- Added liveness and writable-storage readiness probes, cross-platform CI, Ruff, Bandit, and dependency auditing.
- Refreshed runtime and development dependencies; the declared dependency sets have no known vulnerabilities in the release audit performed on 2026-09-20.
- Labelled the retained vendor feature matrix as a legacy illustrative snapshot and removed unsupported licensing and pricing claims.
- Reworked the main README around operators and developers.

Historical AuroraEdge releases are documented in the academic project records under `docs/`.
