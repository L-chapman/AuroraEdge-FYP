# Stage 7 - Dashboard v1 (FastAPI)

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../../../README.md) and [`testing guide`](../../TESTING.md). Return to the [archive guide](../README.md).

## Configure
Add to `.env` (or keep empty for dev/open):
```
DASH_TOKEN=aurora-dev
DASH_BIND_HOST=127.0.0.1
DASH_PORT=8080
```

## Run
```powershell
.\scripts\serve.ps1
```

Open: `http://127.0.0.1:8080/?token=aurora-dev` (or use `Authorization: Bearer <token>`). If you run on a different port, substitute accordingly.

## Features
- Latest CSV rendering.
- Severity counts (OK/WARN/HIGH/INFO/OTHER) and average score at a glance.
- Download links for latest CSV and Markdown reports.
- API: `/health`, `/api/runs`, `/api/latest`, `/api/summary`, `/download/latest`.
