# Stage 6 — Unit tests for rules + scanner (no external network)

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../../../README.md) and [`testing guide`](../../TESTING.md). Return to the [archive guide](../README.md).

Run tests:
```powershell
.\scripts\test.ps1
```

Notes:
- Tests monkeypatch DNS/HTTP so they are deterministic and offline.
- Rule tests assert severity/violations; scanner tests assert parsed fields.
