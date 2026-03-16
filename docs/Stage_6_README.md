# Stage 6 — Unit tests for rules + scanner (no external network)

Run tests:
```powershell
.\scripts\test.ps1
```

Notes:
- Tests monkeypatch DNS/HTTP so they are deterministic and offline.
- Rule tests assert severity/violations; scanner tests assert parsed fields.
