# Stage 2 — SPF recursion & DMARC strength

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../README.md) and [`testing guide`](TESTING.md).

Enhancements:
- **SPF lookup counting** now follows include/redirect/exists and common lookup-causing mechanisms recursively with depth and fetch caps.
- **DMARC strength** column indicates `none`, `quarantine`, or `reject`.

## Run
```powershell
.\scripts\run.ps1 --domain example.com
```

Outputs are written to `reports\stage2_results_*.csv` and `.md`.
