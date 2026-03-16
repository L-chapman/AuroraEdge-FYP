# Stage 2 — SPF recursion & DMARC strength

Enhancements:
- **SPF lookup counting** now follows include/redirect/exists and common lookup-causing mechanisms recursively with depth and fetch caps.
- **DMARC strength** column indicates `none`, `quarantine`, or `reject`.

## Run
```powershell
.\scripts\run.ps1 --domain example.com
```

Outputs are written to `reports\stage2_results_*.csv` and `.md`.
