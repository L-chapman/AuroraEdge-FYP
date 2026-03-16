# Stage 3 — DKIM selector discovery + nicer Markdown tables

Adds DKIM selector discovery for common providers (google, s1/s2, selector1/2, mandrill, sendgrid, zoho, amazonses, mailgun, sparkpost, mailchimp, klaviyo …).
Outputs now include a Markdown table per run.

## Run
```powershell
.\scripts\run.ps1 --domain example.com
```

Results land in `reports\stage3_results_*.csv` and `.md`.
