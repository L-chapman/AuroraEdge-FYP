# Stage 14 - Interactive Test Hub + Demo Script

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../README.md) and [`testing guide`](TESTING.md).

## Overview
Stage 14 added an interactive testing page for live domain scans and a demo script for evaluators.

## Features

### Test Hub (`/test`)

Located in `src/app/dashboard.py`:

#### Single Domain Scan
- Text input for domain entry
- Quick-select buttons for example domains
- Options for STARTTLS checks and remediation
- Real-time scanning with loading overlay

#### Batch Scan Mode
- Textarea for multiple domains (one per line)
- Comments supported (lines starting with #)
- Up to 20 domains per batch
- Progress indicator during scanning

#### Results Display
Each result shows:
- Domain name with grade badge
- Score (0-100) with visual bar
- Protocol check status (SPF, DKIM, DMARC, MTA-STS, TLS-RPT)
- Remediation recommendations (if enabled)
- Expandable details section

### API Endpoint

```python
@app.post("/api/scan")
async def scan_domains(request: ScanRequest):
    """Scan domains via API"""
    results = []
    for domain in request.domains[:20]:  # Limit to 20
        scan = scan_domain(domain, starttls=request.starttls)
        evaluation = evaluate(scan)
        remediation = generate_remediation(scan) if request.remediation else []
        results.append({
            "domain": domain,
            "scan": scan,
            "evaluation": evaluation,
            "remediation": remediation
        })
    return {"results": results}
```

### Ethical & Safety Framing for Auto-Fix

Auto-fix is intentionally limited for ethical and practical reasons. It supports a small set of DNS-only fixes once a domain is onboarded with Cloudflare credentials.

- **Safety controls:** Only apply to domains you own or have explicit permission to manage. Cloudflare tokens must be scoped to **Zone:DNS:Edit** for a single zone. Once configured, auto-fix runs automatically for managed domains (no per-fix prompt).
- **Operational risk:** Changing SPF/DMARC/TLS-RPT can affect deliverability and enforcement. This is why remediation is limited to a small subset and is designed to be **auditable**.
- **Rollback & audit:** All DNS changes are logged for an audit trail (`logs/dns_audit.log`) and the monitoring system records automation events as Alerts.
- **DKIM scope:** AuroraEdge can auto-configure DKIM for supported providers where the selector pattern is known safely. If the provider cannot be identified, AuroraEdge reports the issue and gives manual guidance instead of guessing.

Additional limitation:
- **BIMI** is not auto-fixed. It is mainly a branding layer rather than a core protection control, and it also needs extra assets such as a logo and sometimes a VMC.

### Demo Script

Located in `scripts/demo.ps1`:

```powershell
# Interactive demo for evaluators
.\scripts\demo.ps1
```

The demo script:
1. Runs system verification
2. Scans example domains (good and bad configurations)
3. Starts the dashboard
4. Opens the Test Hub in default browser
5. Provides guided walkthrough instructions

### Quick Start

#### Test Hub
```powershell
.\scripts\serve.ps1
# Open: http://127.0.0.1:8080/test (or the port printed by serve.ps1)
```

#### Demo Mode
```powershell
.\scripts\demo.ps1
```

## Test Dataset

`domains.txt` contains 50+ domains for academic testing:
- Major tech companies (google.com, microsoft.com)
- UK universities (ulster.ac.uk, qub.ac.uk)
- Government sites (gov.uk, ncsc.gov.uk)
- Known good configurations (mailchimp.com, sendgrid.com)
- Mixed configurations for variety

## Tests
- `test_dashboard.py::test_dashboard_health_and_home`
- `test_dashboard_auth.py::test_dashboard_token_enforcement`
