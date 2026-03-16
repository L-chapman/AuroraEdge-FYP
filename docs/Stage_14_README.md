# Stage 14 - Interactive Test Hub + Demo Script

## Overview
Week 18 deliverable: Created an interactive testing interface for live domain scanning and a comprehensive demo script for evaluators.

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

Auto-fix is intentionally constrained for ethical and professional practice. The current implementation supports **zero-touch remediation** for a limited set of DNS-only records once a domain is onboarded with Cloudflare credentials.

- **Safety controls:** Only apply to domains you own or have explicit permission to manage. Cloudflare tokens must be scoped to **Zone:DNS:Edit** for a single zone. Once configured, auto-fix runs automatically for managed domains (no per-fix prompt).
- **Operational risk:** Changing SPF/DMARC/TLS-RPT can affect deliverability and enforcement. This is why remediation is limited to a small subset and is designed to be **auditable**.
- **Rollback & audit:** All DNS changes are logged for an audit trail (`logs/dns_audit.log`) and the monitoring system records automation events as Alerts.
- **Why DKIM is not auto-fixed:** DKIM requires **private key generation, selector alignment, and mail server signing configuration**. Automating DNS alone can create a false sense of security and may break existing signing setups, so DKIM is reported but not automatically remediated.

Additional limitation:
- **MTA-STS** requires both a DNS TXT record and an HTTPS policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`. AuroraEdge can publish the DNS TXT record automatically, but hosting the policy file is outside DNS-only automation.

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
