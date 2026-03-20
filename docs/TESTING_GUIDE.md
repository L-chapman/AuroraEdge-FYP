# AuroraEdge Testing Guide

## For Lecturers, Markers, and Other Test Users

AuroraEdge is an automated email authentication and cyber defence system for small organisations. This guide keeps the testing steps simple and practical.

---

## Quick Start

If you only want the simplest route, use **Option A**.

### Option A: Double-click Start (Recommended)
```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
.\START.bat
```
Then open: **http://127.0.0.1:8080/test**

This is the same route opened automatically by `START.bat`.

### Option B: Interactive Demo Script
```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
.\scripts\demo.ps1
```
This opens a simple guided menu with the main testing options.

### Option C: Start the Web Dashboard Manually
```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```
Then open: **http://127.0.0.1:8080/test**

---

## CLI Testing

### Single Domain Scan
```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
python -m app.cli --domain google.com
```

### Multiple Domains
```powershell
python -m app.cli --domains domains.txt
```

### With Remediation Recommendations
```powershell
python -m app.cli --domain bbc.co.uk --remediation
```

### Test Your Own Domain
```powershell
python -m app.cli --domain belfast.ac.uk --remediation
```

If you do not own a domain, use `auroraedge.co.uk` as the demo domain.

---

## Dashboard Testing

### 1. Start the Dashboard
```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
$env:DASH_TOKEN = ""  # Disable auth for testing
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

### 2. Available Pages

| URL | Description |
|-----|-------------|
| http://127.0.0.1:8080 | Main Dashboard - View scan results |
| http://127.0.0.1:8080/test | **Test Hub** - Scan any domain interactively |
| http://127.0.0.1:8080/domains | **My Domains** - Managed domains + monitoring |
| http://127.0.0.1:8080/generator | **Generator** - DNS record generator wizard |
| http://127.0.0.1:8080/settings | **Settings** - Cloudflare + monitoring interval |
| http://127.0.0.1:8080/health | Health check endpoint |
| http://127.0.0.1:8080/api/runs | List all scan reports |

### 3. Test Hub Features
The Test Hub (`/test`) allows you to:
- **Single Domain Scan**: Enter any domain and view the results
- **Batch Scan**: Paste multiple domains (up to 20)
- **Quick Examples**: Click on suggested domains (Google, Microsoft, etc.)
- **Results**: See grades, scores, and check status
- **Remediation Recommendations**: View suggested fixes
- **Auto-Fix**: If Cloudflare settings are entered, supported fixes can be applied from the page

---

## What Gets Tested

AuroraEdge checks the following email security standards:

| Check | Standard | Description |
|-------|----------|-------------|
| **SPF** | RFC 7208 | Sender Policy Framework - authorizes sending servers |
| **DKIM** | RFC 6376 | DomainKeys - cryptographic email signatures |
| **DMARC** | RFC 7489 | Domain-based Message Authentication - policy enforcement |
| **MTA-STS** | RFC 8461 | Mail Transfer Agent Strict Transport Security |
| **TLS-RPT** | RFC 8460 | TLS Reporting - delivery problem notifications |

---

## Test Scenarios

### Scenario 1: Well-Configured Domain
**Expected Result**: Grade A/A+, Score 85+
```
google.com, microsoft.com, cloudflare.com
```

### Scenario 2: Average Configuration
**Expected Result**: Grade B/C, Score 50-80
```
Most educational institutions (e.g., belfast.ac.uk)
```

### Scenario 3: Missing Configurations
**Expected Result**: Grade D/F, Score 0-40
```
Small websites without email security
```

---

## Run Unit Tests
```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
$env:PYTHONPATH = "$PWD\src"
python -m pytest tests/ -v
```
Expected: **397/397 tests passing**


---

## Output Files

After scanning, reports are saved to:
- `reports/indexed/auroraedge_results_YYYYMMDD_HHMMSS.csv` - spreadsheet format
- `reports/indexed/auroraedge_results_YYYYMMDD_HHMMSS.md` - Markdown report

This keeps the proof-of-testing in one clear place.

Database is stored at:
- `state/auroraedge.db` - SQLite database with scan history

---

## Troubleshooting

### "ModuleNotFoundError"
```powershell
$env:PYTHONPATH = "$(Get-Location)\src"
```

### "Port already in use"
```powershell
# Use a different port
python -m uvicorn app.dashboard:app --port 8001
```

### "No reports found"
Run a scan first:
```powershell
python -m app.cli --domain google.com
```

---

## Evaluation Checklist

| Feature | How to Test | Expected Result |
|---------|-------------|-----------------|
| CLI Single Scan | `--domain example.com` | Grade, score, and check results |
| CLI Batch Scan | `--domains domains.txt` | Multiple results, CSV/MD reports |
| Remediation | `--remediation` | Fix recommendations per issue |
| Dashboard View | Open `/` in browser | Stats, charts, result table |
| Interactive Test | Open `/test` in browser | Form to scan any domain |
| Real-time Updates | Run scan while dashboard open | Dashboard auto-refreshes |
| Database | Check `state/auroraedge.db` | Persistent scan history |
| Unit Tests | `pytest tests/ -v` | 397/397 passing |

### Optional (Owned Domain Only): Automatic DNS Fixing
If you have a Cloudflare-managed test domain and explicit permission, you can test the automatic fixing safely:

1. In `/settings`, set Cloudflare API Token + Zone ID (token scoped to a single zone).
2. In `/domains`, add the domain.
3. Confirm DNS changes are recorded in `logs/dns_audit.log` and that monitoring alerts are created.

Important notes:
- DKIM can be auto-configured for some known providers where AuroraEdge can detect the right selector pattern safely.
- MTA-STS can now be completed fully through Cloudflare, including the HTTPS policy file served by a Worker.
- BIMI is reported, but not auto-fixed. It is mainly branding, not core protection, and it needs logo/VMC assets outside normal DNS fixing.

---

## Project Information

**Student**: Leon Chapman  
**Student ID**: 50030738  
**Course**: Cybersecurity & Networking Infrastructure  
**Institution**: Belfast Metropolitan College  
**Year**: 2025/2026 Final Year Project  

---

## References

- RFC 7208 - Sender Policy Framework (SPF)
- RFC 6376 - DomainKeys Identified Mail (DKIM)
- RFC 7489 - Domain-based Message Authentication (DMARC)
- RFC 8461 - SMTP MTA Strict Transport Security (MTA-STS)
- RFC 8460 - SMTP TLS Reporting (TLS-RPT)
