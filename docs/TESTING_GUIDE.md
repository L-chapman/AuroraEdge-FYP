# AuroraEdge Testing Guide

## For Lecturers and Evaluators

AuroraEdge is an automated email authentication and cyber defence system for small organisations. This guide shows the quickest ways to test it.

---

## Quick Start

### Option A: Interactive Demo (Recommended)
```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
.\scripts\demo.ps1
```
This launches a simple menu with the main testing options.

### Option B: Web Dashboard
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
Expected: **395/395 tests passing**


---

## Output Files

After scanning, reports are saved to:
- `reports/auroraedge_results_YYYYMMDD_HHMMSS.csv` - Spreadsheet format
- `reports/auroraedge_results_YYYYMMDD_HHMMSS.md` - Markdown report

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
| Unit Tests | `pytest tests/ -v` | 395/395 passing |

### Optional (Owned Domain Only): Automatic DNS Remediation
If you have a Cloudflare-managed test domain and explicit permission, you can evaluate zero-touch remediation:

1. In `/settings`, set Cloudflare API Token + Zone ID (token scoped to a single zone).
2. In `/domains`, add the domain.
3. Confirm DNS changes are recorded in `logs/dns_audit.log` and that monitoring alerts are created.

Important: DKIM is intentionally not auto-fixed (requires mail-system key management). MTA-STS requires both DNS and HTTPS policy hosting; the DNS TXT is auto-applied, but the policy file still needs hosting.

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
