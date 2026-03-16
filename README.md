# AuroraEdge Security

**Designing and Implementing an Automated Email Authentication and Cyber Defence System for Small Organisations**

**Final Year Project** | Leon Chapman (50030738)  
Belfast Metropolitan College | Cybersecurity & Networking Infrastructure  
Academic Year 2025/2026

---

## What Is It?

Email attacks like phishing and spoofing are still one of the biggest problems in cybersecurity. Systems like SPF, DKIM, and DMARC exist to protect email domains, but most small businesses either don't set them up correctly or don't know how to maintain them.

AuroraEdge Security is an automated cyber defence system that solves this. It:

- **Detects** misconfigurations across SPF, DKIM, DMARC, MTA-STS, and TLS-RPT
- **Scores** each domain's security posture (0–100, letter grades A+ to F)
- **Defends** by automatically fixing DNS records via Cloudflare API
- **Monitors** domains continuously and alerts on security drift
- **Reports** with step-by-step remediation advice

The goal is to give small organisations enterprise-grade email defence without needing them to understand the technical details.

If you have Cloudflare credentials, AuroraEdge can **automatically fix** DNS records for you — no manual DNS editing required.

---

## How to Run It

### Double-click `START.bat`

That's it. It will:
1. Create a Python virtual environment
2. Install all dependencies
3. Open the dashboard in your browser at **http://127.0.0.1:8080**

> **Requires:** Python 3.10+ ([download](https://www.python.org/downloads/)) and an internet connection.

---

## Using the Dashboard

Once the server is running, open **http://127.0.0.1:8080** in your browser.

### Pages

| Page | URL | What It Does |
|------|-----|-------------|
| **Dashboard** | `/` | Defence overview — domain health, scores, alerts, grade distribution |
| **Scan Domains** | `/test` | Analyse any domain and get a full security assessment |
| **My Domains** | `/domains` | Add your domains for continuous monitoring and auto-defence |
| **Settings** | `/settings` | Cloudflare credentials, monitoring intervals, export/import |

### Try a Scan

1. Go to **http://127.0.0.1:8080/test**
2. Type a domain (e.g. `google.com`, `belfastmet.ac.uk`, `example.com`)
3. Click **Scan Domain**
4. See the security grade, score, and what needs defending
5. Results auto-save to the Dashboard

### Sample Domains to Try

| Domain | Expected Grade | Why |
|--------|---------------|-----|
| `google.com` | A | Strong email security |
| `microsoft.com` | A | Enterprise-level |
| `github.com` | A/B | Good configuration |
| `example.com` | D/F | Minimal security (test domain) |

### Live Auto-Fix Demo

The domain **`auroraedge.co.uk`** is pre-configured as the live demo domain.
It has **intentional weaknesses** — SPF set to softfail (`~all`), DMARC at
`p=quarantine` with only 50% coverage (`pct=50`), and no MTA-STS policy —
so the automated remediation engine has real issues to detect and fix.

**Quick walkthrough:**

1. Open the **Scan** page (`/test`).
2. Click the **⭐ auroraedge.co.uk (Auto-Fix Demo)** quick-domain button and press **Scan Domain**.
3. Observe the low security grade (D) and the violations listed (SPF softfail, DMARC quarantine at 50%, MTA-STS missing, etc.).
4. Click **🔧 Auto-Fix DNS** on the scan results — the system will harden/create DNS records via the Cloudflare API in real time.
5. Press **🔄 Rescan** and watch the grade improve as each record is now corrected.
6. The system performs a **post-fix verification scan** and shows the grade change (e.g. D → B).

> **Note:** Only `auroraedge.co.uk` supports auto-fix because it is the Cloudflare-managed zone whose credentials are stored in Settings. You can scan any other domain freely, but auto-fix will only work for domains within this zone.

**To reset the demo** (re-break the records for a fresh demonstration):

```powershell
.\.venv\Scripts\Activate.ps1
python scripts/demo_prep.py          # delete DMARC & TLS-RPT records
python scripts/demo_prep.py --restore  # put them back if needed
```

---

## Automated DNS Remediation (Cloudflare)

AuroraEdge's cyber defence capability goes beyond scanning — it can **automatically fix** SPF, DMARC, TLS-RPT, and MTA-STS DNS records when Cloudflare credentials are provided. This is the "automated" part of the project title.

1. Go to **Settings** (`/settings`)
2. Enter your Cloudflare API Token (Zone:DNS:Edit scope) and Zone ID
3. Add a domain in **My Domains** (`/domains`)
4. The system scans, auto-fixes supported records, and begins continuous monitoring
5. All remediations logged to `logs/dns_audit.log` and visible as Dashboard Alerts

---

## Command Line (Alternative)

If you prefer the terminal over the web UI:

```powershell
# Activate environment
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"

# Scan a single domain
python -m app.cli --domain google.com

# Scan with fix recommendations
python -m app.cli --domain example.com --remediation

# Scan multiple domains from file
python -m app.cli --domains domains.txt

# Apply DNS fixes via Cloudflare
python -m app.cli --domain example.com --apply-fix
```

---

## Running Tests

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
python -m pytest tests/ -v
```

**Result:** 392 tests passing across functional, security, stress, and backend QA suites

---

## What It Checks

| Check | Standard | What It Means |
|-------|----------|---------------|
| **SPF** | RFC 7208 | Which servers are allowed to send email for a domain |
| **DKIM** | RFC 6376 | Cryptographic signing of email messages |
| **DMARC** | RFC 7489 | Policy for handling SPF/DKIM failures |
| **MTA-STS** | RFC 8461 | Enforcing TLS for mail transport |
| **TLS-RPT** | RFC 8460 | Reporting on TLS delivery issues |
| **STARTTLS** | RFC 3207 | Encryption capability of mail servers |
| **MX Records** | — | Mail exchange server configuration |

### Grading Scale

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ / A | 90–100 | Excellent — all protections in place |
| B | 75–89 | Good — minor improvements recommended |
| C | 60–74 | Fair — some security gaps |
| D | 40–59 | Poor — significant vulnerabilities |
| F | 0–39 | Failing — critical security issues |

---

## Project Structure

```
AuroraEdge_FYP/
├── START.bat               ← Double-click to launch
├── README.md               ← This file
├── requirements.txt        ← Python dependencies
├── domains.txt             ← 50-domain academic dataset
├── verify_system.py        ← Quick system check script
├── .env.example            ← Environment variable reference
│
├── src/app/                ← Source code (10 modules)
│   ├── scanner.py          # DNS lookups (SPF, DKIM, DMARC, MTA-STS, TLS-RPT)
│   ├── rules.py            # 17 evaluation rules, scoring, grading
│   ├── dashboard.py        # FastAPI cyber defence dashboard
│   ├── database.py         # SQLite persistence (WAL mode, thread-safe)
│   ├── dns_fix.py          # Cloudflare auto-remediation engine
│   ├── cli.py              # Command-line interface
│   ├── analysis.py         # Statistics and chart generation
│   ├── logging_config.py   # Structured JSON logging
│   └── main.py             # CLI entry point
│
├── tests/                  ← 392 automated tests
├── docs/                   ← Stage READMEs, weekly logs, guides
├── reports/archive/        ← Historical scan results
├── scripts/
│   ├── demo.ps1            # Interactive demo for evaluators
│   └── lab_experiment.py   # Lab evaluation protocol
├── state/                  ← SQLite database
└── logs/                   ← Runtime logs (auto-created)
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/test` | GET | Interactive scanner |
| `/settings` | GET | Settings page |
| `/health` | GET | Health check |
| `/api/scan` | POST | Scan domains |
| `/api/apply-fix` | POST | Apply DNS fixes via Cloudflare |
| `/api/fix-status` | GET | Cloudflare availability check |
| `/api/managed-domains` | GET/POST | Managed domains CRUD |
| `/api/settings` | GET/POST | App settings |
| `/api/settings/test-cloudflare` | GET | Validate Cloudflare credentials |
| `/api/alerts` | GET | Monitoring alerts |
| `/api/runs` | GET | All scan files |
| `/api/latest` | GET | Latest scan results |
| `/api/summary` | GET | Aggregate statistics |
| `/api/stream` | GET | SSE real-time updates |
| `/download/latest` | GET | Download report |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Run `$env:PYTHONPATH = "$PWD\src"` |
| Port 8080 in use | Change port: `--port 8081` |
| DNS timeout | Check internet connection |
| Virtual env not found | Run `python -m venv .venv` then activate |

---

## Documentation

| Document | Description |
|----------|-------------|
| `docs/TESTING_GUIDE.md` | Step-by-step testing instructions |
| `docs/FYP_SPEC.md` | Project specification |
| `docs/DEVELOPMENT_TIMELINE.md` | 24-week development timeline |
| `docs/STATUS.md` | Current project status and test breakdown |
| `docs/ACADEMIC_NOTEBOOK.md` | Design decisions and rationale |
| `docs/VERIFICATION_REPORT.md` | System verification report |
| `docs/weekly/` | Weekly development logs |
| `docs/PRIVACY_AND_ETHICS.md` | GDPR, CMA 1990, legal compliance |

---

## Privacy & Legal

AuroraEdge only queries **publicly available DNS records** — the same data any
browser or mail server can see. No authentication credentials are tested, no
mail is sent, and no private data is accessed.

Full compliance details: UK Computer Misuse Act 1990, GDPR Article 4(1),
Cloudflare API Terms of Service, and Spamhaus usage terms are documented in
[docs/PRIVACY_AND_ETHICS.md](docs/PRIVACY_AND_ETHICS.md).

---

## License

This project was developed as a Final Year Project for academic assessment.
All rights reserved © 2025–2026 Leon Chapman.
