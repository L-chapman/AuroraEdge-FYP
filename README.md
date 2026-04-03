# AuroraEdge Security

**Designing and Implementing an Automated Email Authentication and Cyber Defence System for Small Organisations**

**Final Year Project** | Leon Chapman (50030738)  
Belfast Metropolitan College | Cybersecurity & Networking Infrastructure  
Academic Year 2025/2026

---

## What It Does

Email attacks like phishing and spoofing are still one of the biggest problems in cybersecurity. Systems like SPF, DKIM, and DMARC exist to protect email domains, but most small businesses either don't set them up correctly or don't know how to maintain them.

AuroraEdge Security is an automated cyber defence system built to make this easier. It:

- **Detects** misconfigurations across SPF, DKIM, DMARC, MTA-STS, and TLS-RPT
- **Scores** each domain's security posture (0–100, letter grades A+ to F)
- **Defends** by automatically fixing supported DNS records through Cloudflare
- **Monitors** domains continuously and alerts on security drift
- **Reports** with step-by-step remediation advice

The goal is to give small organisations strong email protection without expecting them to be DNS experts.

If you have Cloudflare credentials, AuroraEdge can **automatically fix** supported DNS records for you, so there is far less manual DNS editing to do.

---

## Installation Guide

### Prerequisites

Before you begin, make sure you have the following installed:

- **Python 3.10+** — [Download here](https://www.python.org/downloads/). On Windows, tick **"Add Python to PATH"** during installation.
- **Git** — [Download here](https://git-scm.com/downloads).
- An **internet connection** — required for cloning, installing dependencies, and DNS lookups at runtime.
- **(Optional)** A Cloudflare account with an API token if you want to use the auto-fix features.

---

### Clone the Repository

```bash
git clone https://github.com/L-chapman/AuroraEdge-FYP.git
cd AuroraEdge-FYP
```

---

### Quick Start (Windows)

The simplest approach on Windows is to double-click **`START.bat`**. It automatically:

1. Creates a Python virtual environment (`.venv`)
2. Installs all dependencies from `requirements.txt`
3. Starts the web dashboard and opens it in the browser

No further steps are needed for most Windows users.

---

### Manual Setup (All Platforms)

For macOS/Linux users, or anyone who prefers manual control:

**Create and activate a virtual environment:**

```bash
# Create
python -m venv .venv

# Activate (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Activate (macOS / Linux)
source .venv/bin/activate
```

**Install dependencies:**

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Set the Python path:**

```bash
# Windows PowerShell
$env:PYTHONPATH = "$PWD\src"

# macOS / Linux
export PYTHONPATH="$(pwd)/src"
```

**Create required directories (if they don't already exist):**

```bash
# macOS / Linux
mkdir -p reports state logs

# Windows PowerShell
New-Item -ItemType Directory -Force reports, state, logs
```

**(Optional) Configure environment variables:**

Copy `.env.example` to `.env` and update the values as needed — especially the Cloudflare credentials if you plan to use auto-fix:

```bash
cp .env.example .env
```

---

### Verify the Installation

Run the built-in system check:

```bash
python verify_system.py
```

Optionally, run the full test suite to confirm everything is working:

```bash
python -m pytest tests/ -v
```

---

### Launch the Dashboard

```bash
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

Then open **http://127.0.0.1:8080/test** in your browser.

---

## Start Here

### Easiest Option: Double-click `START.bat`

That is all most people need to do. It will:
1. Create a Python virtual environment
2. Install all dependencies
3. Open the Test Hub in your browser automatically

> **You only need:** Python 3.10+ ([download](https://www.python.org/downloads/)) and an internet connection.

---

## Using the Dashboard

Once the server is running, the browser should open automatically. If it does not, open **http://127.0.0.1:8080/test** in your browser.

### Pages

| Page | URL | What It Does |
|------|-----|-------------|
| **Dashboard** | `/` | Defence overview — domain health, scores, alerts, grade distribution |
| **Scan Domains** | `/test` | Analyse any domain and get a full security assessment |
| **My Domains** | `/domains` | Add your domains for continuous monitoring and auto-defence |
| **Generator** | `/generator` | DNS record generator wizard — build SPF, DMARC, MTA-STS records |
| **Settings** | `/settings` | Cloudflare credentials, monitoring intervals, export/import |

### If You Only Want To Try It Quickly

1. Open **http://127.0.0.1:8080/test**
2. Type a domain such as `google.com`, `bbc.co.uk`, or `example.com`
3. Click **Scan Domain**
4. Read the grade, score, and plain-English advice
5. Your result is saved automatically to the Dashboard

### Sample Domains to Try

| Domain | Expected Grade | Why |
|--------|---------------|-----|
| `google.com` | A | Strong email security |
| `microsoft.com` | A | Enterprise-level |
| `github.com` | A/B | Good configuration |
| `example.com` | D/F | Minimal security (test domain) |

### Live Auto-Fix Demo

The domain **`auroraedge.co.uk`** is the live demo domain used for testing and marking.
It is safe to scan even if you do not own a domain yourself.

At different points in the demo, this domain may be left in a weaker state on purpose so the auto-fix flow can be shown clearly. If it has already been fixed, you can still scan it and see a real working setup.

**Quick walkthrough:**

1. Open the **Scan** page (`/test`).
2. Click the **auroraedge.co.uk** quick-domain button or type the domain yourself.
3. Press **Scan Domain**.
4. Read the grade and the issues found.
5. If Cloudflare credentials are already set up on that machine, click **Auto-Fix DNS**.
6. Press **Rescan** to confirm the change.

> **Important:** You can scan any public domain. Auto-fix only works for domains you own, control, or have explicit permission to manage in Cloudflare.

**To reset the demo** for another live walkthrough:

```powershell
.\.venv\Scripts\Activate.ps1
python scripts/demo_prep.py             # weaken selected demo records
python scripts/demo_prep.py --restore   # put them back if needed
```

---

## Automated DNS Fixing (Cloudflare)

AuroraEdge does more than scan. When Cloudflare credentials are provided, it can automatically fix supported DNS records.

Supported automatic fixes include:

- SPF
- DMARC
- TLS-RPT
- MTA-STS DNS
- MTA-STS HTTPS policy hosting through a Cloudflare Worker
- DKIM for known providers where the selector pattern can be detected safely

1. Go to **Settings** (`/settings`)
2. Enter your Cloudflare API Token and Zone ID
3. Add a domain in **My Domains** (`/domains`)
4. The system scans, auto-fixes supported records, and begins continuous monitoring
5. All changes are logged to `logs/dns_audit.log` and shown as alerts in the dashboard

If Worker route creation is blocked by token permissions, you can also add an optional Cloudflare **Global API Key** and **account email** in Settings for that specific route step.

---

## Command Line (Optional)

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

**Current result:** 397 tests passing across functional, security, stress, and backend QA test suites.

Proof-of-testing files are kept in `reports/indexed/` so the main project stays tidy.

---

## Demo Domain (No Cloudflare Required)

If you do not have your own domain or Cloudflare account, you can still test
the full system using the pre-configured demo domain **`auroraedge.co.uk`**.

**What you can do without Cloudflare credentials:**

- Scan `auroraedge.co.uk` and view the full security assessment
- View grades, scores, violations, and remediation recommendations
- Generate DNS record suggestions via the Generator page
- Use the CLI: `python -m app.cli --domain auroraedge.co.uk --remediation`
- Scan any other public domain (e.g. `google.com`, `bbc.co.uk`)

**What still needs Cloudflare credentials:**

- Automatic DNS fixing from the **Auto-Fix DNS** button
- Adding domains to **My Domains** with automatic defence
- Cloudflare Worker deployment for MTA-STS policy hosting

> The demo domain is there so a marker or user can still test the platform properly without needing to buy or manage a domain first.

### Why BIMI Is Not Auto-Fixed

BIMI is mainly a branding extra, not a core email authentication control like SPF, DKIM, or DMARC.

It also needs assets outside normal DNS fixing, such as:

- a brand logo in the correct SVG format
- in some cases a Verified Mark Certificate (VMC)
- brand approval and presentation decisions

Because of that, AuroraEdge reports BIMI if it is missing, but it does not try to auto-fix it. That is the right trade-off: protect mail first, branding second.

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
│   ├── rules.py            # 20 evaluation rules, scoring, grading
│   ├── dashboard.py        # FastAPI cyber defence dashboard
│   ├── database.py         # SQLite persistence (WAL mode, thread-safe)
│   ├── dns_fix.py          # Cloudflare auto-remediation engine
│   ├── cli.py              # Command-line interface
│   ├── analysis.py         # Statistics and chart generation
│   ├── logging_config.py   # Structured JSON logging
│   └── main.py             # CLI entry point
│
├── tests/                  ← 397 automated tests
├── docs/                   ← Stage READMEs, weekly logs, guides
├── reports/
│   ├── indexed/            ← Current proof-of-testing outputs
│   └── archive/            ← Older historical scan results
├── scripts/
│   ├── demo.ps1            # Interactive demo for evaluators
│   ├── demo_prep.py        # Weaken/restore DNS for demo flow
│   └── lab_experiment.py   # Lab evaluation protocol
├── state/                  ← SQLite database
└── logs/                   ← Runtime logs (auto-created)
```

---

## API Endpoints (36 total)

### Pages

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard home |
| `/test` | GET | Interactive scanner |
| `/domains` | GET | Managed domains page |
| `/generator` | GET | DNS record generator wizard |
| `/settings` | GET | Settings page |
| `/health` | GET | Health check (JSON) |

### Scan & Remediation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Scan one or more domains |
| `/api/rescan/{domain}` | POST | Rescan a single domain |
| `/api/apply-fix` | POST | Apply DNS fixes via Cloudflare |
| `/api/fix-status` | GET | Cloudflare availability check |

### Data & Reports

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/runs` | GET | All scan report files |
| `/api/latest` | GET | Latest scan results |
| `/api/summary` | GET | Aggregate statistics |
| `/api/stats` | GET | Score distribution data |
| `/api/domain/{domain}` | GET | Single-domain results |
| `/api/search` | GET | Search scan results |
| `/api/history/{domain}` | GET/DELETE | Domain scan history |
| `/api/stream` | GET | SSE real-time updates |
| `/api/report/pdf/{domain}` | GET | PDF report download |
| `/download/latest` | GET | Download latest report |
| `/download/{filename}` | GET | Download specific report |
| `/api/data/clear` | POST | Clear all scan data |

### Domain Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/managed-domains` | GET/POST | Managed domains CRUD |
| `/api/managed-domains/{domain}` | DELETE | Remove managed domain |
| `/api/settings` | GET/POST | App settings |
| `/api/settings/test-cloudflare` | GET | Validate Cloudflare credentials |
| `/api/alerts` | GET | Monitoring alerts |
| `/api/alerts/{id}/acknowledge` | POST | Acknowledge an alert |

### Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/explanations/all` | GET | All rule & severity explanations |
| `/api/explanations/rule/{id}` | GET | Single rule explanation |
| `/api/explanations/severity/{level}` | GET | Severity level explanation |
| `/api/tools/comparison` | GET | Tool comparison data |

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
| `docs/Stage_*_README.md` | Development stage snapshots for project history |

---

## Privacy & Legal

AuroraEdge only queries **publicly available DNS and HTTPS security records** —
the same data any mail server or browser can see. No mailbox credentials are
tested, no mail is sent, and no private third-party systems are accessed.

Full compliance details: UK Computer Misuse Act 1990, GDPR considerations,
Cloudflare API Terms of Service, and Spamhaus usage terms are documented in
[docs/PRIVACY_AND_ETHICS.md](docs/PRIVACY_AND_ETHICS.md).

---

## License

This project was developed as a Final Year Project for academic assessment.
All rights reserved © 2025–2026 Leon Chapman.
