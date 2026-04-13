# AuroraEdge Security

**Designing and Implementing an Automated Email Authentication and Cyber Defence System for Small Organisations**

**Final Year Project** | Leon Chapman (50030738)  
Belfast Metropolitan College | Cybersecurity & Networking Infrastructure  
Academic Year 2025/2026

---

## Overview

AuroraEdge Security is a local-first email security assessment and remediation platform built for small organisations.

It focuses on the email security controls that are commonly missing, misconfigured, or left too weak in real deployments:

- SPF
- DKIM
- DMARC
- MTA-STS
- TLS-RPT
- STARTTLS
- MX mail routing

AuroraEdge does not just detect problems. It also explains what they mean, scores the domain, stores results locally, and can automatically fix supported DNS records through Cloudflare when credentials are available.

This repository includes:

- A FastAPI web dashboard
- A command-line scanner
- SQLite-backed local state and history
- Report generation
- Cloudflare DNS auto-remediation
- Monitoring and alerting for managed domains
- A demo workflow for lecturers and evaluators
- A large automated test suite

---

## At A Glance

| Area | Details |
|------|---------|
| **Problem** | Small organisations often lack the expertise to configure and maintain secure email authentication records correctly |
| **Solution** | AuroraEdge scans domains, grades them, explains risks, recommends fixes, and can automate supported DNS changes |
| **Primary Interface** | FastAPI dashboard with pages for scanning, managed domains, DNS record generation, and settings |
| **Secondary Interface** | CLI for single-domain scans, batch scans, remediation reporting, and optional DNS fixing |
| **Storage** | SQLite database in `state/auroraedge.db`, report files in `reports/`, logs in `logs/` |
| **Optional Integration** | Cloudflare API for zero-touch DNS remediation and MTA-STS Worker deployment |
| **Verification** | `verify_system.py`, `scripts/demo.ps1`, and the `tests/` suite |

---

## What AuroraEdge Does

AuroraEdge is built around five practical jobs:

1. **Scan** public DNS and HTTPS resources for email security controls.
2. **Evaluate** the results using RFC-based rules, severity levels, and a 0-100 scoring model.
3. **Explain** why each issue matters and how to fix it in plain language.
4. **Store** scan results, settings, alerts, and local state for follow-up work.
5. **Defend** by applying supported Cloudflare DNS fixes for domains you own or are explicitly authorised to manage.

---

## How The Project Works

The main application flow is:

1. `src/app/scanner.py` performs DNS, HTTPS, and optional STARTTLS checks.
2. `src/app/rules.py` evaluates the raw scan output and assigns score, grade, severity, and remediation guidance.
3. `src/app/dashboard.py` exposes the web UI and API endpoints.
4. `src/app/cli.py` provides the command-line workflow for single and batch scans.
5. `src/app/database.py` stores scans, managed domains, settings, and alerts in SQLite.
6. `src/app/dns_fix.py` integrates with Cloudflare for supported DNS remediation and audit logging.
7. `src/app/analysis.py` calculates statistics used by reports and dashboard views.
8. `src/app/logging_config.py` centralises structured logging.

In practice, that means AuroraEdge can support four kinds of users from the same codebase:

- **Lecturers or markers** who just want to run the system and test a few domains
- **Developers** who want to inspect, verify, and extend the platform
- **Security testers** who prefer terminal-based scans and reports
- **Domain owners** who want ongoing monitoring and Cloudflare-backed auto-fix

---

## Choose Your Starting Option

| If you want to... | Best option | What to use |
|-------------------|-------------|-------------|
| **Try the project as quickly as possible** | Recommended | Double-click `START.bat` |
| **Show the project in a guided way** | Demo path | `scripts/demo.ps1` |
| **Run the web app manually** | Developer path | Activate `.venv`, set `PYTHONPATH`, run Uvicorn |
| **Use only the terminal** | CLI path | `python -m app.cli ...` |
| **Confirm the environment is healthy** | Verification path | `python verify_system.py` |
| **Run the full automated test suite** | Validation path | `python -m pytest tests/ -v` |

Important note:

- `START.bat` is the easiest first run because it creates the virtual environment, installs requirements, prepares folders, and starts the dashboard.
- `scripts/demo.ps1` is best used **after** the project has already been set up once.

---

## Getting The Project Files

This project can be used in more than one distribution model. Choose the one that matches how you received it.

### Option 1: You Already Have A Folder Copy

If the project was shared with you through Google Drive, OneDrive, email, USB, or a ZIP extract, you do **not** need Git.

1. Place the project folder somewhere convenient.
2. Open the folder.
3. Run `START.bat`.

If the folder was copied from another machine and the included `.venv` is unusable, `START.bat` will rebuild it automatically. If you ever need to do that manually, delete `.venv` and run `START.bat` again.

That is enough for most evaluators and test users.

### Option 2: Download A ZIP Or Shared-Drive Copy

1. Download the latest project archive or sync the shared folder.
2. Extract it if needed.
3. Open the extracted folder.
4. Run `START.bat`.

### Option 3: Clone With Git

Use this if the project is hosted in a Git repository and you have the repository URL.

```powershell
git clone <repository-url> AuroraEdge_FYP
cd AuroraEdge_FYP
```

Then continue with the setup steps below.

### How To Update Your Copy Later

#### If your copy is just a normal folder

Use one of these approaches:

1. Replace the folder with the latest ZIP or shared-drive version.
2. Copy the newer files over the old folder.
3. Re-run `START.bat` so the environment can refresh dependencies if needed.

#### If your copy is a real Git clone

```powershell
git pull
```

Then refresh the environment:

```powershell
python -m pip install -r requirements.txt
```

#### If `git pull` says `not a git repository`

That means your copy is a normal folder, not a Git checkout. Use the folder-copy update method instead of Git commands.

---

## Requirements

### Required

- Python 3.10 or newer
- Internet access for DNS and HTTPS checks
- Permission to run local scripts

### Optional

- Cloudflare account and API credentials if you want automatic DNS remediation
- PowerShell if you want to use the Windows demo script

### Platform Notes

- **Windows** is the primary path because this repository includes `START.bat` and a PowerShell demo script.
- **Linux/macOS** can still run the project, but you should use the manual setup steps rather than `START.bat`.

---

## Setup Instructions

## Option A: Windows Quick Setup

This is the simplest and recommended setup path.

1. Open the project folder.
2. Double-click `START.bat`.
3. Wait while it:
   - finds Python
   - creates `.venv` if needed
   - installs dependencies from `requirements.txt`
   - creates `reports/`, `state/`, and `logs/` if missing
   - selects an available port between `8080` and `8085`
   - starts the dashboard
4. Let the browser open automatically.
5. If the browser does not open, visit `http://127.0.0.1:8080/test` or the port shown in the terminal window.

You only need to do the full dependency install on first run or after dependency changes.

## Option B: Windows Manual Setup

Use this if you want full control over the environment.

```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

Then open:

- `http://127.0.0.1:8080`
- `http://127.0.0.1:8080/test`
- `http://127.0.0.1:8080/domains`
- `http://127.0.0.1:8080/settings`

If PowerShell blocks activation scripts, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

and then activate the virtual environment again.

## Option C: Linux/macOS Manual Setup

```bash
cd /path/to/AuroraEdge_FYP
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
export PYTHONPATH="$PWD/src"
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
```

Then open `http://127.0.0.1:8080/test` in your browser.

---

## First Run Checklist

If you just want to prove the project works, do this:

1. Start the dashboard with `START.bat`.
2. Open `/test`.
3. Scan one public domain.
4. Review the score, grade, and remediation guidance.
5. Open `/` to see dashboard history and statistics.

Good starter domains:

| Domain | What it is useful for |
|--------|------------------------|
| `google.com` | Strong example of mature email security |
| `microsoft.com` | Another strong enterprise reference |
| `github.com` | Good real-world comparison domain |
| `example.com` | Simple weak/example case |
| `auroraedge.co.uk` | Project demo domain |

---

## All Supported Ways To Use The Project

## 1. Dashboard Workflow

The dashboard is the main interface for most users.

### Main pages

| Page | URL | Purpose |
|------|-----|---------|
| **Dashboard** | `/` | Overview of results, trends, alerts, and domain posture |
| **Test Hub** | `/test` | Interactive scanner for one or more domains |
| **My Domains** | `/domains` | Managed domains for monitoring and auto-defence |
| **Generator** | `/generator` | DNS record generator wizard |
| **Settings** | `/settings` | Cloudflare, monitoring, organisation, and startup settings |
| **Health** | `/health` | JSON health check |

### What the dashboard supports

- Single-domain interactive scans
- Multi-domain input through the scan UI
- Score, grade, severity, and remediation display
- History and report access
- Managed domain onboarding
- Monitoring alerts
- Cloudflare credential testing
- Automatic DNS fixing for supported records
- Clearing scan data while keeping app settings

## 2. CLI Workflow

Use the CLI if you prefer working from the terminal.

### Prepare the shell first

```powershell
cd "g:\My Drive\College\AuroraEdge_FYP"
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
```

### Common CLI commands

```powershell
# Scan a single domain
python -m app.cli --domain google.com

# Scan with remediation advice
python -m app.cli --domain example.com --remediation

# Scan multiple domains from a file
python -m app.cli --domains domains.txt

# Apply supported DNS fixes through Cloudflare
python -m app.cli --domain example.com --apply-fix
```

### What the CLI does

- Scans one or more domains
- Prints console output with grades and severities
- Saves results into the local database
- Writes CSV and Markdown reports
- Can apply supported Cloudflare fixes when credentials are configured in the environment

## 3. Demo Workflow

For a more guided lecturer or presentation experience:

```powershell
.\scripts\demo.ps1
```

The demo script offers menu-driven actions such as:

- scanning one domain
- scanning many domains
- scanning with remediation
- launching the dashboard
- opening the test hub
- viewing reports
- checking system health
- running unit tests

Recommended approach:

1. Run `START.bat` once to prepare the environment.
2. Stop the server if you want to use the guided PowerShell demo instead.
3. Run `scripts/demo.ps1`.

## 4. Verification Workflow

Use the verification script to confirm the main modules and scan pipeline are working.

```powershell
.\.venv\Scripts\Activate.ps1
python verify_system.py
```

It checks imports, scanning, rules, remediation generation, and logging.

## 5. Automated Test Workflow

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\src"
python -m pytest tests/ -v
```

The repository includes tests for:

- analysis and benchmarks
- CLI behaviour
- dashboard routes and auth
- database persistence and safety
- misconfiguration scenarios
- remediation logic
- security hardening
- scanner behaviour
- SPF recursion edge cases
- stress and abuse handling

## 6. Domain-Owner Workflow With Cloudflare

Use this when you own a domain or have explicit written permission to manage it.

1. Start the dashboard.
2. Open `/settings`.
3. Add Cloudflare credentials.
4. Test the connection.
5. Go to `/domains` and add your domain.
6. Run a scan.
7. Apply supported fixes where appropriate.
8. Review `logs/dns_audit.log` for the audit trail.

---

## Demo Domain And No-Domain Testing

If you do not own a domain, you can still test the platform.

Use the demo domain:

- `auroraedge.co.uk`

Without Cloudflare credentials, you can still:

- scan the domain
- review score, grade, and violations
- view remediation advice
- generate suggested DNS records
- test the dashboard and CLI

Cloudflare credentials are only needed when you want AuroraEdge to attempt live DNS changes.

---

## What AuroraEdge Checks

| Check | Standard | Purpose |
|-------|----------|---------|
| **SPF** | RFC 7208 | Defines which senders are allowed to send email for the domain |
| **DKIM** | RFC 6376 | Verifies signed mail integrity and sender legitimacy |
| **DMARC** | RFC 7489 | Tells receivers how to handle failed SPF/DKIM alignment |
| **MTA-STS** | RFC 8461 | Enforces secure SMTP transport expectations |
| **TLS-RPT** | RFC 8460 | Receives reports about TLS delivery failures |
| **STARTTLS** | RFC 3207 / RFC 8996 context | Checks SMTP transport encryption capability and strength |
| **MX** | RFC 5321 context | Confirms mail routing exists and is usable |

### Grading Scale

| Grade | Score | Meaning |
|-------|-------|---------|
| **A+ / A** | 90-100 | Strong email security posture |
| **B** | 75-89 | Good but not fully hardened |
| **C** | 60-74 | Usable but with meaningful gaps |
| **D** | 40-59 | Weak and vulnerable to abuse |
| **F** | 0-39 | Failing or critically exposed |

---

## Cloudflare Auto-Fix

AuroraEdge can automatically remediate supported DNS issues through Cloudflare.

### Supported automatic fixes

- SPF
- DMARC
- TLS-RPT
- MTA-STS DNS record
- MTA-STS HTTPS policy hosting through Cloudflare Workers
- DKIM for supported providers where the selector pattern can be identified safely

### Ways to provide Cloudflare credentials

#### Dashboard users

Enter them in the **Settings** page.

#### CLI or shell users

Set environment variables in your session:

```powershell
$env:CF_API_TOKEN = "your_api_token_here"
$env:CF_ZONE_ID = "your_zone_id_here"
$env:CF_ACCOUNT_ID = "your_account_id_here"
$env:CF_API_KEY = "your_global_api_key_here"
$env:CF_EMAIL = "you@example.com"
```

### Important guardrails

- Only use auto-fix for domains you own or are authorised to manage.
- AuroraEdge checks that the target domain belongs to the configured Cloudflare zone.
- DNS changes are logged to `logs/dns_audit.log`.
- MTA-STS Worker deployment may require broader Cloudflare permissions than basic DNS edit actions.
- BIMI is reported but intentionally **not** auto-fixed because it depends on branding assets and, in many cases, a VMC.

### Variable reference

`.env.example` is included as a reference file showing the supported variable names. For the current codebase, the application reads these values from the active environment or from stored dashboard settings.

---

## Reports, Logs, And Local State

AuroraEdge creates and uses these local paths:

| Path | Purpose |
|------|---------|
| `reports/indexed/` | Current CSV and Markdown scan outputs |
| `reports/archive/` | Historical stored reports |
| `state/auroraedge.db` | SQLite database for scans, settings, managed domains, and alerts |
| `logs/` | Runtime logs |
| `logs/dns_audit.log` | DNS auto-fix audit trail |

Note on persistence:

- AuroraEdge stores local state in SQLite.
- Scan history can be preserved or cleared on startup depending on the `clear_on_start` setting in the dashboard settings page.

---

## Project Structure

```text
AuroraEdge_FYP/
├── START.bat
├── README.md
├── requirements.txt
├── domains.txt
├── verify_system.py
├── .env.example
├── docs/
├── logs/
├── reports/
├── scripts/
├── src/
│   └── app/
│       ├── analysis.py
│       ├── cli.py
│       ├── dashboard.py
│       ├── database.py
│       ├── dns_fix.py
│       ├── logging_config.py
│       ├── main.py
│       ├── rules.py
│       └── scanner.py
├── state/
└── tests/
```

---

## API Surface

The dashboard exposes 36 route handlers grouped across:

- page routes
- scan and remediation routes
- report and history routes
- managed domain and settings routes
- alerts and reference routes

Key examples include:

- `/health`
- `/api/scan`
- `/api/rescan/{domain}`
- `/api/apply-fix`
- `/api/runs`
- `/api/history/{domain}`
- `/api/data/clear`
- `/api/managed-domains`
- `/api/settings`
- `/api/settings/test-cloudflare`
- `/api/alerts`
- `/api/tools/comparison`

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Python not found` | Install Python 3.10+ and make sure it is available on `PATH` |
| `ModuleNotFoundError: app` | Set `PYTHONPATH` to the `src` folder before running CLI or Uvicorn |
| PowerShell blocks `.ps1` activation | Run `Set-ExecutionPolicy -Scope Process Bypass` in that session |
| Existing `.venv` fails with `not a valid application for this OS platform` | Delete `.venv` and rerun `START.bat`, or recreate the environment manually with `python -m venv .venv` |
| Port `8080` is in use | Use another port manually or let `START.bat` choose a free port |
| `git pull` fails with `not a git repository` | Your copy is a folder copy, not a Git clone |
| Cloudflare auto-fix unavailable | Add valid Cloudflare credentials in Settings or through environment variables |
| No report files appear | Run a scan first; report files are created after successful scan runs |

---

## Documentation Map

Use these documents depending on what you need:

| Document | Purpose |
|----------|---------|
| `docs/INDEX.md` | Central map of the maintained documentation set |
| `docs/TESTING_GUIDE.md` | Practical step-by-step testing guide |
| `docs/FYP_SPEC.md` | Project specification |
| `docs/STATUS.md` | Build status, timeline, and test breakdown |
| `docs/ACADEMIC_NOTEBOOK.md` | Design decisions and rationale |
| `docs/INTEGRATION_GUIDE.md` | Cloudflare, OpenDMARC, and Postfix integration details |
| `docs/PRIVACY_AND_ETHICS.md` | Legal, privacy, and ethical constraints |
| `docs/VERIFICATION_REPORT.md` | Verification evidence |
| `docs/progress/` | Historical project progress records |
| `docs/Stage_*_README.md` | Historical development snapshots by stage |

---

## Privacy, Ethics, And Safety

AuroraEdge is designed around public-domain email security assessment and authorised remediation.

- It queries public DNS and related HTTPS resources.
- It does not attempt mailbox intrusion or credential abuse.
- Cloudflare auto-fix should only be used for domains you control or are authorised to manage.
- Legal, privacy, and ethical context is documented in `docs/PRIVACY_AND_ETHICS.md`.

---

## Licence

This project was developed as a Final Year Project for academic assessment.  
All rights reserved © 2025-2026 Leon Chapman.
