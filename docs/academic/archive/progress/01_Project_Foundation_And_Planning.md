# Project Foundation & Planning Progress Record

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../../../../README.md) and [`testing guide`](../../../TESTING.md). Return to the [archive guide](../../README.md).

## Project Initiation (02-08 September 2025)
**Focus**: Project Initiation

### Activities
- Submitted project proposal for AuroraEdge Email Security Scanner
- Conducted initial research on email authentication standards
- Reviewed academic papers on email security vulnerabilities
- Identified key RFCs for implementation

### Research Notes
- **SPF (RFC 7208)**: Sender Policy Framework validates sending IP addresses
- **DKIM (RFC 6376)**: DomainKeys adds cryptographic signatures to emails
- **DMARC (RFC 7489)**: Builds on SPF/DKIM with policy enforcement
- **Problem**: Many organisations lack proper email authentication, enabling spoofing

### Decisions Made
- Target: Build automated scanner to assess email security posture
- Scope: Public DNS/HTTPS data only (ethical, no intrusion)
- Output: Risk scores, grades, and remediation recommendations

---

## Requirements Analysis (09-15 September 2025)
**Focus**: Requirements Analysis

### Functional Requirements
1. Scan single or multiple domains via CLI
2. Check SPF, DKIM, DMARC, MTA-STS, TLS-RPT configurations
3. Generate severity ratings (OK, WARN, HIGH, CRITICAL)
4. Export results to CSV and Markdown
5. Web dashboard for viewing results
6. Persistent storage of scan history

### Non-Functional Requirements
- Performance: Scan 50+ domains in under 5 minutes
- Security: Token-protected dashboard, no credential storage
- Portability: Works on Windows, Linux, macOS
- Testability: Offline unit tests with mocked DNS

### Technology Selection
| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Python 3.11 | Rich DNS libraries, rapid development |
| Web Framework | FastAPI | Async support, auto-documentation |
| Database | SQLite | Zero-config, portable, sufficient for scope |
| Testing | pytest | Industry standard, good mocking support |
| UI | HTML/CSS/JS | No build step, simple deployment |

---

## System Design (16-22 September 2025)
**Focus**: System Design

### Architecture Overview
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Scanner   │────▶│    Rules    │────▶│   Output    │
│  (DNS/HTTP) │     │  (Evaluate) │     │ (CSV/MD/DB) │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  Dashboard  │
                    │  (FastAPI)  │
                    └─────────────┘
```

### Module Design
- **scanner.py**: DNS lookups (SPF, MX, DMARC, DKIM), HTTP fetches (MTA-STS)
- **rules.py**: Severity classification, scoring, remediation generation
- **cli.py**: Command-line interface with Rich console output
- **dashboard.py**: FastAPI web application
- **database.py**: SQLite persistence layer
- **analysis.py**: Statistical analysis and chart generation

### Data Flow
1. User provides domain(s) via CLI or Dashboard
2. Scanner queries DNS/HTTPS for security records
3. Rules engine evaluates findings against RFC requirements
4. Results scored (0-100) and graded (A+ to F)
5. Output saved to CSV/MD/Database
6. Dashboard displays results with filtering/sorting

---

## Project Setup (23-29 September 2025)
**Focus**: Project Setup

### Repository Structure Created
```
AuroraEdge_FYP/
├── src/
│   └── app/
│       ├── __init__.py
│       ├── scanner.py
│       ├── rules.py
│       ├── cli.py
│       ├── dashboard.py
│       ├── database.py
│       └── analysis.py
├── tests/
├── docs/
├── reports/
├── scripts/
│   ├── run.ps1
│   ├── test.ps1
│   ├── serve.ps1
│   └── demo.ps1
├── requirements.txt
├── domains.txt
└── README.md
```

### Development Environment
- Python virtual environment (.venv)
- Dependencies: dnspython, requests, fastapi, uvicorn, rich, pytest
- VS Code with Python extension
- Git for version control

### CI/CD Pipeline
- GitHub Actions workflow for automated testing
- Runs on push/PR: black check, flake8, pytest
- Ensures code quality and test coverage

### Outcome
Project foundation complete. Ready to begin the core development phase.
