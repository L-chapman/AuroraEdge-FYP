# AuroraEdge Academic Notebook

This notebook captures the academic rationale, design choices, and development log for the automated email authentication and cyber defence system.

## 1. Purpose and Research Framing
- Problem: Email spoofing and misconfiguration remain common; many orgs lack SPF/DMARC/DKIM and transport-layer protections (MTA-STS, TLS-RPT).
- Aim: Build an automated cyber defence platform that assesses email security posture, classifies risk, and remediates misconfigurations — enabling empirical analysis across domains.
- Objectives: (1) Collect DNS/HTTPS policy data; (2) Interpret via rules; (3) Export/share results (CSV/MD, dashboard); (4) Provide tests and reproducibility; (5) Keep security hygiene (token, .env, no creds).

## 2. System Overview
- Scanner (Python 3.11): SPF/MX/DMARC/DKIM + MTA-STS + TLS-RPT lookups.
- Rules engine: Maps findings to OK/WARN/HIGH with human advice.
- CLI: Runs scans, writes CSV/MD, Rich console summary.
- Dashboard (FastAPI): Token-protected; interactive Test Hub; domain detail pages; managed domains; settings UI.
- Persistence (SQLite): Scan history, managed domains, settings, and alerts.
- Automation: Scheduled monitoring loop with drift detection and (optional) Cloudflare DNS remediation.
- Tooling: PowerShell scripts (doctor/run/test/serve/auri), pytest suite, GitHub Actions CI.

## 3. Staged Development (What/Why)

### Phase 1: Research & Planning
- **Project Initiation**: Project proposal and literature review on email authentication standards
- **Requirements Analysis**: Technology stack selection (Python, FastAPI, SQLite) and delivery requirements
- **System Design**: System architecture design and module breakdown
- **Project Setup**: Repository setup, CI/CD pipeline, and development environment

### Phase 2: Core Development
- **Stage 1**: Basic SPF/MX/DMARC lookup. Why: validate DNS plumbing and output formats
- **Stage 2**: SPF recursion/counting + DMARC strength. Why: SPF 10-lookup RFC limit matters
- **Stage 3**: DKIM selector discovery. Why: Many orgs forget DKIM or leave test keys
- **Stage 4**: Rule engine + Rich console. Why: Operational definition of risk for analysis
- **Stage 5**: MTA-STS + TLS-RPT. Why: Transport-layer safety broadens coverage
- **Stage 6**: Offline tests (pytest). Why: Deterministic validation, academic rigor
- **Stage 7**: Dashboard v1 (FastAPI). Why: Usable view for non-technical stakeholders
- **Stage 8**: Scoring system (0-100). Why: Quantitative comparison across domains

### Phase 3: Enhancement & Integration
- **Stage 9**: SQLite database. Why: Persistent scan history for trend analysis
- **Stage 10**: Remediation engine. Why: Actionable recommendations for improvements
- **Stage 11**: Analysis module + charts. Why: Visual presentation for dissertation
- **Stage 12**: Dashboard v2 redesign. Why: Improved usability and presentation
- **Stage 13**: Real-time SSE updates. Why: Live dashboard without manual refresh
- **Stage 14**: Interactive Test Hub. Why: Easy evaluation by lecturers

### Phase 4: Testing & Documentation
- **Comprehensive Testing**: Stress testing with 50+ domain dataset
- **Polish and Refactoring**: Bug fixes and code polish
- **Documentation Completion**: Technical documentation completion
- **Academic Writing**: Dissertation writing and figures

### Phase 5: Submission
- **Final Review**: Supervisor feedback and final review
- **Submission Preparation**: Submission and demonstration preparation

## 4. Design Decisions and Reasoning
- Public-only data: No creds, only DNS TXT/MX and HTTPS policy fetch → lowers risk and simplifies ethics.
- Token auth via env: DASH_TOKEN required in prod; keeps secrets out of code.
- Optional imports in scanner (dns/requests) with mocks in tests: Enables offline testing and portability; avoids brittle CI failures.
- Rule severities: OK/WARN/HIGH chosen for clarity; HIGH for missing MX/SPF/DMARC, WARN for weak policies or missing transport reporting.
- Outputs: CSV for analysis, Markdown for human reading, Rich console for quick CLI feedback, dashboard for supervision.
- Limits: SPF recursion capped (MAX_SPF_RECURSION/MAX_SPF_FETCHES) to avoid runaway lookups; timeouts on DNS/HTTP to keep runs bounded.

## 5. Testing Strategy
- pytest with monkeypatched DNS/HTTP to keep tests offline and deterministic.
- Coverage: rules, scanner paths, SPF recursion edge cases, CLI file handling, dashboard auth/rendering/summary/download endpoints, import fallbacks.
- CI: GitHub Actions runs black check, flake8 (blocking), pytest.

## 6. Security and Ethics
- Secrets live in `.env`; `.env.example` documents required keys.
- Token-gated dashboard; dev mode open only if token unset.
- Reads only public records/endpoints for scanning; optional DNS remediation requires explicit operator/customer authorisation.
- Cloudflare credentials (API token + zone ID) may be supplied via environment variables or stored in the local SQLite settings table for automation.
- Auditability: DNS changes are appended to `logs/dns_audit.log`; monitoring/automation events are recorded as Alerts.
- Logs/reports stored locally under `reports/` and `state/` for controlled sharing.

## 7. Limitations
- DKIM selector discovery uses common names; may miss custom selectors
- No SMTP-level handshake/STARTTLS verification; relies on published policies
- Scoring weights are heuristic; could be refined with larger dataset analysis

## 8. How to Reproduce
- **Interactive Demo**: `.\scripts\demo.ps1` - Menu-driven interface
- **Single Scan**: `python -m app.cli --domain example.com --remediation`
- **Batch Scan**: `python -m app.cli --domains domains.txt`
- **Dashboard**: `$env:PYTHONPATH = "$PWD\src"; python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080`
- **Test Hub**: Open `http://127.0.0.1:8080/test` in browser
- **Tests**: `python -m pytest -q` (397 passed, all offline)

## 9. Completed Stages (All Implemented)

| Stage | Feature | Tests |
|-------|---------|-------|
| 1 | DNS Scanner Skeleton | - |
| 2 | SPF Recursion + DMARC | - |
| 3 | DKIM Discovery | - |
| 4 | Rules Engine | - |
| 5 | MTA-STS + TLS-RPT | - |
| 6 | Testing Framework | 13 |
| 7 | Dashboard v1 | 15 |
| 8 | Scoring System | 17 |
| 9 | Database Persistence | 19 |
| 10 | Remediation Engine | 23 |
| 11 | Analysis Module | 25 |
| 12 | Dashboard v2 | 29 |
| 13 | Real-time Updates | 32 |
| 14 | Interactive Test Hub | 34 |

## 10. Scoring Implementation (Completed)
- **Goal**: Map rule hits to a 0–100 score (higher = better hygiene)
- **Implemented weights**:
  - CRITICAL rules (R3B_SPF_PLUSALL): -40 points
  - HIGH rules (R1_MX_MISSING, R2_SPF_MISSING, R4_DMARC_MISSING): -25 to -30 each
  - WARN rules (R5_DMARC_NONE, R6_DKIM_NOT_FOUND, R8_MTA_STS_MISSING): -5 to -10 each
  - INFO rules (R3A_SPF_MANY_LOOKUPS, R7_DKIM_TEST, R9_MTA_STS_TESTING): -2 to -5 each
- **Grade mapping**: A+ (95-100), A (85-94), B (75-84), C (65-74), D (50-64), F (0-49)

## 11. Dataset Analysis (Completed)
- **Dataset**: 51 domains across UK universities, government, tech, retail, banking
- **Key Findings**:
  - Average score: 68.5/100
  - SPF adoption: 96%
  - DMARC adoption: 88%
  - DKIM adoption: 67%
  - MTA-STS adoption: 12%
- **Figures generated**: Grade distribution, severity breakdown, score histogram

## 12. Evidence Collection for Dissertation
- Screenshots: CLI Rich table, dashboard views, Test Hub
- CI proof: GitHub Actions workflow
- Testing proof: 397 passed in the final `pytest -q` run
- Architecture diagram: scanner → rules → outputs → dashboard
- Analysis figures: matplotlib charts in `docs/figures/`

## 10. Draft Scoring Rubric (Stage 8)
- Goal: Map rule hits to a 0–100 score (higher = better hygiene).
- Proposed weights (tune after pilot runs):
  - HIGH rules (R1_MX_MISSING, R2_SPF_MISSING, R4_DMARC_MISSING): -30 each (cap floor at 0).
  - WARN rules (R3_SPF_LOOKUPS, R5_DMARC_NONE, R6_DKIM_NOT_FOUND, R7_DKIM_TEST, R8_MTA_STS_MISSING, R9_MTA_STS_MODE, R10_TLS_RPT_MISSING): -10 each.
  - Base score: 100; floor at 0.
- Rationale: Missing MX/SPF/DMARC fundamentally break authentication; WARNs degrade but don’t eliminate protections. Tuning to be validated on a sample dataset.
- Output plan: add `score` column in CSV/MD; show average/min/max in dashboard summary.

## 11. Dataset Plan (Stage 9)
- Target sets: (a) Universities (public list), (b) SMEs sample, (c) Large providers for contrast.
- Ethics: public DNS/HTTPS only; no intrusive probing; document source lists.
- Execution: use `scripts/run.ps1 --domains <file>`; store results under `reports/study1_*`.
- Analysis script (to add): Jupyter or Python script to aggregate counts per rule, severity distribution, and score distribution; generate bar charts/pies for dissertation figures.
- Metrics to extract: % domains missing DMARC; % SPF > 10 lookups; % MTA-STS present/enforce; score histogram.

## 12. Evidence Collection for Dissertation
- Screenshots: doctor output, CLI Rich table, dashboard severity pills + downloads.
- CI proof: screenshot or log snippet of GitHub Actions run.
- Testing proof: pytest summary (13 passed) and mention of offline mocks.
- Architecture diagram: scanner → rules → outputs → dashboard (to include later).
