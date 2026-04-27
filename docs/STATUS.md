# AuroraEdge Development Status Log

## How To Use This Log

- Use this file for the full development timeline, platform status, and test coverage breakdown.
- Use `README.md` and `docs/TESTING_GUIDE.md` for setup and evaluation steps.
- Treat the sections below as project evidence rather than first-time user guidance.

## Project Timeline (September 2025 - February 2026)
**Student**: Leon Chapman (50030738)  
**Start**: 02 September 2025  
**End**: 16 February 2026  

---

## Development Log

### Phase 1: Research & Planning
[2025-09-02] Project Initiation • Research • Project proposal and literature review
[2025-09-09] Requirements Analysis • Analysis • Requirements analysis and technology selection
[2025-09-16] System Design • Design • System architecture and module design
[2025-09-23] Project Setup • Setup • Repository structure and CI/CD pipeline

### Phase 2: Core Development
[2025-09-30] Stage 1 • DNS Scanner Skeleton • SPF/MX/DMARC lookup
[2025-10-07] Stage 2 • SPF Recursion & DMARC Strength • SPF recursion counting + DMARC strength analysis
[2025-10-14] Stage 3 • DKIM Discovery • DKIM selector discovery + key type detection
[2025-10-21] Stage 4 • Rules Engine • Rules engine + Rich console output
[2025-10-28] Stage 5 • Transport Security • MTA-STS + TLS-RPT transport security checks
[2025-11-04] Stage 6 • Testing Framework • pytest test suite with offline mocks (13 tests)
[2025-11-11] Stage 7 • Dashboard v1 • FastAPI + token authentication
[2025-11-18] Stage 8 • Scoring System • Scoring system (0-100) + letter grades (A+ to F)

### Phase 3: Enhancement & Integration
[2025-11-25] Stage 9 • Database Persistence • SQLite database + persistent scan history
[2025-12-02] Stage 10 • Remediation Engine • Remediation recommendations engine
[2025-12-09] Stage 11 • Analysis Module • Analysis module + matplotlib figures
[2025-12-16] Stage 12 • Dashboard v2 • UI redesign
[2025-12-23] Stage 13 • Real-time Updates • SSE updates + auto-refresh
[2025-12-30] Stage 14 • Interactive Test Hub • Interactive Test Hub + demo script

### Phase 4: Testing & Documentation
[2026-01-06] Comprehensive Testing • Testing • Stress testing with 50+ domain dataset
[2026-01-13] Polish and Refactoring • Polish • Bug fixes and code refactoring
[2026-01-20] Documentation Completion • Docs • Technical and user documentation
[2026-01-27] Academic Writing • Writing • Dissertation draft and figures

### Phase 5: Submission
[2026-02-03] Final Review • Review • Final review and supervisor feedback
[2026-02-10] Submission • Submit • Final submission and demonstration

---

## Current Status: Final Submission Snapshot (Apr 2026)

- Exact automated test result reconfirmed on 2026-04-14 with `python -m pytest -q`: **397 passed, 0 skipped**.
- `src/app/dashboard.py` currently exposes **36 route handlers**.
- Current supported auto-fix scope: SPF, DMARC, TLS-RPT, MTA-STS DNS, MTA-STS Worker deployment, and provider-aware DKIM for supported providers.
- `scripts/create_submission_zip.ps1` builds a clean assessment ZIP that excludes local environments, Git metadata, caches, runtime state, logs, and `reports/archive/`.
- Historical milestone sections below keep their original counts for context. The authoritative final test count is the one above.

### Submission Robustness Updates (2026-04-27)
- Hardened `START.bat` to reject false Python detections from Windows App Execution Aliases and require a usable `venv` module before continuing.
- Added writable-path guard in `START.bat`: if launched from a read-only location, it copies to `%LOCALAPPDATA%\\AuroraEdge\\AuroraEdge_FYP_submission` and relaunches automatically.
- Improved demo reset/restore UX on `/test` with explicit progress popup and staged rescans so score/grade updates are visible on first run.
- Updated demo reset verification selection logic to use matching/latest scan snapshots for deterministic post-reset scoring.
- Synced fixes to GitHub and revalidated runtime syntax for updated modules (`START.bat`, `dashboard.py`).

### Test Results: 397 Passed, 0 Skipped

**Functional Tests (39):**
```
tests/test_analysis.py  (2)  — statistics calculation
tests/test_benchmark.py (13) — tool comparison, scoring, rules, performance
tests/test_cli.py       (1)  — CLI output generation
tests/test_cli_domains.py(1) — domains-file parsing
tests/test_dashboard.py (3)  — health, home page, search/settings regressions
tests/test_dashboard_auth.py(1) — token enforcement
tests/test_database.py  (3)  — SQLite persistence
tests/test_fallbacks.py (1)  — missing-dependency handling
tests/test_remediation.py(4) — fix recommendations
tests/test_rules.py     (3)  — severity classification
tests/test_rules_extra.py(4) — edge-case rules + R15 subdomain policy
tests/test_scanner.py   (2)  — scan detection
tests/test_spf_recursion.py(1)— SPF lookup counting
```

**Security & Stress Tests (118):**
```
TestAuthentication          (18) — auth bypass on all 12 protected endpoints
TestSQLInjection            (28) — 7 payloads × 4 input surfaces
TestXSSPrevention           (11) — script/HTML injection via domain names
TestPathTraversal           (10) — file download directory escape
TestStressAndAbuse          (9)  — oversized input, unicode, rapid fire
TestSecurityHeadersPresence (7)  — OWASP headers (CSP, X-Frame-Options, etc.)
TestInputValidation         (6)  — protocol stripping, empty/whitespace
TestDataManagement          (5)  — on-demand clear + per-domain deletion
TestOwnershipEnforcement    (4)  — ethical DNS remediation guardrails
TestTokenForwarding         (4)  — auth JS injected in all HTML pages
TestCredentialSafety        (3)  — CF token masking verification
TestSecurityHeaders         (3)  — content-type, server header leak
TestPrivacyFooter           (3)  — privacy notice on all HTML pages
TestCustom404Page           (3)  — branded 404 page for unknown routes
TestCacheControl            (2)  — Cache-Control no-store on all responses
TestStateSafety             (2)  — concurrent writes, add-remove cycle
```

**Misconfiguration Scenario Tests (200):**
```
TestSingleRuleMisconfig    (61)  — every rule (R1–R15) broken individually, correct severity + score
TestRuleFunctions          (55)  — direct unit tests for every rule_*() function
TestDomainValidation       (15)  — valid/invalid domain regex edge cases
TestGradeBoundaries        (12)  — parameterised boundary values for A+/A/B/C/D/F
TestEdgeCasesSafety        (11)  — empty/None/wrong-type inputs, case insensitivity, unknown keys
TestComplexMisconfigs       (8)  — multi-rule combos: brand-new domain, spoofing-open, all-weak
TestScannerMisconfigs       (8)  — monkeypatched DNS: no-SPF, +all, sp=none, DKIM test, RBL
TestSPFRecursionEdgeCases   (8)  — nested includes, redirect, a/mx/ptr/exists/ip4/ip6
TestRemediationCompleteness (7)  — domain in examples, valid priorities, RFC references
TestScoreArithmetic         (5)  — exact penalty math, weight constants, floor at zero
TestExplanationSystem       (4)  — all rule/severity explanations present + defaults
TestDashboardScanIntegration(4)  — POST /api/rescan with mocked scanner pipeline
TestPerfectConfig           (2)  — baseline: perfect domain = 100/A+, 0 remediations
```

**Backend QA Tests (38):**
```
TestDomainValidation    (3)  — valid/invalid domains, scan rejection
TestDatabaseImprovements(7)  — WAL mode, indexes, context manager, thread safety
TestScannerImprovements (2)  — exp= RFC compliance
TestRulesImprovements  (11)  — severity order, spf guard, DKIM detection, all 17 remediations
TestDnsFixImprovements  (8)  — error extraction safety, ownership enforcement
TestAnalysisImprovements(5)  — median (odd/even/empty/single), statistics
TestCLIImprovements     (2)  — csv.writer escaping, CRITICAL severity
```

### Backend Audit & Hardening (2026-02-19)
- **CRITICAL fixes**: Thread-safe DB writes (Lock + WAL mode), STARTTLS socket leak (try/finally), safe Cloudflare error extraction
- **HIGH fixes**: Domain ownership enforcement on all 4 fix methods, composite DB indexes for query performance
- **Bug fixes**: `exp=` RFC 7208 compliance (not counted as DNS lookup), correct median for even-length lists, DKIM `:test` false-positive prevention
- **Feature expansion**: Remediations expanded from 5 to all 17 rules, `is_valid_domain()` exported, `_extract_error()` helper, `_ensure_ownership()` guard, context manager for DB, rotating audit log
- **Code quality**: Dead imports removed, `print()` replaced with logging, `csv.writer` replacing manual CSV, accurate JSON log timestamps, domain validation regex
- **38 new backend QA tests** covering every fix above
- **397 passed, 0 skipped** after final verification updates

### January 2026 Validation Updates (2026-01-08)
- Fixed all deprecated `datetime.utcnow()` calls (21 occurrences)
- Updated to timezone-aware `datetime.now(timezone.utc)` per Python 3.12 standards
- Added comprehensive benchmark test suite (`test_benchmark.py`)
- New tests for tool comparison, scoring system, and performance benchmarks
- All 397 tests passed with 0 skipped and zero warnings
- **Full System Verification Complete**:
  - ✅ All modules import correctly
  - ✅ All 10 API endpoints verified working
  - ✅ Database persistence tested (86 scans stored)
  - ✅ Multi-domain stress test passed (10/10 domains, avg 4.36s)
  - ✅ Grade distribution verified: A+ (1), A (2), B (3), C (3), D (1)

### Dashboard v3 Enhancements (2026-01-08)
- **Clickable domain results** - Expand/collapse for detailed view
- **Severity explanations** - Why each issue matters + impact description
- **Enhanced remediation** - "Why?" and "How to Fix" for each issue
- **Copy-to-clipboard** - One-click copy DNS record examples
- **Action buttons** - Rescan, View History, Export Report per domain
- **Score breakdown** - Click score to see point deduction details
- **Raw DNS data** - Expandable section showing full scan results
- **15 rule explanations** - RFC references and fix guidance

### New API Endpoints
- `GET /api/explanations/severity/{severity}` - Get severity explanation
- `GET /api/explanations/rule/{rule_id}` - Get rule explanation with why/fix
- `GET /api/explanations/all` - Get all explanations (severities + rules)
- `GET /api/tools/comparison` - Tool comparison data for academic analysis

### Features Complete
- CLI with single/batch domain scanning
- SPF, DKIM, DMARC, MTA-STS, TLS-RPT checks
- Severity classification (OK/INFO/WARN/HIGH/CRITICAL)
- Scoring (0-100) and grades (A+ to F)
- CSV and Markdown reports
- SQLite database persistence
- Remediation recommendations
- FastAPI web dashboard with UI redesign
- Real-time SSE updates
- Interactive Test Hub (/test)
- Token authentication
- Demo script for evaluators
- Tool comparison data (AuroraEdge vs OnDMARC, EasyDMARC, dmarcian, MXToolbox)
- Performance benchmarks (<10ms evaluate, <50ms report generation)

### February 2026 Platform Extensions (Zero-Touch Automation)
- **Managed Domains (continuous monitoring):** Add domains for scheduled rescans.
- **Settings UI + persistence:** Store Cloudflare API Token + Zone ID, monitoring interval, and related config in SQLite settings.
- **Alerts:** Create alerts for grade drops/improvements, scan errors, and automatic remediation events.
- **Zero-touch Cloudflare remediation:** When Cloudflare credentials are configured, the system can automatically apply supported DNS fixes (SPF/DMARC/TLS-RPT/MTA-STS DNS, provider-aware DKIM where supported, and the MTA-STS Worker path) during onboarding and monitoring.
- **Policy hardening improvements:** DMARC can be upgraded automatically to `p=reject` where applicable; SPF can be hardened from `~all` to `-all`.
- **Audit trail:** All DNS changes are appended to `logs/dns_audit.log`.

### Security Hardening (Feb 2026)
- **Domain input validation:** The `_sanitize_domain()` helper performs strict validation and rejects HTML, SQL, and non-domain input across all domain-accepting endpoints.
- **XSS prevention:** Domain names in JSON API responses are sanitised; invalid characters are rejected server-side so the frontend's `innerHTML` rendering is safe.
- **Info-leak prevention:** SQLi payloads in history/scan path params are rejected before echoing, preventing database technology disclosure.
- **Type-safety:** Non-string domain inputs (int, null, etc.) are coerced to string then validated — no more 500 errors on numeric input.
- **Auth token forwarding:** Injected `_auth_js()` script patches `fetch()` and `EventSource` to forward `DASH_TOKEN` from URL query params, making the full dashboard functional in production.
- **97 security/stress tests** added: auth bypass, SQL injection, path traversal, XSS, credential leaks, ethical guardrails, concurrency, and more.

### Final Security Hardening (Feb 2026)
- **Security headers middleware:** OWASP-recommended headers on all responses (X-Frame-Options DENY, CSP, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy, X-XSS-Protection)
- **Rate limiting:** In-memory per-IP rate limiter on scan endpoints (10 scans per 60 seconds)
- **Error info leakage fixed:** `/api/history/{domain}`, `/api/stats`, and `/api/report/pdf/{domain}` now return generic error messages instead of stack traces
- **SSE stream authentication:** `/api/stream` endpoint now requires authentication token
- **Privacy notice:** Footer on all pages states "Public DNS checks only" with a link to the privacy and ethics policy
- **Privacy & Ethics Policy:** Comprehensive `docs/PRIVACY_AND_ETHICS.md` covering data collection, storage, retention, legal basis (Computer Misuse Act 1990, GDPR), ethical framework, third-party services
- **Strengths & Weaknesses Analysis:** `docs/STRENGTHS_AND_WEAKNESSES.md` — academic self-critique with comparison tables and future work identification
- **Custom 404 page:** Branded HTML error page for unknown routes (API routes still return JSON)
- **DMARC subdomain policy rule (R15):** Detects when sp= is weaker than p= (RFC 7489 Section 6.3)
- **Version bump:** 3.0 → 3.1
- **15 new tests** added: OWASP headers (7), privacy footer (3), 404 page (3), R15 rule (2)
- **185/185 tests passing**

### Data Management & Final Hardening (Feb 2026)
- **On-demand data clearing:** `POST /api/data/clear` — clears all scan data while preserving settings
- **Per-domain history deletion:** `DELETE /api/history/{domain}` — removes all scan records, domain entries, and alerts for a specific domain
- **"Clear All Scan Data" UI button:** Settings page Data Management section with confirmation dialog
- **Cache-Control headers:** `no-store, no-cache, must-revalidate` + `Pragma: no-cache` on all HTML and JSON responses via SecurityHeadersMiddleware — prevents stale data display
- **Version consistency fix:** All `3.0` references updated to `3.1` (settings page + export JS)
- **7 new tests:** Data management (5) + cache-control headers (2)
- **192/192 tests passing**

### Comprehensive Misconfiguration Testing (Feb 2026)
- **200 new misconfiguration scenario tests** in `test_misconfig_scenarios.py` covering every rule, edge case, and API endpoint
- **Single-rule isolation:** Each of the 20 rules broken individually — verifies correct rule fires, correct severity, exact score deduction, and accurate remediation text
- **Complex multi-misconfiguration combos:** Brand-new domain (zero config → grade F), SPF+all with DMARC none (spoofing-open), DMARC reject without SPF/DKIM (pointless policy), all-records-present-but-all-weak, almost-perfect (grade A+ at 98)
- **Grade boundary verification:** Every grade threshold tested at exact cutoff values (95→A+, 85→A, 75→B, 60→C, 40→D, <40→F)
- **Score arithmetic:** Precise penalty math validated — weight constants, multi-severity combos, floor at 0, INFO-only deductions
- **Edge cases & safety:** Empty dicts, None values, string/float type coercion, case insensitivity (REJECT/~ALL/ENFORCE), unknown enum values, extra unknown keys
- **Scanner mock tests:** Monkeypatched DNS resolution for realistic scan scenarios — no-SPF/no-MX, SPF +all detection, DMARC sp=none, DKIM test mode, RBL blacklisted
- **SPF recursion edge cases:** 8 scenarios covering nested includes, redirect, a/mx/ptr/exists mechanisms, ip4/ip6 (no lookup count)
- **Domain validation:** 15 parameterised valid/invalid formats including IDN, hyphens, numeric TLDs, special chars
- **Dashboard API integration:** POST /api/rescan tested end-to-end with mocked scanner — response shape, violation propagation, remediation population
- **Explanation system:** All 18 rule IDs and 5 severity levels have complete why/fix/example/rfc entries
- **Key finding:** R15 correctly treats unknown sp= values (e.g. "banana") as weaker than any known parent policy — secure default behaviour verified
- **397 passed, 0 skipped**

---

## Quick Start

### Interactive Demo
```powershell
.\scripts\demo.ps1
```

### CLI Scan
```powershell
python -m app.cli --domain example.com --remediation
```

### Dashboard
```powershell
$env:PYTHONPATH = "$PWD\src"
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
# Dashboard:  http://127.0.0.1:8080
# Test Hub:   http://127.0.0.1:8080/test
# Domains:    http://127.0.0.1:8080/domains
# Generator:  http://127.0.0.1:8080/generator
# Settings:   http://127.0.0.1:8080/settings
```

### Run Tests
```powershell
python -m pytest -q
```

