# AuroraEdge Development Timeline

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../README.md) and [`testing guide`](TESTING.md).

## Project Information
**Student**: Leon Chapman
**Course**: Cybersecurity & Networking Infrastructure  
**Institution**: Belfast Metropolitan College  
**Project Span**: September 2025 - February 2026  
**Project**: Automated Email Authentication & Cyber Defence System

---

## Phase 1: Research & Planning

### Project Initiation (02-08 Sep 2025)
- [x] Project proposal submitted
- [x] Initial research on email security standards
- [x] Literature review: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)
- [x] Defined project scope and objectives

### Requirements Analysis (09-15 Sep 2025)
- [x] Functional requirements documented
- [x] Non-functional requirements (performance, security)
- [x] Technology stack selection: Python 3.11, FastAPI, SQLite
- [x] Development environment setup

### System Design (16-22 Sep 2025)
- [x] System architecture design
- [x] Module breakdown: Scanner, Rules, CLI, Dashboard, Database
- [x] Data flow diagrams created
- [x] API endpoint planning

### Project Setup (23-29 Sep 2025)
- [x] Repository structure created
- [x] Virtual environment configured
- [x] Development scripts written (run.ps1, test.ps1, serve.ps1)
- [x] CI/CD pipeline (.github/workflows/ci.yml)

---

## Phase 2: Core Development

### Stage 1: DNS Scanner Skeleton (30 Sep - 06 Oct 2025)
- [x] Basic SPF lookup implementation
- [x] MX record discovery
- [x] DMARC TXT record parsing
- [x] CSV/Markdown output generation
- **Commit**: `feat: Stage 1 - Basic DNS scanner for SPF/MX/DMARC`

### Stage 2: SPF Recursion & DMARC Parsing (07-13 Oct 2025)
- [x] SPF include/redirect recursion (RFC 7208 compliance)
- [x] SPF lookup counting (10-lookup limit detection)
- [x] DMARC policy strength analysis (none/quarantine/reject)
- [x] DMARC tag parsing (p, sp, pct, rua, ruf)
- **Commit**: `feat: Stage 2 - SPF recursion counting + DMARC strength`

### Stage 3: DKIM Discovery (14-20 Oct 2025)
- [x] Common DKIM selector probing (google, selector1, default, etc.)
- [x] DKIM key type detection (RSA, Ed25519)
- [x] Test key flag detection (t=y)
- [x] Results integration into reports
- **Commit**: `feat: Stage 3 - DKIM selector discovery + key analysis`

### Stage 4: Rules Engine (21-27 Oct 2025)
- [x] Severity classification: OK, INFO, WARN, HIGH, CRITICAL
- [x] Rule definitions for all checks
- [x] Violation tracking and advice generation
- [x] Rich console output with colour coding
- **Commit**: `feat: Stage 4 - Rules engine + Rich console display`

### Stage 5: Transport Security (28 Oct - 03 Nov 2025)
- [x] MTA-STS policy lookup (RFC 8461)
- [x] MTA-STS mode parsing (none/testing/enforce)
- [x] TLS-RPT record discovery (RFC 8460)
- [x] STARTTLS check infrastructure (optional)
- **Commit**: `feat: Stage 5 - MTA-STS + TLS-RPT transport security`

### Stage 6: Testing Framework (04-10 Nov 2025)
- [x] pytest test suite structure
- [x] DNS/HTTP mocking for offline tests
- [x] Scanner edge case tests
- [x] Rules engine validation tests
- [x] 13 initial tests passing
- **Commit**: `feat: Stage 6 - Pytest suite with offline mocks`

### Stage 7: Dashboard v1 (11-17 Nov 2025)
- [x] FastAPI application structure
- [x] Token-based authentication
- [x] HTML dashboard with severity counts
- [x] REST API endpoints
- [x] Report download functionality
- **Commit**: `feat: Stage 7 - FastAPI dashboard with auth`

### Stage 8: Scoring System (18-24 Nov 2025)
- [x] 0-100 scoring algorithm
- [x] Letter grades (A+ to F)
- [x] Weighted rule penalties
- [x] Score display in CLI and dashboard
- **Commit**: `feat: Stage 8 - Scoring system with letter grades`

---

## Phase 3: Enhancement & Integration

### Stage 9: Database Persistence (25 Nov - 01 Dec 2025)
- [x] SQLite database design
- [x] Scan history storage
- [x] Domain tracking across scans
- [x] Statistics aggregation queries
- **Commit**: `feat: Stage 9 - SQLite database for scan history`

### Stage 10: Remediation Engine (02-08 Dec 2025)
- [x] Automated fix recommendations
- [x] Priority-based remediation ordering
- [x] Example DNS records for fixes
- [x] RFC references for each recommendation
- **Commit**: `feat: Stage 10 - Remediation recommendations`

### Stage 11: Analysis Module (09-15 Dec 2025)
- [x] Statistical analysis functions
- [x] Matplotlib chart generation
- [x] Grade distribution visualisation
- [x] Severity breakdown charts
- **Commit**: `feat: Stage 11 - Analysis module + matplotlib figures`

### Stage 12: Dashboard v2 (16-22 Dec 2025)
- [x] UI redesign (CSS variables, gradients)
- [x] Interactive filtering and sorting
- [x] Domain detail pages
- [x] Responsive design
- **Commit**: `feat: Stage 12 - Dashboard v2 UI redesign`

### Stage 13: Real-time Updates (23-29 Dec 2025)
- [x] Server-Sent Events (SSE) for live updates
- [x] Auto-refresh functionality
- [x] Toast notifications
- [x] Connection status indicator
- **Commit**: `feat: Stage 13 - SSE real-time dashboard updates`

### Stage 14: Test Hub (30 Dec - 05 Jan 2026)
- [x] Interactive web test interface (/test)
- [x] Single and batch domain scanning
- [x] On-demand scan API endpoint
- [x] Quick example domains
- [x] Demo PowerShell script
- **Commit**: `feat: Stage 14 - Interactive test hub + demo script`

---

## Phase 4: Testing & Documentation

### Comprehensive Testing (06-12 Jan 2026)
- [x] Stress testing with 50+ domains
- [x] Edge case validation
- [x] Cross-browser dashboard testing
- [x] Performance benchmarking
- [ ] Test coverage report (optional)

### Bug Fixes & Polish (13-19 Jan 2026)
- [x] All identified bugs resolved
- [x] Code refactoring
- [x] Error handling improvements
- [x] Logging enhancements

### Documentation (20-26 Jan 2026)
- [x] Technical documentation complete
- [x] API documentation
- [x] User guide
- [x] Testing guide for evaluators

### Academic Writing (27 Jan - 02 Feb 2026)
- [x] Dissertation draft
- [x] Methodology chapter
- [x] Results analysis
- [x] Screenshots and figures

---

## Phase 5: Submission

### Final Review (03-09 Feb 2026)
- [x] Dissertation review and editing
- [x] Code cleanup
- [x] Final testing
- [x] Supervisor feedback

### Submission (10-16 Feb 2026)
- [x] Final dissertation submission
- [x] Code repository cleanup
- [x] Demonstration preparation
- [x] Project handover

---

## Post-Submission Enhancements (Feb 2026)

These changes extend the prototype toward the spec phrasing “set up, monitor, and fix” with minimal operator involvement:

- Managed domains: onboarding and persistent tracking for continuous monitoring
- Settings + persistence: Cloudflare token/zone + monitoring interval stored in SQLite
- Alerts: drift detection (grade changes), scan errors, and remediation events
- Zero-touch remediation: supported Cloudflare DNS fixes can be applied automatically on onboarding and during monitoring
- Policy hardening: DMARC upgrades to `p=reject` and SPF softfail to hardfail where applicable

---

## Deliverables Summary

| Deliverable | Status | Location |
|-------------|--------|----------|
| Scanner Module | Complete | `src/app/scanner.py` |
| Rules Engine | Complete | `src/app/rules.py` |
| CLI Interface | Complete | `src/app/cli.py` |
| Dashboard | Complete | `src/app/dashboard.py` |
| Database | Complete | `src/app/database.py` |
| Analysis | Complete | `src/app/analysis.py` |
| Test Suite | Complete | `tests/` (397 tests) |
| Documentation | In progress | `docs/` |
| Dissertation | Pending | External |

---

## Test Results

```
============================= test session starts =============================
platform win32 -- Python 3.11.9
collected 21 items

tests/test_analysis.py::test_calculate_statistics PASSED
tests/test_analysis.py::test_empty_statistics PASSED
tests/test_cli.py::test_cli_writes_outputs PASSED
tests/test_cli_domains.py::test_cli_reads_domains_file PASSED
tests/test_dashboard.py::test_dashboard_health_and_home PASSED
tests/test_dashboard_auth.py::test_dashboard_token_enforcement PASSED
tests/test_database.py::test_database_init_and_save PASSED
tests/test_database.py::test_database_multiple_scans PASSED
tests/test_fallbacks.py::test_scanner_handles_missing_dns_and_requests PASSED
tests/test_remediation.py::test_remediation_for_missing_spf PASSED
tests/test_remediation.py::test_remediation_for_dmarc_none PASSED
tests/test_remediation.py::test_remediation_for_missing_mta_sts PASSED
tests/test_remediation.py::test_no_remediation_for_perfect_config PASSED
tests/test_rules.py::test_rules_mx_and_spf_missing_is_high PASSED
tests/test_rules.py::test_rules_dmarc_none_warn PASSED
tests/test_rules.py::test_rules_spf_lookups_warn PASSED
tests/test_rules_extra.py::test_spf_lookups_boundary PASSED
tests/test_rules_extra.py::test_dmarc_none_is_warn_when_present PASSED
tests/test_scanner.py::test_scan_spf_missing PASSED
tests/test_scanner.py::test_scan_dmarc_present_quarantine PASSED
tests/test_spf_recursion.py::test_spf_count_recursive PASSED

============================= 21 passed in 2.17s ==============================
```

---

## References

- RFC 7208 - Sender Policy Framework (SPF)
- RFC 6376 - DomainKeys Identified Mail (DKIM)
- RFC 7489 - Domain-based Message Authentication (DMARC)
- RFC 8461 - SMTP MTA Strict Transport Security (MTA-STS)
- RFC 8460 - SMTP TLS Reporting (TLS-RPT)
