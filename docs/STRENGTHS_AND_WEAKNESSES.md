# AuroraEdge — Strengths, Weaknesses & Future Work

**Author:** Leon Chapman (50030738)  
**Date:** February 2026  
**Version:** Final Build (397 tests passing)

---

## 1. Strengths

### 1.1 Comprehensive Protocol Coverage
AuroraEdge checks **10 email security protocols/standards** — more than most commercial alternatives:

| Protocol | RFC | AuroraEdge | OnDMARC | EasyDMARC | dmarcian | MxToolbox |
|----------|-----|:----------:|:-------:|:---------:|:--------:|:---------:|
| SPF      | 7208 | ✅ | ✅ | ✅ | ✅ | ✅ |
| SPF Lookup Count | 7208 §4.6.4 | ✅ | ❌ | ✅ | ✅ | ✅ |
| DKIM Discovery | 6376 | ✅ (30 selectors) | ✅ | ✅ | ✅ | ✅ |
| DMARC | 7489 | ✅ | ✅ | ✅ | ✅ | ✅ |
| MTA-STS | 8461 | ✅ | ❌ | ❌ | ❌ | ❌ |
| TLS-RPT | 8460 | ✅ | ❌ | ❌ | ❌ | ❌ |
| STARTTLS Grading | 8996 | ✅ | ❌ | ❌ | ❌ | ✅ |
| BIMI | 9495 | ✅ | ✅ | ✅ | ❌ | ❌ |
| Blacklist/RBL | 5782 | ✅ (5 DNSBLs) | ❌ | ❌ | ❌ | ✅ |
| MX Records | 5321 | ✅ | ✅ | ✅ | ✅ | ✅ |

### 1.2 Automated DNS Remediation
The standout differentiator: AuroraEdge can **automatically fix DNS records** via the Cloudflare API — no other academic tool does this. Supports:
- SPF record creation/repair (with provider auto-detection from MX records)
- DMARC policy creation and hardening (`none` → `quarantine` → `reject`)
- DKIM CNAME provisioning (Microsoft 365) or TXT stubs
- MTA-STS DNS record and policy file deployment (via Cloudflare Workers)
- TLS-RPT record creation
- Domain ownership verification prevents cross-zone mistakes

### 1.3 Rules Engine Quality
- **20 distinct rules** (R1–R15 + sub-rules) covering all major email security weaknesses
- Each rule includes: RFC reference, explanation (why it matters), fix guidance, and example DNS record
- Weighted scoring system (CRITICAL: 40pts, HIGH: 25pts, WARN: 10pts, INFO: 2pts) produces 0–100 scores
- Letter grades (A+ through F) provide instant comprehension

### 1.4 Security Posture (Defence-in-Depth)
The system implements proper security controls:
- **Authentication:** Token-based auth on all sensitive endpoints (36 endpoints, 18 tested for bypass)
- **Input validation:** Strict domain regex, SQL injection prevention, XSS sanitisation, path traversal blocking
- **Security headers:** X-Frame-Options DENY, CSP, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy
- **Rate limiting:** In-memory per-IP limiter (10 scans/60s) on scan endpoints
- **Error handling:** Generic error messages to users, detailed logs server-side
- **Audit logging:** Rotating log files for all DNS changes
- **Credential safety:** Cloudflare API tokens masked in API responses

### 1.5 Testing Depth
**397 tests** across 5 categories:
- Misconfiguration scenarios (200): Comprehensive email security edge cases
- Security & stress tests (118): Auth bypass, SQL injection, XSS, path traversal, credential masking, concurrency, security headers, privacy
- Backend QA (38): Thread safety, RFC compliance, median edge cases, error extraction
- Benchmark & rules (20): Tool comparison, scoring system, performance benchmarks, rules regressions
- Functional tests (19): Core scanner, database, dashboard, analysis, CLI, remediation, and fallbacks

This represents approximately **6× more security/stress tests than functional tests** — unusual for an academic project and demonstrates security-first thinking.

### 1.6 Self-Contained Architecture
- Single `pip install -r requirements.txt` sets up everything
- No Docker, Kubernetes, or cloud dependencies required
- SQLite (WAL mode) provides persistence without a database server
- `START.bat` one-click launch for Windows
- All HTML/CSS/JS inline in dashboard.py — no build tools, no npm, no webpack

### 1.7 Academic Features
- PDF report export (reportlab) for individual domains
- Score timeline chart (Chart.js) for trend analysis
- CSV/Markdown report generation for dissertation figures
- Tool comparison API endpoint (`/api/tools/comparison`) for academic benchmarking
- Matplotlib figure generation for academic papers

---

## 2. Weaknesses

### 2.1 Monolithic Dashboard Architecture
The entire web application lives in a single file (`dashboard.py`, ~5,500 lines). While functional, this has consequences:
- **Maintainability:** Difficult for a team to work on simultaneously
- **Readability:** Finding specific functionality requires search rather than navigation
- **Testing:** Cannot test individual UI components in isolation

**Mitigation:** For an FYP prototype built by a single developer, this is pragmatic. All templates are inline which eliminates template-file sync issues.

### 2.2 No DMARC Aggregate Report Parsing
AuroraEdge checks if `rua=` is configured but does not ingest or parse the XML aggregate reports that receivers send back. Commercial tools (OnDMARC, EasyDMARC) provide this as a core feature.

**Impact:** Users cannot visualise who is sending email on their behalf, which is valuable for the `p=none` → `p=reject` migration journey.

### 2.3 No SPF Flattening
While AuroraEdge detects SPF records that exceed the 10-lookup limit (R3), it cannot automatically flatten them. SPF flattening is a non-trivial optimisation that requires resolving all `include:` chains to IP ranges and maintaining them as records change.

### 2.4 DKIM Selector Discovery Is Heuristic
DKIM keys are published at `<selector>._domainkey.<domain>`. Since selectors are arbitrary strings, discovery relies on a list of 30 common selectors (google, selector1, default, etc.). Domains using unusual selectors will show "DKIM not found" even if DKIM is deployed.

**Mitigation:** The 30-selector list covers the vast majority of email providers. True discovery would require parsing email headers (which requires receiving actual emails from the domain).

### 2.5 Localhost-Only Deployment
The system binds to `127.0.0.1:8080` by default. While Cloudflare Tunnel support exists for remote access, there is no built-in HTTPS termination, reverse proxy configuration, or multi-user support.

**Acceptable for:** An FYP prototype / managed security tool run by a single administrator.

### 2.6 In-Memory Rate Limiter
The rate limiter uses a Python `dict` that resets on server restart. Under high traffic this could grow unbounded (though stale entries are cleaned on each check). A production system would use Redis or a database-backed solution.

### 2.7 No IPv6 Blacklist Checking
RBL/DNSBL checks only support IPv4 addresses. If MX servers resolve to IPv6-only addresses, they will not be checked against blacklists.

### 2.8 No Scheduled Background Scanning
While the Managed Domains page allows adding domains for monitoring, there is no background scheduler (cron/APScheduler) that automatically rescans at intervals. Scans are triggered manually or on page load.

---

## 3. Comparison Summary

| Capability | AuroraEdge | Commercial Tools |
|------------|:----------:|:----------------:|
| Protocol checks | 10 | 3–6 typically |
| Auto-fix DNS | ✅ (Cloudflare) | ❌ (manual) |
| DMARC report parsing | ❌ | ✅ |
| SPF flattening | ❌ | Some |
| Self-hosted / free | ✅ | ❌ (£50–200/mo) |
| Open source | ✅ | ❌ |
| PDF reports | ✅ | ✅ |
| Score timeline | ✅ | ✅ |
| Record generator wizard | ✅ | Some |
| Blacklist checking | ✅ | Some |
| Security test suite | 118 tests | N/A |

---

## 4. Future Work

These features would strengthen AuroraEdge for production use beyond the FYP:

1. **DMARC Aggregate Report Ingestion** — Parse RUA XML reports to visualise sending sources and authentication pass rates. Would enable data-driven `p=none` → `p=reject` migration.

2. **Background Scheduler** — Use APScheduler or Celery to rescan managed domains at configured intervals (daily/weekly) without manual intervention.

3. **SPF Flattening Engine** — Automatically resolve `include:` chains to IP CIDRs and maintain flattened SPF records, staying within the 10-lookup limit.

4. **Multi-Provider DNS Support** — Extend auto-fix beyond Cloudflare to Route53 (AWS), Azure DNS, and GoDaddy via their respective APIs.

5. **User Management** — Role-based access control (RBAC) with per-user domain assignments for multi-tenant deployment.

6. **DKIM Header Parsing** — Accept raw email headers (paste or upload) to extract the actual selector in use, solving the heuristic discovery limitation.

7. **IPv6 DNSBL Support** — Extend RBL checking to work with AAAA records and IPv6-format DNSBL queries.

8. **Webhook/Notification Integration** — Push alerts to Slack, Teams, or email when domain grades drop or new vulnerabilities are detected.

---

## 5. Conclusion

AuroraEdge's core strength is its **breadth of protocol coverage** combined with **automated remediation** — a combination not found in any comparable academic or free tool. The security testing depth (118 security tests) demonstrates mature defensive engineering. The main limitations (no DMARC report parsing, no SPF flattening, monolithic architecture) are well-understood trade-offs appropriate for a single-developer FYP prototype targeting small organisations. The system successfully achieves its stated aim: reducing the complexity of email security for organisations without dedicated security teams.
