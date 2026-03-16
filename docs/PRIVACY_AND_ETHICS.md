# AuroraEdge — Privacy, Legal & Ethics Policy

*Version 3.2 — March 2026*
*Final Year Project — Leon Chapman*

---

## 1. Purpose

AuroraEdge is an **academic prototype** for automated email authentication analysis and cyber defence. It scans publicly available DNS records and HTTPS policies to assess email security posture. This document defines the legal, ethical, and data-handling framework governing its use.

---

## 2. Data Collection — What We Collect

### 2.1 DNS & Public Record Data (Scan Data)

AuroraEdge queries **only publicly available information**:

| Data Type | Source | Example |
|-----------|--------|---------|
| SPF records | Public DNS TXT | `v=spf1 include:_spf.google.com -all` |
| DKIM selectors | Public DNS TXT | `v=DKIM1; k=rsa; p=...` |
| DMARC policies | Public DNS TXT (`_dmarc.`) | `v=DMARC1; p=reject; rua=mailto:...` |
| MTA-STS policies | Public HTTPS | `mode: enforce` |
| TLS-RPT records | Public DNS TXT (`_smtp._tls.`) | `v=TLSRPTv1; rua=mailto:...` |
| BIMI records | Public DNS TXT (`default._bimi.`) | `v=BIMI1; l=https://...` |
| MX records | Public DNS MX | `aspmx.l.google.com` |
| STARTTLS support | Public SMTP banner (port 25) | TLS version, cipher info |
| RBL/Blacklist status | Public DNSBL queries | Listed/not listed |

AuroraEdge is designed to process infrastructure data rather than user content. In some cases, published DNS records may contain contact mailbox values such as `rua=mailto:...`, `ruf=mailto:...`, or `TLS-RPT rua=mailto:...`. When present, those values are collected as part of the public record and stored with the scan results. All queries use standard DNS resolution (UDP port 53) and HTTPS (TCP port 443) — the same mechanisms used by any email server or web browser.

### 2.2 User-Provided Configuration

| Data | Storage | Purpose |
|------|---------|---------|
| Cloudflare API Token | Local SQLite DB (`state/auroraedge.db`) | DNS auto-remediation |
| Cloudflare Zone ID | Local SQLite DB | Zone identification |
| Cloudflare Account ID | Local SQLite DB | Optional MTA-STS Worker deployment |
| Organisation name | Local SQLite DB | Report branding |
| Optional alert / contact email | Local SQLite DB | Operator-entered contact field (stored locally only; not used for outbound email in this version) |
| Dashboard token (`DASH_TOKEN`) | Environment variable only | Authentication |

### 2.3 What We Do NOT Collect

- No user tracking, analytics, or telemetry
- No cookies or browser fingerprinting
- No email content, mailbox access, or mail server authentication
- No credentials beyond operator-provided Cloudflare tokens
- No unnecessary personal data by design; operators should prefer shared role addresses (for example `security@org.example`) over individual mailboxes where possible

---

## 3. Data Storage

### 3.1 Storage Location

All data is stored **locally on the operator's machine**:

```
state/auroraedge.db — SQLite database (scan results, settings, alerts)
reports/*.csv       — CSV scan reports
reports/*.md        — Markdown scan reports
logs/dns_audit.log  — DNS change audit trail (rotated, max 2MB × 3)
```

### 3.2 Data at Rest

- **SQLite database** uses WAL (Write-Ahead Logging) mode for integrity
- **No encryption at rest** — this is a local-only prototype; the operator's OS-level encryption (BitLocker, FileVault) provides disk-level protection
- **No application-managed cloud sync** — AuroraEdge does not upload data to a vendor cloud service itself. However, if the project folder is stored inside a synchronised directory (for example OneDrive, Google Drive, or Dropbox), database, report, and log files may sync according to that service's configuration
- **Configurable data retention** — the `clear_on_start` setting wipes scan data on each server restart (default: enabled)
- **On-demand data clearing** — `POST /api/data/clear` allows the operator to wipe all scan data at any time while preserving application settings
- **Per-domain deletion** — `DELETE /api/history/{domain}` removes all scan records, domain entries, and alerts for a specific domain
- **UI data management** — the Settings page includes a "Clear All Scan Data" button with a confirmation dialog, enabling non-technical users to exercise data deletion without API knowledge

### 3.3 Data in Transit

- Dashboard is served over **HTTP on localhost** (127.0.0.1:8080) — suitable for local/lab use
- For production deployment, a reverse proxy with TLS (e.g., Cloudflare Tunnel, nginx + Let's Encrypt) should be used
- Cloudflare API calls use **HTTPS (TLS 1.2+)** exclusively
- DNS queries use standard unencrypted UDP; for sensitive environments, a DNS-over-HTTPS resolver can be configured

### 3.4 Data Retention

| Data | Default Retention | Configurable |
|------|-------------------|--------------|
| Scan results (DB) | Cleared on restart | Yes (`clear_on_start`, on-demand clear, per-domain delete) |
| CSV/MD reports | Persistent until deleted | Manual deletion |
| Audit logs | Rotated at 2MB (3 backups) | Via logging config |
| Settings | Persistent | Manual via Settings page |

---

## 4. Legal Basis

### 4.1 Lawful Scanning

AuroraEdge's scanning activities are **lawful** because:

1. **Public DNS data** — DNS records are published for the explicit purpose of being queried by any party (RFC 1035, RFC 7208, RFC 7489). Querying them does not constitute unauthorised access.

2. **No intrusion** — AuroraEdge performs no authentication attempts, no credential testing, no exploitation, and no modification of third-party systems. It is a **passive observer** of publicly published policies.

3. **MX/STARTTLS checks** — Connecting to port 25 of a public MX server to check STARTTLS support is standard SMTP behaviour (RFC 3207). AuroraEdge does not send emails or authenticate.

4. **RBL queries** — Querying DNSBL providers (Spamhaus, SpamCop, etc.) is a standard and intended use of their public DNS-based services.

5. **DNS auto-remediation** — Modifications to DNS records are performed **only** on domains the operator owns or has explicit written permission to manage, using their own Cloudflare API credentials.

### 4.2 Computer Misuse Act 1990 (UK)

AuroraEdge does **not** violate the Computer Misuse Act because:

- **Section 1 (Unauthorised access)**: Not applicable — all data accessed is publicly available via DNS/HTTPS
- **Section 2 (Intent to commit further offences)**: Not applicable — tool is defensive in nature
- **Section 3 (Unauthorised modification)**: DNS modifications require operator-owned Cloudflare credentials and domain ownership verification

### 4.3 GDPR Considerations

AuroraEdge primarily processes **technical infrastructure data** such as DNS records, MX hostnames, transport-security policies, and security scores. In many normal uses, that data will not identify a natural person. However, **limited personal data may be processed incidentally** where:

- a public DMARC or TLS-RPT record contains an identifiable email address
- the operator stores a personal contact email in Settings
- reports, logs, or screenshots are combined with other information that identifies an individual

Where personal data is present, the operator is the data controller for that local deployment and should ensure:

- a lawful basis for processing, typically legitimate interests or security administration
- data minimisation, including preferring shared role mailboxes over personal addresses
- secure local storage and access control on the host device
- timely deletion using the built-in clear and per-domain deletion controls where appropriate

For normal academic, lab, and local administrative use, the privacy risk is typically low because processing is limited, local, and focused on publicly published security records. A DPIA is not generally expected for this prototype in that context, but operators should assess their own deployment environment.

### 4.4 Cloudflare API Usage

- Cloudflare API tokens are stored locally and transmitted only to Cloudflare's API endpoints over HTTPS
- Token permissions should follow the principle of least privilege (Zone:DNS:Edit for a single zone)
- AuroraEdge does not expose full API tokens in UI/API responses and does not write them to audit logs; the full token remains in local settings storage and process memory while the application is running

---

## 5. Ethical Framework

### 5.1 Responsible Scanning

| Principle | Implementation |
|-----------|----------------|
| **Permission** | Auto-fix operates only on operator-owned domains (Cloudflare ownership check enforced) |
| **Proportionality** | Scans use standard DNS queries; no brute-forcing, no excessive request rates |
| **Transparency** | All scan checks are documented with RFC references; scoring methodology is open |
| **Non-malicious intent** | Tool is designed to improve security, not exploit weaknesses |
| **Rate limiting** | Batch scans limited to 20 domains; delays between DNS queries; DNSBL queries rate-limited |

### 5.2 Auto-Fix Safeguards

AuroraEdge can automatically modify DNS records via Cloudflare. Safeguards include:

1. **Domain ownership verification** — Cloudflare zone lookup confirms the domain belongs to the configured zone before any modification
2. **Audit logging** — Every DNS change is recorded in `logs/dns_audit.log` with timestamp, record type, old value, and new value
3. **Scope limitation** — Only DNS TXT/CNAME records are modified; no MX, A, or AAAA changes
4. **DKIM exclusion** — DKIM is intentionally not auto-fixed because it requires private key management and mail server configuration
5. **Rollback capability** — Audit log preserves previous record values for manual rollback
6. **Operator control** — Auto-fix requires explicit Cloudflare credential configuration; without credentials, no modifications occur

### 5.3 Academic Ethics

This project complies with academic research ethics:

- **No human subjects** — No user studies, surveys, or intervention-based participant research
- **Public data only** — All analysed data is freely available via standard internet protocols
- **Reproducibility** — All scanning methodology is documented and open-source
- **Attribution** — All RFC standards and third-party tools are cited
- **No deception** — The tool accurately represents its capabilities and limitations

---

## 6. Security Measures

### 6.1 Authentication

- Dashboard protected by `DASH_TOKEN` environment variable
- Token accepted via query parameter or `Authorization: Bearer` header
- Development mode (no token set) allows open access for local testing
- No default credentials — token must be explicitly configured

### 6.2 Input Validation

- All domain inputs sanitised via regex (`_DOMAIN_RE`) before processing
- Protocol prefixes, paths, and query strings stripped automatically
- Batch scan API limited to 20 domains per request
- JSON body validation on all POST endpoints
- Settings API accepts only whitelisted keys

### 6.3 Output Security

- Security headers applied to all responses (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Cloudflare API tokens masked in API responses (`****...****`)
- Error messages sanitised to prevent stack trace leakage
- HTML output escaped to prevent XSS

### 6.4 Infrastructure

- Localhost-only binding by default (127.0.0.1)
- No external network services exposed
- SQLite database file permissions controlled by OS
- Audit logs with rotation to prevent disk exhaustion

---

## 7. Limitations & Disclaimers

1. **Prototype status** — AuroraEdge is an academic prototype, not a production security product. It should not be the sole basis for security decisions.

2. **DNS propagation** — DNS changes may take up to 48 hours to propagate globally. Post-fix rescans may not reflect changes immediately.

3. **DKIM coverage** — DKIM selector discovery uses common selector names; custom selectors may not be detected.

4. **Scoring heuristics** — The scoring algorithm uses weighted heuristics. Scores are indicative, not authoritative.

5. **No guarantee** — AuroraEdge does not guarantee email deliverability or security. It provides analysis and recommendations based on published DNS policies.

6. **Operator responsibility** — The operator is responsible for:
   - Ensuring they have permission to scan target domains
   - Securing the local installation and database
   - Evaluating recommendations before applying DNS changes
   - Compliance with local laws and regulations

---

## 8. Third-Party Services

| Service | Purpose | Data Sent | Terms |
|---------|---------|-----------|-------|
| Cloudflare API | DNS record management | Domain names, record contents | [Cloudflare ToS](https://www.cloudflare.com/terms/) |
| Spamhaus DNSBL | Blacklist checking | MX server IP addresses | [Spamhaus DNSBL Usage Terms](https://www.spamhaus.org/organization/dnsblusage/) |
| SpamCop DNSBL | Blacklist checking | MX server IP addresses | Public DNS service |
| Barracuda DNSBL | Blacklist checking | MX server IP addresses | Public DNS service |
| SORBS DNSBL | Blacklist checking | MX server IP addresses | Public DNS service |
| UCEProtect DNSBL | Blacklist checking | MX server IP addresses | Public DNS service |
| jsDelivr CDN (Chart.js) | Client-side charting | Browser request metadata when the chart library is loaded (for example IP address, headers, user agent) | MIT License |

---

## 9. Contact

For questions about this privacy and ethics policy:

- **Project Author:** Leon Chapman
- **Institution:** Final Year Project
- **Repository:** Self-hosted / Academic submission

---

*This document defines the legal, ethical, and privacy controls for an academic cybersecurity tool that primarily processes public DNS and HTTPS security data, plus limited operator-provided local settings.*
