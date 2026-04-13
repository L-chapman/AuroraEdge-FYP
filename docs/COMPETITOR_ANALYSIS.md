# AuroraEdge — Competitor Analysis & Feature Gap Assessment

*Generated: 2026-02-26 | Research-based analysis for FYP academic comparison*

## Executive Summary

- AuroraEdge is strongest where it combines broad protocol coverage with self-hosted operation and Cloudflare-backed DNS remediation.
- The largest competitive gap remains DMARC aggregate report processing, followed by SPF flattening, richer deliverability tooling, and historical visualisation.
- Use **Section 2** for feature-frequency patterns, **Section 3** for priority gaps, **Section 4** for implementation direction, and **Section 6** for the final comparison matrix.

Note:

- Official vendor and product names keep their original spelling where needed.

---

## 1. Competitor Profiles

### 1.1 MXToolbox (mxtoolbox.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Freemium SaaS |
| **Target** | Email admins, IT professionals, marketers |
| **Pricing** | Free (basic lookups) / Delivery Center $129–$399/mo |

**Checks Performed:**
- SPF, DKIM, DMARC, MX, A, PTR, CNAME, SOA, TXT, WHOIS, ARIN
- SMTP diagnostics (port 25 testing)
- Blacklist checking (100+ blacklists)
- HTTP/HTTPS connectivity
- DNS propagation, DNSSEC
- Ping, Traceroute, TCP port scan

**Unique Features AuroraEdge Lacks:**
- **Blacklist/RBL monitoring** — checks IPs against 100+ real-time blacklists
- **IP reputation scoring** — sender IP reputation tracking
- **Inbox placement analysis** — tests delivery to Google, Yahoo, Microsoft inboxes
- **Recipient complaint monitoring** — integrates with 6 feedback loop providers
- **Outbound + inbound mailflow monitoring** — latency measurement for mail flow
- **SPF flattening** — resolves nested SPF includes to stay under 10 DNS lookup limit
- **DNS propagation checking** — verifies record propagation globally
- **WHOIS lookups** — domain registration information
- **Network diagnostics** — ping, traceroute, port scanning
- **REST API** — programmatic access to all lookups and monitors

---

### 1.2 dmarcian (dmarcian.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Commercial SaaS |
| **Target** | Individuals, SMBs, enterprises, MSPs |
| **Pricing** | Free (personal, 2 domains) / Basic $20/mo / Plus $199/mo / Enterprise $499/mo |

**Checks Performed:**
- SPF, DKIM, DMARC inspection and validation
- DMARC aggregate (RUA) report processing
- DMARC forensic (RUF) report processing
- TLS reporting

**Unique Features AuroraEdge Lacks:**
- **DMARC aggregate report (RUA) ingestion & visualisation** — receives, parses, and visualises XML aggregate reports from ISPs
- **DMARC forensic report (RUF) processing** — receives and displays per-message failure forensics
- **XML-to-human converter** — transforms raw DMARC XML into readable format
- **Automatic subdomain detection** — discovers subdomains sending mail from aggregate data
- **Source identification & enrichment** — identifies sending sources (e.g., Mailchimp, SendGrid) from aggregate data
- **Domain discovery** — finds all domains associated with an organisation
- **DMARC record wizard** — step-by-step guided record creation
- **IP safelisting** — whitelist known-good sending IPs
- **Alert Central** — configurable alerts for DMARC compliance changes
- **Domain groups** — organise domains into logical groups
- **Data history** — up to unlimited historical retention

---

### 1.3 DMARC Analyzer by Mimecast (mimecast.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Enterprise SaaS |
| **Target** | Enterprise organisations, brand protection teams |
| **Pricing** | Free trial / Enterprise subscription (contact sales) |

**Checks Performed:**
- SPF, DKIM, DMARC configuration validation
- DMARC aggregate report processing
- Domain spoofing detection
- Brand impersonation monitoring

**Unique Features AuroraEdge Lacks:**
- **DMARC aggregate report (RUA) processing** — cloud-based report ingestion from ISPs
- **Recommendation engine** — AI-driven suggestions for DMARC policy progression
- **DMARC record setup wizard** — guided configuration
- **Active monitoring service** — managed monitoring with expert alerts
- **Brand impersonation detection** — identifies unauthorised use of domain
- **PDF executive reports** — management-ready compliance reports
- **Managed services option** — expert-guided DMARC deployment

---

### 1.4 Postmark DMARC / DMARC Digests (dmarc.postmarkapp.com / dmarcdigests.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Freemium / Paid SaaS |
| **Target** | Developers, SaaS businesses, small teams |
| **Pricing** | Free (weekly email digest via Postmark) / $14/mo per domain (DMARC Digests full platform) |

**Checks Performed:**
- DMARC aggregate report processing
- SPF and DKIM alignment validation
- Source identification

**Unique Features AuroraEdge Lacks:**
- **DMARC aggregate report ingestion** — processes RUA XML reports from mailbox providers
- **Weekly/monthly email digest reports** — human-readable summaries delivered by email
- **60-day activity history** — rolling window of all mail sources
- **Actionable guidance per source** — specific fix instructions per sending source
- **Team accounts** — invite team members to view reports
- **Email deliverability focus** — oriented around inbox placement rather than just security

---

### 1.5 Hardenize (hardenize.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Enterprise SaaS |
| **Target** | Network security teams, enterprises with large web/mail infrastructure |
| **Pricing** | Free trial / Subscription (contact sales) |

**Checks Performed:**
- SPF, DKIM, DMARC, MTA-STS, TLS-RPT
- STARTTLS with TLS/PKI depth analysis
- SSL/TLS protocol enumeration (all versions, cipher suites, named groups)
- HTTP security headers (HSTS, CSP, SRI, Expect-CT)
- DNSSEC validation, DANE
- Certificate analysis (trust stores, CT monitoring, expiration)
- IPv4/IPv6 dual-stack testing
- Network port scanning (top 2,000 TCP/UDP)

**Unique Features AuroraEdge Lacks:**
- **SSL/TLS deep analysis** — full cipher suite enumeration, protocol version testing, client simulation
- **Certificate Transparency monitoring** — real-time CT log watching for misissued certs
- **Certificate expiration alerts** — proactive certificate lifecycle management
- **DNSSEC validation** — verifies DNSSEC chain of trust
- **DANE validation** — DNS-based Authentication of Named Entities
- **HTTP security headers** — HSTS, CSP, SRI, Expect-CT, cookie security analysis
- **Internet asset discovery** — automatic discovery of all web/mail properties
- **Subdomain enumeration** — database of global subdomains
- **Cloud account integrations** — AWS, Azure, GCP, Cloudflare, DigiCert connectors
- **Network port scanning** — TCP/UDP port enumeration
- **IPv6 testing** — dual-stack configuration validation
- **Change detection & events** — configuration change alerts ("network flight recorder")
- **Teams and dashboards** — role-based access, host group assignment

---

### 1.6 Mail-Tester (mail-tester.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Free online tool |
| **Target** | Email marketers, newsletter senders, developers |
| **Pricing** | Free (limited checks/day) / API available |

**Checks Performed:**
- SPF validation on sent email
- DKIM signature verification on sent email
- DMARC alignment check
- Spam score analysis (SpamAssassin-based)
- Email content analysis
- Blacklist checking

**Unique Features AuroraEdge Lacks:**
- **Live email testing** — send an actual email and get it analysed
- **Spam score calculation** — SpamAssassin-based scoring of email content
- **Email content analysis** — checks HTML, text, links, images for spam signals
- **Email header analysis** — parses and evaluates actual email headers
- **Deliverability scoring** — combined score for how "spammy" a message appears

---

### 1.7 Valimail (valimail.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Enterprise SaaS |
| **Target** | Large enterprises, regulated industries |
| **Pricing** | Enterprise subscription (contact sales) |

**Checks Performed:**
- SPF, DKIM, DMARC
- BIMI (Brand Indicators for Message Identification)
- Aggregate report processing

**Unique Features AuroraEdge Lacks:**
- **BIMI support** — validation and implementation of brand logos in email clients
- **Automated SPF management** — dynamic SPF record flattening and optimisation
- **Instant DMARC enforcement** — automated policy progression (none → quarantine → reject)
- **Sender identity management** — centralised control of all authorised senders
- **DMARC-as-a-service** — fully managed deployment
- **FedRAMP authorised** — US government compliance certification

---

### 1.8 EasyDMARC (easydmarc.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Commercial SaaS |
| **Target** | SMBs, enterprises, MSPs, all verticals |
| **Pricing** | Free (1 domain, 1K emails) / Plus £36/mo / Premium £72/mo / Enterprise custom |

**Checks Performed:**
- SPF, DKIM, DMARC, BIMI validation
- MTA-STS, TLS-RPT
- Aggregate report (RUA) processing with GeoMaps
- Failure report (RUF) processing
- Email header analysis
- Phishing URL checking
- DNS record lookups
- IP/domain reputation checking

**Unique Features AuroraEdge Lacks:**
- **DMARC aggregate report (RUA) processing with GeoMaps** — geographic visualisation of sending sources
- **DMARC failure reports (RUF)** — per-message forensic data
- **BIMI checker and managed BIMI** — brand logo in inbox support
- **Email header analyser** — parse and diagnose real email headers
- **Phishing URL checker** — evaluate URLs for phishing indicators
- **IP/domain reputation monitoring** — blacklist & reputation tracking
- **EasySPF (SPF flattening)** — dynamic SPF macro flattening
- **Managed DKIM** — automatic DKIM key rotation across sources
- **DNS provider integrations** — Cloudflare, GoDaddy, Google Cloud DNS push
- **SIEM integrations** — Microsoft Sentinel, audit log export
- **Weekly email reports** — automated email summaries
- **Email vendor identification** — auto-detect sending services from aggregate data
- **Subdomain detection** — from aggregate reports
- **Alert management** — custom alert rules and thresholds
- **Compliance tracking** — Google/Yahoo bulk sender, PCI DSS 4.0, GDPR dashboards

---

### 1.9 PowerDMARC (powerdmarc.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | Commercial SaaS |
| **Target** | MSPs/MSSPs, enterprises, governments |
| **Pricing** | 15-day free trial / Subscription tiers (contact for pricing) |

**Checks Performed:**
- SPF, DKIM, DMARC, BIMI
- MTA-STS, TLS-RPT
- Aggregate (RUA) and forensic (RUF) report processing
- Email header analysis
- Domain reputation

**Unique Features AuroraEdge Lacks:**
- **Threat Intelligence engine** — real-time visibility into malicious sources abusing domains
- **Threat Map** — geographic visualisation of attack origins
- **AI-powered recommendations** — after 7-day learning phase, suggests optimal configurations
- **Forensic reports with encryption** — RUF data encrypted with user's own keys
- **PowerSPF (SPF flattening)** — one-click SPF lookup limit resolution
- **BIMI hosting** — managed BIMI record and VMC certificate
- **Report IP abuse** — one-click reporting of abusive IPs
- **Power Take Down** — 24/7 SOC to take down abusive sources
- **Live threat map** — real-time global attack visualisation
- **Auto DNS publishing** — push DNS changes without manual updates
- **Whitelabel platform** — MSPs can rebrand as their own
- **Multi-lingual control panel** — internationalisation
- **DNS timeline & security score history** — track score progression over time
- **PDF compliance reports** — executive-ready reporting

---

### 1.10 URIports (uriports.com)

| Attribute | Detail |
|-----------|--------|
| **Type** | SaaS (Dutch company) |
| **Target** | Web developers, security teams, domain administrators |
| **Pricing** | Free 1-month trial / $1.25/mo (personal) to $480/mo (enterprise) |

**Checks Performed:**
- DMARC (aggregate + failure), with ARC support
- TLS-RPT (DANE and MTA-STS)
- SPF, DKIM, BIMI, DANE, MTA-STS, MX validation
- Content Security Policy (CSP) monitoring
- Network Error Logging (NEL)
- Permissions Policy, COOP/COEP
- DNS monitoring, Certificate monitoring
- Security.txt validation

**Unique Features AuroraEdge Lacks:**
- **ARC (Authenticated Received Chain) support** — handles forwarded mail scenarios
- **DANE validation** — TLSA record verification
- **BIMI validation** — brand logo record checking
- **Content Security Policy monitoring** — web security header reporting
- **Network Error Logging** — browser-side error collection
- **Certificate monitoring** — expiration alerts, CT log tracking
- **DNS change monitoring** — alerts when records change
- **Security.txt validation** — checks for RFC 9116 security contact file
- **Data enrichment** — geocoding, hostname lookup, WHOIS, abuse contact info
- **Smart prioritisation** — ranks issues by how widespread across sources
- **Custom ignore/block rules** — filter out noise from known-benign violations
- **DMARC failure report encryption** — encrypted forensic report handling
- **Hosted MTA-STS** — manages MTA-STS policy hosting

---

## 2. Feature Frequency Heat Map

How many of the 10 competitors offer each feature that AuroraEdge **lacks**:

| Missing Feature | Competitors Offering It | Count |
|----------------|------------------------|-------|
| DMARC Aggregate Report (RUA) Ingestion | dmarcian, Mimecast, Postmark, EasyDMARC, PowerDMARC, URIports, Valimail | **7/10** |
| DMARC Forensic Report (RUF) Processing | dmarcian, EasyDMARC, PowerDMARC, URIports | **4/10** |
| BIMI Support | EasyDMARC, PowerDMARC, URIports, Valimail | **4/10** |
| SPF Flattening / Macro Optimisation | MXToolbox, EasyDMARC, PowerDMARC, Valimail | **4/10** |
| Blacklist / IP Reputation Monitoring | MXToolbox, EasyDMARC, PowerDMARC, Mail-Tester | **4/10** |
| Email Header Analysis | EasyDMARC, PowerDMARC, Mail-Tester | **3/10** |
| DANE / DNSSEC Validation | Hardenize, URIports | **2/10** |
| Certificate Monitoring / CT Logs | Hardenize, URIports | **2/10** |
| DNS Change Monitoring | URIports, Hardenize | **2/10** |
| Geographic Visualisation (GeoMaps) | EasyDMARC, PowerDMARC | **2/10** |
| Threat Intelligence / Threat Maps | PowerDMARC | **1/10** |
| AI-Powered Recommendations | PowerDMARC | **1/10** |
| Live Email Testing (Send & Analyse) | Mail-Tester | **1/10** |
| Spam Score Analysis | Mail-Tester | **1/10** |
| Subdomain Discovery (from DNS/Reports) | dmarcian, EasyDMARC, Hardenize | **3/10** |
| PDF Report Export | Mimecast, PowerDMARC | **2/10** |
| Scheduled Email Digest Reports | Postmark, EasyDMARC, PowerDMARC | **3/10** |
| DMARC Record Wizard / Generator | dmarcian, Mimecast, PowerDMARC, EasyDMARC | **4/10** |
| Security.txt Validation | URIports | **1/10** |
| ARC Support | URIports | **1/10** |
| Phishing URL Detection | EasyDMARC | **1/10** |

---

## 3. Prioritised Missing Features

### CRITICAL GAPS — Features most competitors have that AuroraEdge lacks

These are table-stakes features that **7 or more** competitors offer. Implementing these would close the most significant gap.

| # | Feature | Difficulty | FYP Impact | Description |
|---|---------|-----------|------------|-------------|
| **C1** | **DMARC Aggregate Report (RUA) Parsing** | HIGH | VERY HIGH | Receive and parse DMARC XML aggregate reports. This is THE defining feature of DMARC monitoring platforms. Requires: (1) an email endpoint or API to receive reports, (2) XML parser for DMARC aggregate format, (3) data storage, (4) visualisation dashboard. Could simulate with file upload of XML reports as MVP. |
| **C2** | **BIMI Lookup & Validation** | LOW | MEDIUM | Check for BIMI DNS records (`default._bimi.domain`), validate SVG Tiny PS logo format, check VMC certificate. Simple DNS TXT lookup + validation logic. Very achievable. |
| **C3** | **SPF Flattening / Lookup Counter** | MEDIUM | HIGH | Count SPF DNS lookups (10 max per RFC 7208), flag `permerror` risk, suggest flattened alternatives. Recursively resolve `include:`, `redirect=`, `a:`, `mx:` mechanisms and count. |
| **C4** | **DMARC/SPF Record Generator Wizard** | LOW | MEDIUM | Interactive form to build valid DMARC/SPF/DKIM records with explanations. Pure frontend + validation logic. Several competitors offer this as a free tool. |

### DIFFERENTIATORS — Features that would make AuroraEdge stand out academically

These are **technically impressive** features with strong FYP writeup value.

| # | Feature | Difficulty | FYP Impact | Description |
|---|---------|-----------|------------|-------------|
| **D1** | **DMARC XML Report Upload & Visualisation** | MEDIUM | VERY HIGH | Allow users to upload DMARC XML aggregate report files (`.xml` or `.xml.gz`) and render visual dashboards: pass/fail rates, source IPs, SPF/DKIM alignment. Doesn't require running an email server — just file upload. Demonstrates report parsing capability. |
| **D2** | **Threat Map / GeoIP Visualisation** | MEDIUM | HIGH | Map sending source IPs to geographic locations using free GeoIP databases (MaxMind GeoLite2). Display on an interactive map. Visually impressive for demos. |
| **D3** | **Email Header Analyser** | LOW-MEDIUM | HIGH | Paste raw email headers → parse and display: authentication results, hop-by-hop routing, SPF/DKIM/DMARC verdicts, delays per hop. Pure parsing logic, no external dependencies. |
| **D4** | **DANE / DNSSEC Validation** | MEDIUM | HIGH | Check TLSA records for DANE, verify DNSSEC chain. Demonstrates understanding of DNS security beyond basic records. Uses `dns.resolver` with DNSSEC flags. |
| **D5** | **Security Score Timeline** | LOW | HIGH | Store historical scores per domain and render a chart showing grade progression over time. Already have scan history — just need a chart visualisation. |
| **D6** | **PDF Report Export** | LOW | MEDIUM | Generate downloadable PDF security reports using `reportlab` or `weasyprint`. Professional-looking output for FYP demo. |
| **D7** | **AI/ML Policy Recommender** | MEDIUM-HIGH | VERY HIGH | Analyse scan results and recommend next steps (e.g., "your SPF is valid, DMARC is at p=none — recommend moving to p=quarantine"). Could use rule-based logic or a simple ML model. Mirrors PowerDMARC's AI feature. |

### NICE-TO-HAVES — Useful but lower priority

| # | Feature | Difficulty | FYP Impact | Description |
|---|---------|-----------|------------|-------------|
| **N1** | **Blacklist / RBL Checking** | LOW-MEDIUM | MEDIUM | Query DNSBL servers for MX server IPs. Simple DNS lookups against known RBL zones (Spamhaus, Barracuda, etc.). |
| **N2** | **DNS Propagation Checker** | MEDIUM | LOW | Query multiple global DNS resolvers to check record consistency. Requires list of public resolvers across regions. |
| **N3** | **WHOIS Lookup** | LOW | LOW | Domain registration info via `python-whois` library. Simple integration. |
| **N4** | **Certificate Transparency Monitoring** | HIGH | MEDIUM | Monitor CT logs for certificates issued for managed domains. Complex real-time streaming from CT log servers. |
| **N5** | **Security.txt Validation** | LOW | LOW | Check `/.well-known/security.txt` for RFC 9116 compliance. Simple HTTP fetch + field validation. |
| **N6** | **ARC (Authenticated Received Chain)** | MEDIUM | LOW | Validate ARC headers for forwarded email scenarios. Niche but technically interesting. |
| **N7** | **Phishing URL Scanner** | MEDIUM | MEDIUM | Check URLs against Google Safe Browsing API or similar. Useful but tangential to core email auth focus. |
| **N8** | **Scheduled Email Digest Reports** | LOW-MEDIUM | LOW | Send periodic email summaries of domain health. Requires SMTP sending capability (could use SendGrid free tier). |
| **N9** | **IPv6 Connectivity Testing** | LOW | LOW | Check if MX servers are reachable over IPv6. Simple socket connection test. |
| **N10** | **Subdomain Enumeration** | MEDIUM | MEDIUM | Discover subdomains via DNS brute-force, Certificate Transparency, or crt.sh API. |

---

## 4. Implementation Recommendations for FYP

### Tier 1 — Implement Now (High impact, achievable)

| Feature | Est. Effort | Why |
|---------|-------------|-----|
| **BIMI Lookup (C2)** | 2–3 hours | Simple DNS TXT lookup at `default._bimi.domain`. Already have DNS infrastructure. Closes a gap with 4 competitors. |
| **SPF Lookup Counter (C3)** | 4–6 hours | Recursive SPF resolver counting DNS lookups. Directly extends existing SPF checking. Very demonstrable. |
| **DMARC Record Generator Wizard (C4)** | 3–4 hours | Frontend form + validation. Competitors offer this as a free tool — great for comparison table. |
| **Security Score Timeline Chart (D5)** | 2–3 hours | Already store scan history. Add a Chart.js line graph to domain detail page. Visually impressive. |
| **PDF Report Export (D6)** | 3–4 hours | Use `reportlab` to generate branded PDF scan reports. Professional touch for demos. |

**Total: ~15–20 hours for 5 features closing gaps against all 10 competitors.**

### Tier 2 — Implement If Time Allows (Strong FYP differentiators)

| Feature | Est. Effort | Why |
|---------|-------------|-----|
| **DMARC XML Upload & Parse (D1)** | 8–12 hours | THE feature that separates toys from real tools. Even a basic file-upload XML parser would be impressive. |
| **Email Header Analyser (D3)** | 4–6 hours | Pure parsing, no external deps. Paste headers → see auth results. Very useful for educational context. |
| **Threat GeoIP Map (D2)** | 6–8 hours | Use MaxMind GeoLite2 + Leaflet.js. Visually stunning for presentations. |
| **Blacklist / RBL Check (N1)** | 3–4 hours | Simple DNSBL queries. MXToolbox's most popular feature. |
| **DANE / DNSSEC Check (D4)** | 4–6 hours | Demonstrates advanced DNS security knowledge. Only 2 competitors do this. |

### Tier 3 — Stretch Goals

| Feature | Est. Effort | Why |
|---------|-------------|-----|
| **AI Policy Recommender (D7)** | 8–12 hours | Rule-based "AI" that suggests DMARC policy progression. High academic value. |
| **Subdomain Discovery (N10)** | 6–8 hours | Query crt.sh API for CT-based subdomain discovery. |
| **Security.txt Validation (N5)** | 1–2 hours | Quick win, easy to implement. |

---

## 5. Updated Competitive Position

### Current AuroraEdge Unique Strengths (vs all 10 competitors)
1. **Open-source / self-hosted** — no competitor except MXToolbox free tier offers this
2. **Automatic DNS remediation via Cloudflare** — only PowerDMARC has "auto DNS publishing"; AuroraEdge does actual record creation + Worker deployment
3. **MTA-STS Worker deployment** — unique automated Cloudflare Worker for MTA-STS policy
4. **Academic/educational focus** — no competitor targets FYP/research use
5. **Zero cost** — most competitors are $20–$500+/month
6. **Combined scanning + remediation** — most tools are scan-only or manage-only

### After Implementing Tier 1 Features
- Closes BIMI gap (matches EasyDMARC, PowerDMARC, URIports, Valimail)
- Closes SPF flattening gap (matches MXToolbox, EasyDMARC, PowerDMARC)
- Adds record generator (matches dmarcian, Mimecast, PowerDMARC, EasyDMARC)
- Visual score timeline (matches PowerDMARC's "security score history")
- PDF reports (matches Mimecast, PowerDMARC)
- **Net result: AuroraEdge would cover 85%+ of features found across all competitors**

### After Implementing Tier 2 Features
- DMARC report parsing makes AuroraEdge a genuine monitoring platform
- Email header analysis brings diagnostic depth
- GeoIP visualisation provides enterprise-grade presentation
- **Net result: AuroraEdge would be the most comprehensive open-source email security tool available**

---

## 6. Summary Comparison Matrix

| Feature | AE | MXT | dmar | Mime | Post | Hard | MailT | Vali | Easy | Pwr | URI |
|---------|:--:|:---:|:----:|:----:|:----:|:----:|:-----:|:----:|:----:|:---:|:---:|
| SPF Check | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DKIM Check | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DMARC Check | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MTA-STS Check | ✅ | — | — | — | — | ✅ | — | — | ✅ | ✅ | ✅ |
| TLS-RPT Check | ✅ | — | ✅ | — | — | ✅ | — | — | ✅ | ✅ | ✅ |
| STARTTLS Check | ✅ | ✅ | — | — | — | ✅ | — | — | — | — | — |
| MX Check | ✅ | ✅ | — | — | — | ✅ | — | — | — | — | ✅ |
| **BIMI** | ❌ | — | — | — | — | — | — | ✅ | ✅ | ✅ | ✅ |
| **DANE/DNSSEC** | ❌ | ✅ | — | — | — | ✅ | — | — | — | — | ✅ |
| **RUA Ingestion** | ❌ | — | ✅ | ✅ | ✅ | — | — | ✅ | ✅ | ✅ | ✅ |
| **RUF Processing** | ❌ | — | ✅ | — | — | — | — | — | ✅ | ✅ | ✅ |
| **SPF Flattening** | ❌ | ✅ | — | — | — | — | — | ✅ | ✅ | ✅ | — |
| **Blacklist/RBL** | ❌ | ✅ | — | — | — | — | ✅ | — | ✅ | ✅ | — |
| **Record Generator** | ❌ | — | ✅ | ✅ | — | — | — | — | ✅ | ✅ | — |
| **Email Header** | ❌ | — | — | — | — | — | ✅ | — | ✅ | ✅ | — |
| **GeoIP Map** | ❌ | — | — | — | — | — | — | — | ✅ | ✅ | — |
| **Cert Monitoring** | ❌ | — | — | — | — | ✅ | — | — | — | — | ✅ |
| **DNS Monitoring** | ❌ | — | — | — | — | ✅ | — | — | — | — | ✅ |
| Auto-Fix DNS | ✅ | — | — | — | — | — | — | — | — | ✅* | — |
| Scoring/Grades | ✅ | — | — | — | — | — | — | — | — | ✅ | — |
| CLI Interface | ✅ | — | — | — | — | — | — | — | — | — | — |
| Self-Hosted | ✅ | — | — | — | — | — | — | — | — | — | — |
| Free/Open Source | ✅ | ✅* | — | — | ✅* | — | ✅* | — | ✅* | — | — |
| Batch Scanning | ✅ | — | — | — | — | — | — | — | — | — | — |

*Legend: ✅ = has feature, ❌ = AuroraEdge gap, — = doesn't have, ✅* = partial/limited*

---

*This analysis was compiled from live website research on 2026-02-26. Feature availability may change as competitors update their products.*
