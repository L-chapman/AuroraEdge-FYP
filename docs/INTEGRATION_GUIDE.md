# AuroraEdge Integration Guide

## Overview

This guide covers the optional integrations and deployment extras around AuroraEdge.

You do **not** need everything in this document to run the project locally. For normal local setup, use `README.md` or `docs/TESTING_GUIDE.md` first.

### Quick Navigation

| If you want to... | Read this section |
|-------------------|------------------|
| Configure Cloudflare auto-fix | **1. Cloudflare DNS Auto-Fix Integration** |
| Build a mail lab with OpenDMARC | **2. OpenDMARC Integration** |
| Configure Postfix in a lab environment | **3. Postfix Mail Server Setup** |
| Publish MTA-STS or TLS-RPT records manually | **4. MTA-STS Configuration** and **5. TLS-RPT Configuration** |
| Deploy AuroraEdge behind HTTPS | **6. HTTPS Deployment for Production** |
| Write up comparison methodology for the dissertation | **7. Empirical Tool Comparison Methodology** |
| Clarify DKIM auto-fix boundaries | **8. DKIM Limitations and Scope** |

### Scope Note

Sections 2 and 3 describe optional external mail-lab integrations. They are not started by AuroraEdge itself and are not required for normal dashboard or CLI use.

---

## 1. Cloudflare DNS Auto-Fix Integration

AuroraEdge can automatically fix supported DNS records using the Cloudflare API.

### Prerequisites

- Cloudflare account with your domain
- API token with **DNS Edit** permissions
- Zone ID for your domain
- Account ID if you want Cloudflare Worker deployment for MTA-STS
- Optional Global API Key and account email if your API token cannot create Worker routes

### Getting Cloudflare Credentials

1. **Create API Token**:
   ```
   Cloudflare Dashboard → Profile → API Tokens → Create Token
   ```
   - Use template: **Edit zone DNS**
   - Zone Resources: Include → Specific zone → Your domain
   - Click "Continue to summary" → "Create Token"
   - **Save the token immediately** (shown only once)

2. **Find Zone ID**:
   ```
   Cloudflare Dashboard → Select Domain → Overview (right sidebar)
   ```
   - Copy the "Zone ID" value

### Configuration

Set environment variables before running AuroraEdge:

**Windows (PowerShell):**
```powershell
$env:CF_API_TOKEN = "your_api_token_here"
$env:CF_ZONE_ID = "your_zone_id_here"
$env:CF_ACCOUNT_ID = "your_account_id_here"
$env:CF_API_KEY = "your_global_api_key_here"   # optional fallback
$env:CF_EMAIL = "you@example.com"              # optional fallback
```

**Windows (Command Prompt):**
```cmd
set CF_API_TOKEN=your_api_token_here
set CF_ZONE_ID=your_zone_id_here
set CF_ACCOUNT_ID=your_account_id_here
```

**Linux/macOS:**
```bash
export CF_API_TOKEN="your_api_token_here"
export CF_ZONE_ID="your_zone_id_here"
export CF_ACCOUNT_ID="your_account_id_here"
```

### Using the DNS Auto-Fix Module

```python
from app.dns_fix import CloudflareDNS

# Initialise client
cf = CloudflareDNS()

# Validate connection
success, message = cf.validate_connection()
print(f"Connection: {message}")

# Fix SPF record
cf.fix_spf("example.com", includes=["_spf.google.com"])

# Fix DMARC record
cf.fix_dmarc(
    "example.com",
    policy="reject",
    rua="dmarc@example.com"
)

# Fix TLS-RPT
cf.fix_tls_rpt("example.com", rua="tlsrpt@example.com")
```

### Supported Auto-Fix Operations

| Record Type | Function | Description |
|-------------|----------|-------------|
| SPF | `fix_spf()` | Creates/updates SPF TXT record |
| DMARC | `fix_dmarc()` | Creates/updates _dmarc TXT record |
| TLS-RPT | `fix_tls_rpt()` | Creates/updates _smtp._tls TXT record |
| MTA-STS DNS | `fix_mta_sts_dns()` | Creates _mta-sts TXT record |
| MTA-STS HTTPS | `deploy_mta_sts_worker()` | Publishes the HTTPS policy through Cloudflare Workers |
| DKIM | `fix_dkim()` | Auto-configures DKIM for supported providers |

### Security Notes

⚠️ **Important Security Considerations:**

1. Never commit API tokens to version control
2. Use environment variables or secure secret management
3. Restrict token permissions to specific zones only
4. Audit log is maintained at `logs/dns_audit.log`
5. Automation mode:
    - Manual: call `fix_*()` methods directly (lab usage)
    - Platform: when Cloudflare settings are configured and a domain is onboarded as a managed domain, supported fixes can be applied automatically (zero-touch)

### Ethical & Operational Safeguards (Auto-Fix)

- **Test domain + explicit permission:** Auto-fix must be used only for domains you own or have written permission to manage.
- **Scoped permissions:** Use the minimum Cloudflare token scope (Zone:DNS:Edit) and a single zone.
- **Mail-flow risk:** Incorrect DNS changes can disrupt email delivery; treat automation as a controlled operational change and document it.
- **Rollback & audit trail:** Every change is logged, enabling rollback to a previous record value if problems occur.
- **DKIM scope:** AuroraEdge can auto-configure DKIM only for providers it can identify safely from MX patterns. If the provider is unknown, AuroraEdge gives manual guidance instead of guessing.

Additional limitation:
- **BIMI** is intentionally not auto-fixed. It is mainly a branding feature and needs logo/VMC assets that sit outside safe DNS-only automation.

---

## 2. OpenDMARC Integration

OpenDMARC validates DMARC policies on incoming email.

### Installation (Ubuntu/Debian)

```bash
# Install OpenDMARC
sudo apt update
sudo apt install opendmarc

# Start and enable service
sudo systemctl start opendmarc
sudo systemctl enable opendmarc
```

### Configuration

Edit `/etc/opendmarc.conf`:

```conf
# OpenDMARC Configuration for AuroraEdge
AuthservID mail.yourdomain.com
Socket inet:8893@localhost
TrustedAuthservIDs mail.yourdomain.com

# DMARC Policy
RejectFailures true
FailureReports true

# Reporting
HistoryFile /var/run/opendmarc/opendmarc.dat
ReportCommand /usr/sbin/opendmarc-sendmail

# Logging (integrates with AuroraEdge)
Syslog true
SyslogFacility mail
```

### Postfix Integration

Add to `/etc/postfix/main.cf`:

```conf
# OpenDMARC Integration
smtpd_milters = inet:localhost:8893
non_smtpd_milters = inet:localhost:8893
milter_default_action = accept
```

Reload Postfix:
```bash
sudo systemctl reload postfix
```

### Testing OpenDMARC

```bash
# Check status
sudo systemctl status opendmarc

# View logs
sudo tail -f /var/log/mail.log | grep opendmarc

# Send test email
echo "Test" | mail -s "DMARC Test" test@yourdomain.com
```

---

## 3. Postfix Mail Server Setup

Complete Postfix configuration for email authentication.

### Installation

```bash
sudo apt install postfix postfix-policyd-spf-python
```

### SPF Configuration

Add to `/etc/postfix/main.cf`:

```conf
# SPF Policy Check
policy-spf_time_limit = 3600s
smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    check_policy_service unix:private/policy-spf
```

Add to `/etc/postfix/master.cf`:

```conf
# SPF Policy Service
policy-spf  unix  -  n  n  -  0  spawn
    user=nobody argv=/usr/bin/policyd-spf
```

### DKIM with OpenDKIM

```bash
# Install OpenDKIM
sudo apt install opendkim opendkim-tools

# Generate DKIM key
sudo opendkim-genkey -t -s mail -d yourdomain.com
sudo mv mail.private /etc/opendkim/keys/yourdomain.com.private
sudo mv mail.txt /etc/opendkim/keys/yourdomain.com.txt
```

Configure `/etc/opendkim.conf`:

```conf
Domain yourdomain.com
KeyFile /etc/opendkim/keys/yourdomain.com.private
Selector mail
Socket inet:8891@localhost
```

Add DKIM DNS record from `/etc/opendkim/keys/yourdomain.com.txt`:

```
mail._domainkey IN TXT "v=DKIM1; k=rsa; p=MIGf..."
```

### Complete Postfix main.cf

```conf
# Basic Settings
myhostname = mail.yourdomain.com
mydomain = yourdomain.com
myorigin = $mydomain

# TLS Configuration (STARTTLS)
smtpd_tls_cert_file = /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3

# Milters (DKIM + DMARC)
smtpd_milters = inet:localhost:8891, inet:localhost:8893
non_smtpd_milters = inet:localhost:8891, inet:localhost:8893
milter_default_action = accept
```

### Testing

```bash
# Test local mail
echo "Test email body" | mail -s "Test Subject" user@yourdomain.com

# Check mail queue
mailq

# View mail logs
sudo tail -f /var/log/mail.log

# Test SMTP with STARTTLS
openssl s_client -connect mail.yourdomain.com:25 -starttls smtp
```

---

## 4. MTA-STS Configuration

MTA-STS requires HTTPS hosting for policy file.

### DNS Record

```
_mta-sts.yourdomain.com  TXT  "v=STSv1; id=20250101120000"
```

### Policy File

Host at `https://mta-sts.yourdomain.com/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mail.yourdomain.com
max_age: 604800
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name mta-sts.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/mta-sts.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mta-sts.yourdomain.com/privkey.pem;
    
    location /.well-known/mta-sts.txt {
        root /var/www/mta-sts;
        default_type text/plain;
    }
}
```

---

## 5. TLS-RPT Configuration

### DNS Record

```
_smtp._tls.yourdomain.com  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com"
```

### Processing Reports

TLS-RPT reports arrive as JSON attachments. Use AuroraEdge to parse:

```python
# Future AuroraEdge feature
# from src.app.tlsrpt_parser import parse_report
# parse_report("report.json")
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Cloudflare API error | Check token permissions and zone ID |
| OpenDMARC not filtering | Ensure milter is connected in Postfix |
| DKIM failing | Verify DNS record matches key selector |
| STARTTLS not working | Check certificate paths and permissions |
| SPF too many lookups | Flatten SPF record (max 10 lookups) |

### Diagnostic Commands

```bash
# Check DNS records
dig TXT _dmarc.yourdomain.com
dig TXT yourdomain.com
dig TXT mail._domainkey.yourdomain.com

# Test SMTP
telnet mail.yourdomain.com 25
EHLO test
STARTTLS

# Check services
systemctl status postfix opendkim opendmarc

# View logs
journalctl -u postfix -f
```

---

## AuroraEdge Logging

AuroraEdge maintains detailed logs for all operations:

| Log File | Purpose |
|----------|---------|
| `logs/auroraedge.log` | Main application log |
| `logs/scanner.log` | DNS scanning operations |
| `logs/dashboard.log` | Web dashboard requests |
| `logs/audit.log` | Security audit trail |
| `logs/errors.log` | Error-only log |
| `logs/dns_audit.log` | Cloudflare DNS changes |

### Log Level Configuration

Set environment variable:
```bash
export AURORAEDGE_LOG_LEVEL=DEBUG  # DEBUG, INFO, WARNING, ERROR
```

---

## 6. HTTPS Deployment for Production

For production deployments, AuroraEdge should be served over HTTPS. This is typically achieved using a reverse proxy rather than configuring TLS directly in Uvicorn.

### Option A: Caddy (Recommended - Automatic HTTPS)

Caddy automatically obtains and renews Let's Encrypt certificates.

**Install Caddy:**
```bash
# Ubuntu/Debian
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

**Caddyfile** (`/etc/caddy/Caddyfile`):
```
auroraedge.yourdomain.com {
    reverse_proxy localhost:8080
}
```

**Start Caddy:**
```bash
sudo systemctl enable caddy
sudo systemctl start caddy
```

### Option B: Nginx with Let's Encrypt

**Install Certbot:**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d auroraedge.yourdomain.com
```

**Nginx config** (`/etc/nginx/sites-available/auroraedge`):
```nginx
server {
    listen 443 ssl http2;
    server_name auroraedge.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/auroraedge.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auroraedge.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name auroraedge.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

### Option C: Direct Uvicorn TLS (Development/Testing Only)

```bash
# Generate self-signed cert (testing only)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run with TLS
uvicorn app.dashboard:app --host 0.0.0.0 --port 443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

### Security Checklist for Production

- [ ] HTTPS enabled via reverse proxy or direct TLS
- [ ] `DASH_TOKEN` environment variable set to a strong random value
- [ ] Firewall configured to allow only ports 80/443
- [ ] Dashboard not exposed to public internet unless necessary
- [ ] Regular certificate renewal (automatic with Caddy/Certbot)

---

## 7. Empirical Tool Comparison Methodology

AuroraEdge includes a feature-based comparison matrix (`generate_comparison_report()` in `dns_fix.py`). For academic rigor, an empirical comparison should follow this methodology:

### Comparison Protocol

1. **Domain Selection**
   - Select 20-50 domains across categories (universities, government, enterprise)
   - Ensure variety in security posture (some well-configured, some with issues)
   - Document selection criteria and sources

2. **Tool Configuration**
   - Configure AuroraEdge, OnDMARC, and EasyDMARC with identical domain lists
   - Use free tiers or trial accounts where applicable
   - Document versions and configuration settings

3. **Metrics to Collect**

   | Metric | Description |
   |--------|-------------|
   | Detection Rate | % of domains where tool identifies issues |
   | False Positive Rate | Issues flagged that aren't real problems |
   | False Negative Rate | Real issues missed by the tool |
   | Time to Insight | Seconds from scan start to results display |
   | Coverage | Which checks are supported (SPF, DKIM, DMARC, MTA-STS, TLS-RPT) |
   | Remediation Quality | Accuracy and actionability of fix recommendations |

4. **Test Procedure**
   ```
   For each tool:
       For each domain in dataset:
           1. Record start timestamp
           2. Run scan
           3. Record end timestamp
           4. Capture all findings
           5. Compare against ground truth (manual DNS verification)
   ```

5. **Ground Truth Establishment**
   - Manually verify DNS records for each domain using `dig`
   - Document expected findings before running automated tools
   - Use this as reference for accuracy calculation

6. **Analysis**
   - Calculate precision: TP / (TP + FP)
   - Calculate recall: TP / (TP + FN)
   - Compare average scan times
   - Tabulate feature coverage differences

### Running the Built-in Comparison

```python
from app.dns_fix import generate_comparison_report

# Generate feature comparison matrix
report = generate_comparison_report()
print(report)
```

---

## 8. DKIM Limitations and Scope

### What AuroraEdge Does

AuroraEdge performs **DKIM selector discovery** - it probes common selector names to determine if DKIM DNS records exist:

```python
# Selectors checked (from scanner.py)
DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "mail",
    "dkim", "k1", "s1", "s2", "smtp", "email"
]
```

### What AuroraEdge Does NOT Do

DKIM implementation involves more than DNS records:

1. **Key Generation** - Creating RSA/Ed25519 keypairs
2. **MTA Configuration** - Configuring mail server to sign outbound mail
3. **Key Rotation** - Periodic key updates for security
4. **Multiple Selectors** - Managing different selectors for different mail streams

### Why Auto-Fix is Limited for DKIM

| Component | Auto-Fixable? | Reason |
|-----------|---------------|--------|
| DKIM DNS TXT Record | ⚠️ Partial | Requires existing public key |
| Private Key Generation | ❌ No | Security-sensitive, must be done on mail server |
| MTA Signing Config | ❌ No | Requires mail server access |
| Key Rotation | ❌ No | Requires coordinated DNS + MTA changes |

### Recommended Approach

For domains missing DKIM, AuroraEdge provides:
1. **Detection** - Identifies missing or invalid DKIM records
2. **Advice** - Recommends DKIM implementation
3. **Template** - Shows example DKIM record format

Actual DKIM deployment should be done through:
- Mail service provider (Google Workspace, Microsoft 365)
- Manual OpenDKIM configuration (see Section 3)
- Hosted email security platforms

### Academic Framing

In academic writing, DKIM auto-fix limitations should be acknowledged:

> "AuroraEdge provides DKIM selector discovery and detection of missing/invalid records. Full DKIM automation would require mail server integration, which is outside the scope of a DNS-focused security scanner. This limitation is consistent with the tool's design as a posture assessment platform rather than a mail server configuration tool."

---

## References

- [Cloudflare API Documentation](https://api.cloudflare.com/)
- [OpenDMARC Documentation](http://www.trusteddomain.org/opendmarc/)
- [Postfix Documentation](http://www.postfix.org/documentation.html)
- [RFC 7489 - DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [RFC 8461 - MTA-STS](https://datatracker.ietf.org/doc/html/rfc8461)
- [RFC 8460 - TLS-RPT](https://datatracker.ietf.org/doc/html/rfc8460)

---

*AuroraEdge FYP 2025/26 - Automated Email Authentication & Cyber Defence System*
