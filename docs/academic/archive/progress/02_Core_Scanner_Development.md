# Core Scanner Development Progress Record

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../../../../README.md) and [`testing guide`](../../../TESTING.md). Return to the [archive guide](../../README.md).

## Stage 1 - DNS Scanner Skeleton (30 Sep - 06 Oct 2025)
**Stage 1**: DNS Scanner Skeleton

### Implemented
- Basic DNS lookup functions using dnspython
- SPF record discovery and parsing
- MX record enumeration
- DMARC policy extraction
- CSV and Markdown report generation

### Code Highlights
```python
def scan_domain(domain: str) -> dict:
    """Scan a domain for email security records."""
    result = {
        "spf_present": False,
        "mx_present": False,
        "dmarc_present": False,
        ...
    }
    # Query TXT records for SPF
    # Query MX records
    # Query _dmarc.domain TXT records
    return result
```

### Testing
- Manual tests with known domains (google.com, microsoft.com)
- Verified output CSV format
- Confirmed Markdown table rendering

### Challenges
- DNS timeout handling for slow resolvers
- Some domains return multiple TXT records

### Outcome
Basic scanner functional. Outputs generated in `reports/`.

---

## Stage 2 - SPF Recursion & DMARC Strength (07-13 Oct 2025)
**Stage 2**: SPF Recursion & DMARC Strength

### Implemented
- SPF `include:` and `redirect=` recursion
- SPF lookup counting (RFC 7208 requires ≤10 lookups)
- Recursive mechanism depth limiting (MAX_SPF_RECURSION=10)
- DMARC policy strength classification
- DMARC tag parsing (p, sp, pct, rua, ruf, adkim, aspf)

### SPF Recursion Logic
```python
def _count_spf_mechanisms(record: str, domain: str, 
                          visited: set, depth: int) -> int:
    """Recursively count SPF lookup mechanisms."""
    if depth > MAX_SPF_RECURSION or domain in visited:
        return 0
    visited.add(domain)
    
    count = 0
    for part in record.split():
        if part.startswith("include:"):
            target = part.split(":", 1)[1]
            count += 1  # The include itself
            count += _count_spf_mechanisms(fetch_spf(target), target, visited, depth+1)
        elif part.startswith("redirect="):
            target = part.split("=", 1)[1]
            count += _count_spf_mechanisms(fetch_spf(target), target, visited, depth+1)
    return count
```

### DMARC Strength
| Policy | Classification |
|--------|----------------|
| reject | Strong (recommended) |
| quarantine | Medium |
| none | Weak (monitoring only) |

### Testing
- Tested SPF recursion with deeply nested includes
- Verified lookup counting accuracy
- Confirmed DMARC policy extraction

---

## Stage 3 - DKIM Discovery (14-20 Oct 2025)
**Stage 3**: DKIM Discovery

### Implemented
- Common DKIM selector probing
- DKIM key type detection (RSA, Ed25519)
- Test key flag detection (t=y)
- Selector list: google, selector1, selector2, default, s1, s2, k1, k2, mail, smtp, mandrill, sendgrid, zoho

### DKIM Selector Logic
```python
SELECTOR_CANDIDATES = [
    "default", "google", "selector1", "selector2",
    "s1", "s2", "k1", "k2", "mail", "smtp",
    "mandrill", "sendgrid", "zoho"
]

def discover_dkim(domain: str) -> dict:
    """Probe common DKIM selectors."""
    found_selectors = []
    for selector in SELECTOR_CANDIDATES:
        record = query_txt(f"{selector}._domainkey.{domain}")
        if record and "v=DKIM1" in record:
            found_selectors.append(selector)
    return {"dkim_present": len(found_selectors) > 0, ...}
```

### Limitations Noted
- Cannot discover custom/unknown selectors
- Some providers use unique selector names (e.g., `20230601._domainkey`)
- Documented as known limitation

### Testing
- Verified detection for google.com (google selector)
- Verified detection for microsoft.com (selector1, selector2)
- Confirmed test key flag parsing

---

## Stage 4 - Rules Engine (21-27 Oct 2025)
**Stage 4**: Rules Engine

### Implemented
- Severity classification system: OK, INFO, WARN, HIGH, CRITICAL
- 10 core rules for email security evaluation
- Violation tracking with human-readable advice
- Rich console output with colour-coded results

### Rule Definitions
| Rule ID | Check | Severity |
|---------|-------|----------|
| R1_MX_MISSING | No MX records | HIGH |
| R2_SPF_MISSING | No SPF record | HIGH |
| R3_SPF_LOOKUPS | >10 DNS lookups | WARN |
| R3A_SPF_MANY_LOOKUPS | >7 DNS lookups | INFO |
| R3B_SPF_PLUSALL | SPF +all (allows any sender) | CRITICAL |
| R3C_SPF_SOFTFAIL | SPF ~all (softfail) | WARN |
| R4_DMARC_MISSING | No DMARC record | HIGH |
| R5_DMARC_NONE | DMARC p=none | WARN |
| R6_DKIM_NOT_FOUND | No DKIM selectors found | WARN |
| R7_DKIM_TEST | DKIM test key (t=y) | INFO |
| R8_MTA_STS_MISSING | No MTA-STS policy | WARN |
| R9_MTA_STS_TESTING | MTA-STS mode=testing | INFO |
| R10_TLS_RPT_MISSING | No TLS-RPT record | WARN |

### Rich Console Output
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                        AuroraEdge Email Security Scan                          │
├──────────────┬───────┬───────┬──────────┬─────┬─────────────┬──────┬───────────┤
│ Domain       │ Grade │ Score │ Severity │ SPF │ DMARC       │ DKIM │ Violations│
├──────────────┼───────┼───────┼──────────┼─────┼─────────────┼──────┼───────────┤
│ google.com   │ A     │ 88    │ WARN     │ ✓   │ ✓ reject    │ ✓    │ 2         │
│ example.org  │ D     │ 45    │ HIGH     │ ✓   │ ✗           │ ✗    │ 4         │
└──────────────┴───────┴───────┴──────────┴─────┴─────────────┴──────┴───────────┘
```

### Outcome
Rules engine provides clear, actionable severity classifications. CLI output is visually informative.
