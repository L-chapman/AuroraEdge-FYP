# Stage 10 - Remediation Recommendations Engine

## Overview
Week 14 deliverable: Implemented an intelligent remediation engine that generates actionable recommendations for fixing email security misconfigurations.

## Features

Located in `src/app/rules.py`:

### Remediation Generation
The `generate_remediation()` function analyses scan results and produces specific fix recommendations:

```python
from app.rules import generate_remediation

scan = {
    "spf_present": False,
    "dmarc_present": True,
    "dmarc_policy": "none",
    "dkim_present": False,
    # ...
}

recommendations = generate_remediation(scan)
# Returns list of remediation objects
```

### Remediation Object Format
```python
{
    "issue": "No SPF record found",
    "severity": "CRITICAL",
    "recommendation": "Add SPF TXT record to authorize mail servers",
    "example": 'v=spf1 include:_spf.google.com ~all',
    "rfc": "RFC 7208",
    "priority": 1
}
```

### Covered Issues
1. **Missing SPF** - Provides example record with include mechanism
2. **Excessive SPF Lookups** - Explains flattening and recommends optimisation
3. **Missing DMARC** - Generates a starter policy with monitoring
4. **DMARC p=none** - Recommends quarantine/reject upgrade path
5. **Missing DKIM** - Explains key generation and selector setup
6. **Missing MTA-STS** - Provides policy file and DNS record examples
7. **Missing TLS-RPT** - Recommends reporting endpoint setup
8. **Weak DKIM Keys** - Recommends 2048-bit RSA or Ed25519

## CLI Integration

```powershell
python -m app.cli --domain example.com --remediation
```

## Tests
- `test_remediation.py::test_remediation_for_missing_spf`
- `test_remediation.py::test_remediation_for_dmarc_none`
- `test_remediation.py::test_remediation_for_missing_mta_sts`
- `test_remediation.py::test_no_remediation_for_perfect_config`
