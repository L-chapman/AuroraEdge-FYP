# Testing & Dashboard Development Progress Record

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../../README.md) and [`testing guide`](../TESTING.md).

## Stage 5 - Transport Security (28 Oct - 03 Nov 2025)
**Stage 5**: Transport Security (MTA-STS & TLS-RPT)

### Implemented
- MTA-STS policy discovery (RFC 8461)
- MTA-STS mode parsing: none, testing, enforce
- TLS-RPT record discovery (RFC 8460)
- STARTTLS check infrastructure (optional feature)

### MTA-STS Implementation
```python
def check_mta_sts(domain: str) -> dict:
    """Check MTA-STS policy via HTTPS."""
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        response = requests.get(policy_url, timeout=HTTP_TIMEOUT)
        if response.status_code == 200:
            content = response.text
            mode = "enforce"  # default
            if "mode: testing" in content:
                mode = "testing"
            elif "mode: none" in content:
                mode = "none"
            return {"mta_sts_present": True, "mta_sts_mode": mode}
    except:
        pass
    return {"mta_sts_present": False, "mta_sts_mode": ""}
```

### TLS-RPT Discovery
- Query `_smtp._tls.{domain}` for TXT record
- Parse `v=TLSRPTv1` records
- Extract reporting address (rua=mailto:...)

### RFC Compliance Notes
- MTA-STS requires valid HTTPS certificate on mta-sts.{domain}
- Policy file must be at exact path /.well-known/mta-sts.txt
- TLS-RPT is optional but recommended for monitoring

### Testing
- Verified MTA-STS detection for google.com (mode: enforce)
- Verified TLS-RPT for major providers
- Confirmed fallback handling for missing policies

---

## Stage 6 - Testing Framework (04-10 Nov 2025)
**Stage 6**: Testing Framework

### Implemented
- pytest test suite structure
- DNS/HTTP mocking for offline tests
- Scanner edge case tests
- Rules engine validation tests
- Import fallback tests

### Test Categories
| Category | Tests | Purpose |
|----------|-------|---------|
| Scanner | 2 | SPF missing, DMARC parsing |
| Rules | 3 | Severity classification |
| SPF Recursion | 1 | Lookup counting |
| CLI | 2 | File handling, output |
| Dashboard | 2 | Auth, rendering |
| Database | 2 | Persistence, multiple scans |
| Remediation | 4 | Fix recommendations |
| Fallbacks | 1 | Optional imports |

### Mocking Strategy
```python
@pytest.fixture
def mock_dns(monkeypatch):
    """Mock DNS resolver for offline tests."""
    def fake_resolve(domain, rdtype):
        if rdtype == "TXT" and "_dmarc" in domain:
            return [MockAnswer("v=DMARC1; p=reject")]
        return []
    monkeypatch.setattr("dns.resolver.resolve", fake_resolve)
```

### Test Results
```
============================= test session starts =============================
collected 13 items
13 passed in 1.42s
```

### Benefits
- Tests run without network access
- Deterministic results
- Fast execution (<2 seconds)
- CI/CD integration ready

---

## Stage 7 - Dashboard v1 (11-17 Nov 2025)
**Stage 7**: Dashboard v1 (FastAPI)

### Implemented
- FastAPI application structure
- Token-based authentication (DASH_TOKEN)
- HTML dashboard with severity counts
- REST API endpoints
- Report download functionality

### Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | HTML dashboard |
| `/health` | GET | Health check |
| `/api/runs` | GET | List all scan files |
| `/api/latest` | GET | Latest scan results |
| `/api/summary` | GET | Severity/grade statistics |
| `/download/latest` | GET | Download CSV/MD report |

### Authentication
```python
def require_token(req: Request):
    """Token-based authentication dependency."""
    want = os.environ.get("DASH_TOKEN", "")
    if not want:
        return  # Dev mode - open access
    
    # Check query param or header
    if req.query_params.get("token") == want:
        return
    if req.headers.get("Authorization", "").startswith("Bearer "):
        if req.headers["Authorization"].split(" ")[1] == want:
            return
    
    raise HTTPException(401, "Unauthorised")
```

### Dashboard Features
- Severity distribution (OK/WARN/HIGH counts)
- Average score display
- Download links for CSV and Markdown
- Latest report file name

### Testing
- Dashboard auth test (401 without token)
- Home page rendering test
- API endpoint validation

---

## Stage 8 - Scoring System (18-24 Nov 2025)
**Stage 8**: Scoring System

### Implemented
- 0-100 scoring algorithm
- Letter grades (A+ to F)
- Weighted rule penalties
- Score display in CLI and dashboard

### Scoring Algorithm
```python
def calculate_score(violations: list) -> int:
    """Calculate 0-100 security score."""
    score = 100
    
    # Heavy penalties for critical issues
    heavy_penalties = {
        "R1_MX_MISSING": 30,
        "R2_SPF_MISSING": 25,
        "R4_DMARC_MISSING": 25,
        "R3B_SPF_PLUSALL": 40,
    }
    
    # Medium penalties
    medium_penalties = {
        "R5_DMARC_NONE": 10,
        "R6_DKIM_NOT_FOUND": 10,
        "R8_MTA_STS_MISSING": 5,
        "R10_TLS_RPT_MISSING": 5,
    }
    
    # Light penalties
    light_penalties = {
        "R3_SPF_LOOKUPS": 5,
        "R3C_SPF_SOFTFAIL": 5,
        "R7_DKIM_TEST": 3,
        "R9_MTA_STS_TESTING": 2,
    }
    
    for v in violations:
        score -= heavy_penalties.get(v, 0)
        score -= medium_penalties.get(v, 0)
        score -= light_penalties.get(v, 0)
    
    return max(0, score)  # Floor at 0
```

### Grade Mapping
| Score Range | Grade |
|-------------|-------|
| 95-100 | A+ |
| 85-94 | A |
| 75-84 | B |
| 65-74 | C |
| 50-64 | D |
| 0-49 | F |

### Rationale
- Missing MX/SPF/DMARC are critical (highest penalties)
- SPF +all is dangerous (allows any sender)
- DKIM and transport security are important but less critical
- Grades provide quick assessment at a glance

### Testing
- Verified score calculation with various violation combinations
- Confirmed grade mapping accuracy
- Updated CLI output to show scores
