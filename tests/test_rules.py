from app.rules import evaluate


def test_rules_mx_and_spf_missing_is_high():
    """Test that missing MX, SPF, and DMARC trigger HIGH severity.
    
    With the new scoring system:
    - R1_MX_MISSING: HIGH = 25
    - R2_SPF_MISSING: HIGH = 25  
    - R4_DMARC_MISSING: HIGH = 25
    Total penalty = 75, Score = 100 - 75 = 25
    """
    res = {
        "mx_present": False,
        "spf_present": False,
        "dmarc_present": False,
        "dkim_present": True,
        "mta_sts_present": True,
        "mta_sts_mode": "enforce",
        "tls_rpt_present": True,
    }
    out = evaluate(res)
    assert out["severity"] == "HIGH"
    assert "R1_MX_MISSING" in out["violations"]
    assert "R2_SPF_MISSING" in out["violations"]
    assert out["score"] == 25  # three HIGH hits -> 100 - 75 = 25


def test_rules_dmarc_none_warn():
    """Test that DMARC p=none triggers warnings.
    
    With new rules:
    - R5_DMARC_NONE: WARN = 10
    - R5D_DMARC_NO_RUA: WARN = 10 (no rua tag)
    - R12_NO_STRICT_POLICY: INFO = 2 (no strict SPF/DMARC)
    Total penalty = 22, Score = 100 - 22 = 78
    """
    res = {
        "mx_present": True,
        "spf_present": True,
        "dmarc_present": True,
        "dmarc_policy": "none",
        "dkim_present": True,
        "mta_sts_present": True,
        "mta_sts_mode": "enforce",
        "tls_rpt_present": True,
    }
    out = evaluate(res)
    assert out["severity"] in ("WARN", "HIGH")
    assert "R5_DMARC_NONE" in out["violations"]
    assert out["score"] == 78  # multiple WARN + INFO hits


def test_rules_spf_lookups_warn():
    """Test that SPF > 10 lookups triggers warning.
    
    With new rules:
    - R3_SPF_LOOKUPS: WARN = 10
    - R5D_DMARC_NO_RUA: WARN = 10 (no rua tag in test data)
    Total penalty = 20, Score = 100 - 20 = 80
    """
    res = {
        "mx_present": True,
        "spf_present": True,
        "spf_lookups": 11,
        "dmarc_present": True,
        "dmarc_policy": "reject",
        "dkim_present": True,
        "mta_sts_present": True,
        "mta_sts_mode": "enforce",
        "tls_rpt_present": True,
        "bimi_present": True,
        "rbl_listings": 0,
    }
    out = evaluate(res)
    assert out["severity"] in ("WARN", "HIGH")
    assert "R3_SPF_LOOKUPS" in out["violations"]
    assert out["score"] == 80  # two WARN hits
