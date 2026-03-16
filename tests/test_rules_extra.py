from app.rules import evaluate


def test_spf_lookups_boundary():
    """Exactly 10 lookups should not trigger the warn rule.
    
    Score should be 90 due to R5D_DMARC_NO_RUA (no rua tag = WARN = 10)
    """
    res = {
        "mx_present": True,
        "spf_present": True,
        "spf_lookups": 10,
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
    assert "R3_SPF_LOOKUPS" not in out["violations"]
    assert out["score"] == 90  # R5D_DMARC_NO_RUA penalty

    # 11 lookups should trigger warn
    res["spf_lookups"] = 11
    out = evaluate(res)
    assert "R3_SPF_LOOKUPS" in out["violations"]
    assert out["score"] == 80  # R3_SPF_LOOKUPS + R5D_DMARC_NO_RUA = 2 WARN = 20 penalty


def test_dmarc_none_is_warn_when_present():
    """Test that DMARC p=none triggers warnings.
    
    Score = 78 due to:
    - R5_DMARC_NONE: WARN = 10
    - R5D_DMARC_NO_RUA: WARN = 10
    - R12_NO_STRICT_POLICY: INFO = 2
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
    assert "R5_DMARC_NONE" in out["violations"]
    assert out["score"] == 78  # WARN + WARN + INFO penalties


def test_dmarc_sp_weak_triggers_when_weaker_than_parent():
    """R15: sp=none with p=reject should fire a WARN."""
    res = {
        "mx_present": True,
        "spf_present": True,
        "spf_all": "-all",
        "dmarc_present": True,
        "dmarc_policy": "reject",
        "dmarc_sp": "none",
        "dkim_present": True,
        "mta_sts_present": True,
        "mta_sts_mode": "enforce",
        "tls_rpt_present": True,
        "bimi_present": True,
        "rbl_listings": 0,
    }
    out = evaluate(res)
    assert "R15_DMARC_SP_WEAK" in out["violations"]


def test_dmarc_sp_ok_when_matching_parent():
    """sp=reject with p=reject should NOT fire."""
    res = {
        "mx_present": True,
        "spf_present": True,
        "spf_all": "-all",
        "dmarc_present": True,
        "dmarc_policy": "reject",
        "dmarc_sp": "reject",
        "dkim_present": True,
        "mta_sts_present": True,
        "mta_sts_mode": "enforce",
        "tls_rpt_present": True,
        "bimi_present": True,
        "rbl_listings": 0,
    }
    out = evaluate(res)
    assert "R15_DMARC_SP_WEAK" not in out["violations"]
