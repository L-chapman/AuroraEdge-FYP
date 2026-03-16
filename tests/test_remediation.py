"""
Tests for the remediation generation in the rules module.
"""
import pytest
from app.rules import generate_remediation


def test_remediation_for_missing_spf():
    """Test remediation suggestions for missing SPF."""
    result = {
        "domain": "test.com",
        "spf_present": False,
        "dmarc_present": True,
        "dmarc_policy": "reject",
        "mta_sts_present": True,
        "tls_rpt_present": True,
        "dkim_present": True,
    }
    
    remediations = generate_remediation(result)
    
    assert len(remediations) >= 1
    spf_fix = next((r for r in remediations if r["rule"] == "R2_SPF_MISSING"), None)
    assert spf_fix is not None
    assert "SPF" in spf_fix["description"]
    assert "v=spf1" in spf_fix["example"]
    assert spf_fix["priority"] == "HIGH"


def test_remediation_for_dmarc_none():
    """Test remediation suggestions for weak DMARC policy."""
    result = {
        "domain": "test.com",
        "spf_present": True,
        "dmarc_present": True,
        "dmarc_policy": "none",
        "mta_sts_present": True,
        "tls_rpt_present": True,
        "dkim_present": True,
    }
    
    remediations = generate_remediation(result)
    
    dmarc_fix = next((r for r in remediations if r["rule"] == "R5_DMARC_NONE"), None)
    assert dmarc_fix is not None
    assert "p=reject" in dmarc_fix["example"]
    assert dmarc_fix["priority"] == "WARN"


def test_remediation_for_missing_mta_sts():
    """Test remediation for missing MTA-STS."""
    result = {
        "domain": "example.org",
        "spf_present": True,
        "dmarc_present": True,
        "dmarc_policy": "reject",
        "dmarc_rua": "mailto:dmarc@example.org",
        "mta_sts_present": False,
        "tls_rpt_present": True,
        "dkim_present": True,
    }
    
    remediations = generate_remediation(result)
    
    sts_fix = next((r for r in remediations if r["rule"] == "R8_MTA_STS_MISSING"), None)
    assert sts_fix is not None
    assert "MTA-STS" in sts_fix["description"]
    assert "example.org" in sts_fix["example"]


def test_no_remediation_for_perfect_config():
    """Test that a perfect configuration generates no remediations."""
    result = {
        "domain": "perfect.com",
        "spf_present": True,
        "spf_all": "-all",
        "spf_lookups": 5,
        "mx_present": True,
        "dmarc_present": True,
        "dmarc_policy": "reject",
        "dmarc_pct": 100,
        "dmarc_rua": "mailto:dmarc@perfect.com",
        "mta_sts_present": True,
        "mta_sts_mode": "enforce",
        "tls_rpt_present": True,
        "dkim_present": True,
        "bimi_present": True,
        "rbl_listings": 0,
        "starttls_worst": "A",
        "notes": "",
    }
    
    remediations = generate_remediation(result)
    
    # Perfect config should have no remediations
    assert len(remediations) == 0
