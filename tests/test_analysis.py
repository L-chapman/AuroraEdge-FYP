"""
Tests for the analysis module.
"""
import pytest


def test_calculate_statistics():
    """Test statistics calculation from scan results."""
    from app.analysis import calculate_statistics
    
    rows = [
        {"score": "100", "grade": "A+", "severity": "OK", "violations": "",
         "spf_present": "True", "dmarc_present": "True", "dkim_present": "True",
         "mta_sts_present": "True", "tls_rpt_present": "True", "dmarc_policy": "reject"},
        {"score": "80", "grade": "B", "severity": "WARN", "violations": "R8,R10",
         "spf_present": "True", "dmarc_present": "True", "dkim_present": "True",
         "mta_sts_present": "False", "tls_rpt_present": "False", "dmarc_policy": "reject"},
        {"score": "50", "grade": "D", "severity": "HIGH", "violations": "R2,R4,R6",
         "spf_present": "False", "dmarc_present": "False", "dkim_present": "False",
         "mta_sts_present": "False", "tls_rpt_present": "False", "dmarc_policy": ""},
    ]
    
    stats = calculate_statistics(rows)
    
    assert stats["total_domains"] == 3
    assert stats["score_avg"] == pytest.approx(76.67, rel=0.01)
    assert stats["score_min"] == 50
    assert stats["score_max"] == 100
    
    assert stats["grade_distribution"]["A+"] == 1
    assert stats["grade_distribution"]["B"] == 1
    assert stats["grade_distribution"]["D"] == 1
    
    assert stats["severity_distribution"]["OK"] == 1
    assert stats["severity_distribution"]["WARN"] == 1
    assert stats["severity_distribution"]["HIGH"] == 1
    
    assert stats["check_presence"]["spf"] == 2
    assert stats["check_presence"]["dmarc"] == 2
    assert stats["check_presence"]["dkim"] == 2
    assert stats["check_presence"]["mta_sts"] == 1
    assert stats["check_presence"]["tls_rpt"] == 1
    
    assert "R8" in stats["violation_frequency"]
    assert "R2" in stats["violation_frequency"]


def test_empty_statistics():
    """Test statistics with empty data."""
    from app.analysis import calculate_statistics
    
    stats = calculate_statistics([])
    assert stats == {}
