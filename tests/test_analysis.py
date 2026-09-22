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


def test_statistics_accept_live_booleans_and_skip_non_finite_scores():
    from app.analysis import calculate_statistics

    rows = [
        {"score": 0, "spf_present": True, "dmarc_present": True, "dmarc_policy": "reject"},
        {"score": "100", "spf_present": " true ", "dmarc_present": "1", "dmarc_policy": None},
        {"score": "NaN", "spf_present": False, "dmarc_present": "False"},
        {"score": "inf"},
        {},
    ]
    stats = calculate_statistics(rows)
    assert stats["score_avg"] == 50
    assert stats["score_min"] == 0
    assert stats["score_max"] == 100
    assert stats["score_median"] == 50
    assert stats["check_presence"]["spf"] == 2
    assert stats["check_presence"]["dmarc"] == 2
    assert stats["dmarc_policies"] == {"reject": 1, "unknown": 1}


def test_latest_report_uses_timestamp_not_brand_prefix_or_folder_priority(tmp_path, monkeypatch):
    import app.analysis as analysis

    indexed = tmp_path / "indexed"
    indexed.mkdir()
    (indexed / "stage9_results_20250101_120000.csv").write_text("domain,score\nold.example,0\n", encoding="utf-8")
    (tmp_path / "northflux_results_20260922_120000.csv").write_text("domain,score\nnew.example,100\n", encoding="utf-8")
    monkeypatch.setattr(analysis, "REPORTS", indexed)
    monkeypatch.setattr(analysis, "REPORTS_ROOT", tmp_path)
    assert analysis.load_latest_csv()[0]["domain"] == "new.example"


def test_default_analysis_report_stays_in_runtime_storage(tmp_path, monkeypatch):
    import app.analysis as analysis

    source = tmp_path / "source"
    reports = tmp_path / "private-reports"
    monkeypatch.setattr(analysis, "ROOT", source)
    monkeypatch.setattr(analysis, "REPORTS_ROOT", reports)
    path = analysis.generate_summary_report([
        {"score": 0, "dmarc_present": True, "dmarc_policy": "<script>|bad\nrow",
         "violations": "[link](https://example.invalid)"}
    ])
    assert path == reports / "northflux_analysis.md"
    report = path.read_text(encoding="utf-8")
    assert "<script>" not in report
    assert "&lt;script&gt;\\|bad<br>row" in report
    assert "\\[link\\]" in report
    assert not source.exists()


def test_histogram_grade_boundaries_and_custom_output_directory(tmp_path, monkeypatch):
    import app.analysis as analysis

    if not analysis.HAS_MATPLOTLIB:
        pytest.skip("The optional chart library is not installed")
    captured = {}
    original_subplots = analysis.plt.subplots

    def subplots(*args, **kwargs):
        figure, axis = original_subplots(*args, **kwargs)
        captured["axis"] = axis
        return figure, axis

    monkeypatch.setattr(analysis.plt, "subplots", subplots)
    unused_default = tmp_path / "default-figures"
    monkeypatch.setattr(analysis, "FIGURES", unused_default)
    target = tmp_path / "chosen-output" / "histogram.png"
    analysis.generate_score_histogram([{"score": value} for value in [0, 40, 60, 75, 85, 95, 100]], target)
    axis = captured["axis"]
    assert [patch.get_x() for patch in axis.patches] == [0, 40, 60, 75, 85, 95]
    assert [text.get_text() for text in axis.texts] == ["F", "D", "C", "B", "A", "A+"]
    assert target.is_file()
    assert not unused_default.exists()
