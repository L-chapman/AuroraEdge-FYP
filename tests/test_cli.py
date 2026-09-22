import sys
from pathlib import Path
import os
import csv
import logging
from unittest.mock import Mock

import pytest

import app.cli as cli


def test_cli_writes_outputs(tmp_path, monkeypatch):
    # Prepare args: --domain example.com --outdir <tmp_path>
    monkeypatch.setattr(sys, "argv", ["cli.py", "--domain", "example.com", "--outdir", str(tmp_path)])

    # Monkeypatch scan_domain and evaluate to predictable values
    def fake_scan(d, check_starttls=False):
        return {
            "spf_present": True,
            "spf_lookups": 1,
            "mx_present": True,
            "mx_count": 1,
            "dmarc_present": False,
            "dmarc_policy": "",
            "dkim_present": False,
            "mta_sts_present": False,
            "tls_rpt_present": False,
            "notes": "",
        }

    def fake_eval(res):
        return {"severity": "OK", "violations": "", "advice": ""}

    monkeypatch.setattr(cli, "scan_domain", fake_scan)
    monkeypatch.setattr(cli, "evaluate", fake_eval)

    # Run main which should write CSV and MD files
    cli.main()

    # Check outputs exist
    files = list(tmp_path.iterdir())
    assert any(p.suffix == ".csv" for p in files)
    assert any(p.suffix == ".md" for p in files)
    with next(p for p in files if p.suffix == ".csv").open(encoding="utf-8", newline="") as report:
        row = next(csv.DictReader(report))
    assert row["spf_present"] == "True"
    assert row["mx_count"] == "1"


def test_csv_keeps_zero_false_and_empty_values_distinct(tmp_path):
    path = tmp_path / "results.csv"
    cli.write_csv([("example.com", {"spf_present": False, "spf_lookups": 0,
                                  "dmarc_present": True, "dmarc_pct": 0,
                                  "notes": None},
                    {"score": 0, "violation_count": 0})], path)
    with path.open(encoding="utf-8", newline="") as report:
        row = next(csv.DictReader(report))
    assert row["score"] == "0"
    assert row["violation_count"] == "0"
    assert row["spf_lookups"] == "0"
    assert row["dmarc_pct"] == "0"
    assert row["spf_present"] == "False"
    assert row["dmarc_present"] == "True"
    assert row["notes"] == ""
    assert row["advice"] == ""


def test_markdown_external_values_cannot_create_markup_or_extra_rows(tmp_path):
    path = tmp_path / "results.md"
    cli.write_markdown([("example.com",
        {"dmarc_present": True, "dmarc_policy": '<img src=x>|new\nrow',
         "mta_sts_present": True, "mta_sts_mode": "[click](https://example.invalid)"},
        {"score": 0, "grade": "F", "severity": "HIGH", "violations": "<script>bad</script>",
         "violation_count": 1})], path, "2026-09-22")
    report = path.read_text(encoding="utf-8")
    assert "<img" not in report
    assert "<script>" not in report
    assert "&lt;img src=x&gt;\\|new<br>row" in report
    assert "\\[click\\]\\(https://example.invalid\\)" in report
    assert "| example.com | F | 0 | HIGH |" in report


@pytest.mark.parametrize("rich_output", [False, True])
def test_database_save_failure_keeps_one_successful_scan_row(monkeypatch, caplog, rich_output):
    if rich_output and not cli.HAS_RICH:
        pytest.skip("Rich is not installed")
    monkeypatch.setattr(cli, "HAS_RICH", rich_output)
    database = Mock()
    database.start_scan.return_value = "test-scan"
    database.save_result.side_effect = [RuntimeError("disk full"), None]
    monkeypatch.setattr(cli, "get_database", lambda: database)
    scan = Mock(side_effect=[{"notes": "Existing scan note", "spf_present": True},
                             {"notes": "", "spf_present": False}])
    monkeypatch.setattr(cli, "scan_domain", scan)
    evaluation = {"score": 91, "grade": "A", "severity": "WARN"}
    monkeypatch.setattr(cli, "evaluate", lambda _: evaluation)

    with caplog.at_level(logging.WARNING, logger="northflux.cli"):
        rows = cli.scan_domains(["example.com", "example.net"], check_starttls=True)

    assert [row[0] for row in rows] == ["example.com", "example.net"]
    assert rows[0][1]["spf_present"] is True
    assert "error" not in rows[0][1]
    assert rows[0][2] == evaluation
    assert "Existing scan note" in rows[0][1]["notes"]
    assert "not saved to the database" in rows[0][1]["notes"]
    assert "disk full" in caplog.text
    assert "Error scanning" not in caplog.text
    assert rows[1][1]["notes"] == ""
    assert database.save_result.call_count == 2
    database.complete_scan.assert_called_once_with("test-scan", 2)
    assert scan.call_count == 2
    scan.assert_any_call("example.com", check_starttls=True)


@pytest.mark.parametrize("rich_output", [False, True])
def test_database_completion_failure_does_not_discard_scan_results(monkeypatch, caplog, rich_output):
    if rich_output and not cli.HAS_RICH:
        pytest.skip("Rich is not installed")
    monkeypatch.setattr(cli, "HAS_RICH", rich_output)
    database = Mock()
    database.start_scan.return_value = "test-scan"
    database.complete_scan.side_effect = RuntimeError("database unavailable")
    monkeypatch.setattr(cli, "get_database", lambda: database)
    monkeypatch.setattr(cli, "scan_domain", lambda *args, **kwargs: {"notes": ""})
    monkeypatch.setattr(cli, "evaluate", lambda _: {"score": 91, "grade": "A"})

    with caplog.at_level(logging.WARNING, logger="northflux.cli"):
        rows = cli.scan_domains(["example.com"])

    assert len(rows) == 1
    assert rows[0][2]["score"] == 91
    assert "Could not mark scan complete in the database" in caplog.text
    assert "database unavailable" in caplog.text


@pytest.mark.parametrize("rich_output", [False, True])
def test_scan_failure_returns_one_incomplete_row_without_saving(monkeypatch, rich_output):
    if rich_output and not cli.HAS_RICH:
        pytest.skip("Rich is not installed")
    monkeypatch.setattr(cli, "HAS_RICH", rich_output)
    database = Mock()
    monkeypatch.setattr(cli, "get_database", lambda: database)
    monkeypatch.setattr(cli, "scan_domain", Mock(side_effect=RuntimeError("scan failed")))

    rows = cli.scan_domains(["example.com"])

    assert len(rows) == 1
    assert rows[0][1] == {"error": "scan failed", "scan_incomplete": True}
    assert rows[0][2]["severity"] == "CRITICAL"
    database.save_result.assert_not_called()
