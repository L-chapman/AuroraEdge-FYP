import sys
from pathlib import Path
import os
import csv

import app.cli as cli


def test_cli_reads_domains_file(tmp_path, monkeypatch):
    # Create a domains file with two entries
    doms = tmp_path / "domains.txt"
    doms.write_text("example.com\nexample.org\n", encoding="utf-8-sig")

    monkeypatch.setattr(sys, "argv", ["cli.py", "--domains", str(doms), "--outdir", str(tmp_path), "--no-db"])

    # Monkeypatch scan_domain and evaluate
    def fake_scan(d, check_starttls=False):
        return {"spf_present": True, "spf_lookups": 1, "mx_present": True, "mx_count": 1, "dmarc_present": False, "dkim_present": False, "mta_sts_present": False, "tls_rpt_present": False, "notes": ""}

    def fake_eval(res):
        return {"severity": "OK", "violations": "", "advice": ""}

    monkeypatch.setattr(cli, "scan_domain", fake_scan)
    monkeypatch.setattr(cli, "evaluate", fake_eval)

    cli.main()

    files = list(tmp_path.iterdir())
    assert any(p.suffix == ".csv" for p in files)
    assert any(p.suffix == ".md" for p in files)
    with next(p for p in files if p.suffix == ".csv").open(encoding="utf-8", newline="") as report:
        rows = list(csv.DictReader(report))
    assert [row["domain"] for row in rows] == ["example.com", "example.org"]
    assert all(row["spf_present"] == "True" for row in rows)
