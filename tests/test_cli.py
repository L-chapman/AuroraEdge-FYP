import sys
from pathlib import Path
import os

import app.cli as cli


def test_cli_writes_outputs(tmp_path, monkeypatch):
    # Prepare args: --domain example.com --outdir <tmp_path>
    monkeypatch.setattr(sys, "argv", ["cli.py", "--domain", "example.com", "--outdir", str(tmp_path)])

    # Monkeypatch scan_domain and evaluate to predictable values
    def fake_scan(d):
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
