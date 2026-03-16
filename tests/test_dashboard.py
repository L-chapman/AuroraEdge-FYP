from fastapi.testclient import TestClient
import os
import json

import app.dashboard as dashboard
from app.database import AuroraDatabase


def test_dashboard_health_and_home(tmp_path, monkeypatch):
    # Clear DASH_TOKEN for testing (allow open access)
    monkeypatch.setenv("DASH_TOKEN", "")
    
    client = TestClient(dashboard.app)

    # health endpoint should return ok (now includes timestamp)
    r = client.get("/health")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert "timestamp" in j

    # Point REPORTS to an empty temp dir -> home should still render OK
    monkeypatch.setattr(dashboard, "REPORTS", tmp_path)
    r = client.get("/")
    assert r.status_code == 200
    # Dashboard renders a JS-driven shell; verify it contains the app title
    assert "AuroraEdge" in r.text

    # Create CSV/MD files and check endpoints
    csv = tmp_path / "stage7_results_sample.csv"
    md = tmp_path / "stage7_results_sample.md"
    csv.write_text("domain,severity\nexample.com,OK\nfoo.com,HIGH\n", encoding="utf-8")
    md.write_text("# sample md", encoding="utf-8")

    r = client.get("/api/latest")
    assert r.status_code == 200
    j = r.json()
    assert j["file"] == csv.name
    assert isinstance(j["rows"], list)

    r = client.get("/api/summary")
    assert r.status_code == 200
    js = r.json()
    assert js["file"] == csv.name
    assert js["counts"]["HIGH"] == 1
    assert js["counts"]["OK"] == 1
    assert "scores" in js and js["scores"]["avg"] >= 0

    r = client.get("/download/latest?kind=csv")
    assert r.status_code == 200
    assert "example.com" in r.text

    r = client.get("/download/latest?kind=md")
    assert r.status_code == 200
    assert "sample md" in r.text


def test_search_prefers_database_results(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "")

    db = AuroraDatabase(tmp_path / "test.db")
    scan_id = db.start_scan(notes="search test")
    db.save_result(
        scan_id,
        "example.net",
        {
            "spf_present": True,
            "mx_present": True,
            "dmarc_present": True,
            "dkim_present": False,
            "mta_sts_present": False,
            "tls_rpt_present": False,
        },
        {
            "severity": "HIGH",
            "score": 55,
            "grade": "D",
            "violations": "R6_DKIM_NOT_FOUND",
            "violation_count": 1,
            "advice": "Configure DKIM",
        },
    )
    db.complete_scan(scan_id, 1)

    monkeypatch.setattr(dashboard, "get_database", lambda: db)
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "REPORTS", tmp_path)

    client = TestClient(dashboard.app)
    r = client.get("/api/search?q=example.net")
    assert r.status_code == 200
    payload = r.json()
    assert payload["count"] == 1
    assert payload["results"][0]["domain"] == "example.net"


def test_settings_reject_invalid_monitor_interval(monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "")
    client = TestClient(dashboard.app)

    r = client.post(
        "/api/settings",
        content=json.dumps({"monitor_interval": "-1"}),
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert "monitor_interval must be one of" in r.text


def test_ip_address_rejected_as_domain(monkeypatch):
    """IP addresses should be rejected — we need real domain names for DNS checks."""
    monkeypatch.setenv("DASH_TOKEN", "")
    client = TestClient(dashboard.app)

    r = client.post("/api/rescan/127.0.0.1")
    assert r.status_code == 400

    r = client.post("/api/rescan/192.168.1.1")
    assert r.status_code == 400

    r = client.post("/api/rescan/10.0.0.1")
    assert r.status_code == 400


def test_unknown_rule_id_returns_404(monkeypatch):
    """Unknown rule IDs should return 404, not a generic fallback."""
    monkeypatch.setenv("DASH_TOKEN", "")
    client = TestClient(dashboard.app)

    r = client.get("/api/explanations/rule/FAKE_RULE")
    assert r.status_code == 404

    r = client.get("/api/explanations/rule/R1_MX_MISSING")
    assert r.status_code == 200
