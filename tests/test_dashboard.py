from fastapi.testclient import TestClient
import os

import app.dashboard as dashboard


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
