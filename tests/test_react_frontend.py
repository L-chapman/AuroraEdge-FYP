"""Production SPA serving and React-specific safety regression tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import dashboard


def _spa_build(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text(
        '<!doctype html><html><body><div id="root">react-shell</div></body></html>',
        encoding="utf-8",
    )
    (assets / "app.js").write_text("console.log('northflux')", encoding="utf-8")
    return dist


def test_production_spa_serves_entry_deep_links_and_assets(monkeypatch, tmp_path):
    monkeypatch.setenv("NORTHFLUX_SERVE_REACT", "true")
    monkeypatch.setattr(dashboard, "FRONTEND_DIST", _spa_build(tmp_path))
    client = TestClient(dashboard.app)

    login = client.get("/login")
    assert login.status_code == 200
    assert "react-shell" in login.text
    assert "'unsafe-inline'" not in login.headers["content-security-policy"]

    deep_link = client.get("/outside-the-known-routes")
    assert deep_link.status_code == 200
    assert "react-shell" in deep_link.text

    asset = client.get("/assets/app.js")
    assert asset.status_code == 200
    assert "immutable" in asset.headers["cache-control"]


def test_spa_fallback_never_swallows_an_unknown_api_route(monkeypatch, tmp_path):
    monkeypatch.setenv("NORTHFLUX_SERVE_REACT", "true")
    monkeypatch.setattr(dashboard, "FRONTEND_DIST", _spa_build(tmp_path))
    response = TestClient(dashboard.app).get("/api/not-a-real-endpoint")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_production_fails_closed_when_react_build_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    monkeypatch.setenv("DASH_TOKEN", "northflux-production-test-token-123456789")
    monkeypatch.setattr(dashboard, "FRONTEND_DIST", tmp_path / "missing-dist")

    with pytest.raises(RuntimeError, match="compiled React frontend is required"):
        with TestClient(dashboard.app):
            pass


def test_domain_navigation_never_starts_a_scan(monkeypatch):
    monkeypatch.setenv("NORTHFLUX_SERVE_REACT", "false")
    monkeypatch.delenv("DASH_TOKEN", raising=False)
    monkeypatch.setattr(dashboard, "HAS_DB", False)
    monkeypatch.setattr(dashboard, "HAS_SCANNER", True)

    called = False

    def forbidden_scan(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("GET navigation must not scan")

    monkeypatch.setattr(dashboard, "scan_domain", forbidden_scan)
    response = TestClient(dashboard.app).get(
        "/domain/example.com", follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/scan?domain=example.com"
    assert called is False


def test_scan_history_and_monitoring_enrolment_are_independent(monkeypatch):
    monkeypatch.delenv("DASH_TOKEN", raising=False)
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "HAS_SCANNER", True)
    monkeypatch.setattr(dashboard, "HAS_EXPLANATIONS", False)
    monkeypatch.setattr(
        dashboard,
        "scan_domain",
        lambda domain, _starttls=False: {
            "domain": domain,
            "spf_present": True,
            "dmarc_present": True,
            "mx_present": True,
        },
    )
    monkeypatch.setattr(
        dashboard,
        "evaluate",
        lambda _result: {"grade": "A", "score": 90, "severity": "OK"},
    )
    monkeypatch.setattr(dashboard, "generate_remediation", lambda _result: [])

    class RecordingDatabase:
        def __init__(self):
            self.managed = []
            self.history = []

        def get_data_generation(self):
            return 0

        def write_scan_results(
            self,
            entries,
            *,
            save_history,
            manage_domains,
            **_kwargs,
        ):
            domains = [entry[0] for entry in entries]
            if save_history:
                self.history.extend(domains)
            if manage_domains:
                self.managed.extend(domains)
            return True

    database = RecordingDatabase()
    monkeypatch.setattr(dashboard, "get_database", lambda: database)
    client = TestClient(dashboard.app)

    saved_only = client.post(
        "/api/scan",
        json={"domains": ["example.com"], "save_to_db": True},
    )
    assert saved_only.status_code == 200
    assert saved_only.json()["results"][0]["saved"] is True
    assert database.history == ["example.com"]
    assert database.managed == []

    enrolled = client.post(
        "/api/scan",
        json={
            "domains": ["example.com"],
            "save_to_db": False,
            "manage_domains": True,
        },
    )
    assert enrolled.status_code == 200
    assert enrolled.json()["results"][0]["saved"] is False
    assert database.managed == ["example.com"]


def test_cloudflare_connection_test_supports_csrf_protected_post(monkeypatch):
    monkeypatch.delenv("DASH_TOKEN", raising=False)
    monkeypatch.setattr(dashboard, "HAS_DB", False)
    response = TestClient(dashboard.app).post("/api/settings/test-cloudflare")
    assert response.status_code == 200
    assert response.json()["ok"] is False
