from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.dashboard as dashboard
from app import database as database_module
from app.database import NorthFluxDatabase
from app.runtime_paths import get_logs_dir, get_reports_dir, get_state_dir


@pytest.fixture
def api_database(tmp_path, monkeypatch):
    database = NorthFluxDatabase(tmp_path / "northflux-v1.db")
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "get_database", lambda: database)
    yield database
    database.close()


@pytest.fixture(autouse=True)
def reset_auth_state(monkeypatch):
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    monkeypatch.delenv("NORTHFLUX_DEMO_MODE", raising=False)
    monkeypatch.delenv("DASH_TOKEN", raising=False)


def test_v1_open_session_and_bootstrap_are_typed_and_secret_free(
    api_database, monkeypatch
):
    api_database.set_setting("org_name", "Example Operator")
    api_database.set_setting("monitoring_enabled", "true")
    api_database.set_setting("automatic_remediation", "false")
    api_database.set_setting("cf_api_token", "stored-secret-must-not-leak")
    monkeypatch.setenv("CF_API_TOKEN", "environment-secret-must-not-leak")

    client = TestClient(dashboard.app)
    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200
    assert session.json() == {
        "required": False,
        "authenticated": True,
        "expires_at": None,
    }

    response = client.get("/api/v1/bootstrap")
    assert response.status_code == 200
    payload = response.json()
    assert payload["product"]["name"] == "NorthFlux Security"
    assert payload["auth"] == session.json()
    assert payload["runtime"] == {"production": False, "demo_mode": False}
    assert payload["operator"] == {"org_name": "Example Operator"}
    assert payload["capabilities"]["monitoring_enabled"] is True
    assert payload["capabilities"]["automatic_remediation"] is False
    serialised = response.text
    assert "stored-secret-must-not-leak" not in serialised
    assert "environment-secret-must-not-leak" not in serialised
    assert "cf_api_token" not in serialised


def test_v1_json_login_session_and_csrf_logout(monkeypatch):
    token = "northflux-v1-browser-token-32-chars"
    monkeypatch.setenv("DASH_TOKEN", token)
    client = TestClient(dashboard.app)

    unauthenticated = client.get("/api/v1/auth/session")
    assert unauthenticated.json() == {
        "required": True,
        "authenticated": False,
        "expires_at": None,
    }
    assert client.get("/api/v1/bootstrap").status_code == 401

    login = client.post("/api/v1/auth/login", json={"token": token})
    assert login.status_code == 200
    assert login.json()["required"] is True
    assert login.json()["authenticated"] is True
    assert login.json()["expires_at"]
    assert client.cookies.get("northflux_session")
    assert client.cookies.get("northflux_csrf")

    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200
    assert session.json()["authenticated"] is True
    assert session.json()["expires_at"]

    assert client.post("/api/v1/auth/logout").status_code == 403
    csrf_token = client.cookies.get("northflux_csrf")
    logout = client.post(
        "/api/v1/auth/logout",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf_token,
        },
    )
    assert logout.status_code == 200
    assert logout.json() == {
        "required": True,
        "authenticated": False,
        "expires_at": None,
    }
    assert client.get("/api/v1/auth/session").json()["authenticated"] is False


@pytest.mark.parametrize(
    "body",
    [
        {"token": 123},
        {"token": "valid-shape", "unexpected": True},
        {},
    ],
)
def test_v1_login_rejects_non_strict_payloads(body, monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "northflux-v1-validation-token-32")
    response = TestClient(dashboard.app).post("/api/v1/auth/login", json=body)
    assert response.status_code == 422


def test_v1_dashboard_normalises_database_values(api_database):
    api_database.add_managed_domain("good.example", notes="Primary domain")
    api_database.update_managed_domain_scan("good.example", "A", 90)
    api_database.add_managed_domain("risk.example")
    api_database.update_managed_domain_scan("risk.example", "D", 50)
    api_database.create_alert(
        domain="risk.example",
        alert_type="grade_drop",
        severity="HIGH",
        message="Grade dropped",
        details="Score moved below target",
    )
    api_database.set_setting("monitor_interval", "12")
    api_database.set_setting("monitoring_enabled", "true")
    api_database.set_setting("automatic_remediation", "false")

    response = TestClient(dashboard.app).get("/api/v1/dashboard")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"stats", "domains", "alerts", "settings"}
    assert payload["stats"] == {
        "total_scans": 0,
        "unique_domains": 0,
        "total_results": 0,
        "score_stats": {
            "avg_score": None,
            "min_score": None,
            "max_score": None,
        },
        "severity_distribution": {},
        "total_domains": 2,
        "average_score": 70,
        "passing_domains": 1,
        "failing_domains": 1,
        "grade_distribution": {
            "A+": 0,
            "A": 1,
            "B": 0,
            "C": 0,
            "D": 1,
            "F": 0,
        },
        "alert_count": 1,
    }
    assert payload["settings"] == {
        "monitor_interval_hours": 12,
        "monitoring_enabled": True,
        "automatic_remediation": False,
    }
    assert [item["domain"] for item in payload["domains"]] == [
        "good.example",
        "risk.example",
    ]
    assert all(isinstance(item["is_active"], bool) for item in payload["domains"])
    assert payload["alerts"][0]["acknowledged"] is False
    assert payload["alerts"][0]["created_at"]


def test_v1_dashboard_keeps_unscanned_domains_unscored(api_database):
    api_database.add_managed_domain("unscanned.example")
    api_database.add_managed_domain("scanned.example")
    api_database.update_managed_domain_scan("scanned.example", "A", 90)

    response = TestClient(dashboard.app).get("/api/v1/dashboard")

    assert response.status_code == 200
    payload = response.json()
    domains = {item["domain"]: item for item in payload["domains"]}
    assert domains["unscanned.example"]["last_grade"] is None
    assert domains["unscanned.example"]["last_score"] is None
    assert payload["stats"]["average_score"] == 90
    assert payload["stats"]["passing_domains"] == 1
    assert payload["stats"]["failing_domains"] == 0
    assert sum(payload["stats"]["grade_distribution"].values()) == 1


def test_runtime_directory_overrides_are_resolved(monkeypatch, tmp_path):
    state_dir = tmp_path / "state-e2e"
    reports_dir = tmp_path / "reports-e2e"
    logs_dir = tmp_path / "logs-e2e"
    monkeypatch.setenv("NORTHFLUX_STATE_DIR", str(state_dir))
    monkeypatch.setenv("NORTHFLUX_REPORTS_DIR", str(reports_dir))
    monkeypatch.setenv("NORTHFLUX_LOGS_DIR", str(logs_dir))

    assert get_state_dir() == state_dir.resolve()
    assert get_reports_dir() == reports_dir.resolve()
    assert get_logs_dir() == logs_dir.resolve()
    assert database_module._default_db_path() == state_dir.resolve() / "northflux.db"


def test_relative_runtime_directory_override_is_project_relative(monkeypatch):
    monkeypatch.setenv("NORTHFLUX_STATE_DIR", "tmp/e2e-state")
    expected = (Path(dashboard.ROOT) / "tmp" / "e2e-state").resolve()
    assert get_state_dir() == expected


def test_clear_data_deletes_generated_reports_and_preserves_settings(
    api_database, monkeypatch, tmp_path
):
    reports_root = tmp_path / "reports"
    indexed = reports_root / "indexed"
    archive = reports_root / "archive"
    indexed.mkdir(parents=True)
    archive.mkdir(parents=True)
    current_report = indexed / "northflux_results_20260922_010203.csv"
    legacy_report = archive / "auroraedge_results_20260319_151244.md"
    stage_report = archive / "stage7_results_20251203_232634.csv"
    root_report = reports_root / "northflux_results_20260922_010204.md"
    current_report.write_text("domain,score\nexample.com,90\n")
    legacy_report.write_text("# legacy report\n")
    stage_report.write_text("domain,score\nexample.com,70\n")
    root_report.write_text("# report\n")

    unrelated_root = reports_root / "customer_export.csv"
    unrelated_indexed = indexed / "northflux_results_latest.csv"
    unrelated_archive = archive / "notes.md"
    nested_report = reports_root / "customer-folder" / current_report.name
    nested_report.parent.mkdir()
    for sentinel in (
        unrelated_root,
        unrelated_indexed,
        unrelated_archive,
        nested_report,
    ):
        sentinel.write_text("preserve me\n")

    api_database.set_setting("org_name", "Example Operator")
    monkeypatch.setattr(dashboard, "REPORTS_ROOT", reports_root)

    response = TestClient(dashboard.app).post("/api/data/clear")

    assert response.status_code == 200
    assert response.json()["deleted_reports"] == 4
    assert not current_report.exists()
    assert not legacy_report.exists()
    assert not stage_report.exists()
    assert not root_report.exists()
    assert all(
        sentinel.exists()
        for sentinel in (
            unrelated_root,
            unrelated_indexed,
            unrelated_archive,
            nested_report,
        )
    )
    assert (reports_root / "indexed").is_dir()
    assert (reports_root / "archive").is_dir()
    assert api_database.get_setting("org_name") == "Example Operator"


def test_clear_data_fails_closed_for_unsafe_reports_root(
    api_database, monkeypatch, tmp_path
):
    protected_project = tmp_path / "project"
    protected_project.mkdir()
    sentinel = protected_project / "northflux_results_20260922_010203.csv"
    sentinel.write_text("must not be deleted\n")
    api_database.add_managed_domain("keep.example")
    monkeypatch.setattr(dashboard, "PROJECT_ROOT", protected_project)
    monkeypatch.setattr(dashboard, "REPORTS_ROOT", protected_project)

    response = TestClient(dashboard.app).post("/api/data/clear")

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Reports could not be cleared; scan data was not changed"
    }
    assert sentinel.exists()
    assert [
        domain["domain"] for domain in api_database.get_managed_domains()
    ] == ["keep.example"]


@pytest.mark.parametrize(
    "unsafe_root",
    [
        Path(dashboard.PROJECT_ROOT.anchor),
        Path.home(),
        dashboard.PROJECT_ROOT,
    ],
)
def test_reports_root_validation_rejects_broad_paths(unsafe_root):
    with pytest.raises(RuntimeError, match="unsafe"):
        dashboard._validated_reports_root(unsafe_root)
