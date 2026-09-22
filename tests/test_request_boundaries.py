"""Adversarial request regressions using disposable storage and no live services."""

import json
import sqlite3
import asyncio
import threading
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import app.dashboard as dashboard
from app.database import NorthFluxDatabase


@pytest.fixture
def isolated_api(tmp_path, monkeypatch):
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    monkeypatch.delenv("NORTHFLUX_DEMO_MODE", raising=False)
    monkeypatch.setenv("DASH_TOKEN", "")
    monkeypatch.setattr(dashboard, "_sessions", {})
    monkeypatch.setattr(dashboard, "_login_rate", {})
    database = NorthFluxDatabase(tmp_path / "requests.db")
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "HAS_SCANNER", True)
    monkeypatch.setattr(dashboard, "get_database", lambda: database)
    monkeypatch.setattr(dashboard, "_apply_cf_settings", lambda db: None)
    scanner = Mock(side_effect=AssertionError("Unexpected scan"))
    monkeypatch.setattr(dashboard, "scan_domain", scanner)
    client = TestClient(dashboard.app, raise_server_exceptions=False)
    try:
        # Do not enter the application lifespan or touch operator runtime paths.
        yield client, database, scanner
    finally:
        client.close()
        database.close()


@pytest.mark.parametrize("route", ["/api/v1/auth/login", "/login"])
def test_non_ascii_wrong_token_is_rejected_not_server_error(route, monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "test-operator-token-with-32-characters")
    monkeypatch.setattr(dashboard, "_login_rate", {})
    client = TestClient(dashboard.app, raise_server_exceptions=False)
    request = {"json": {"token": "not-valid-\u00e9\U0001f512"}} if route.startswith("/api") else {
        "data": {"token": "not-valid-\u00e9\U0001f512"}
    }
    response = client.post(route, **request)
    assert response.status_code == 401
    assert len(dashboard._login_rate["testclient"]) == 1


def test_non_ascii_legacy_query_token_is_rejected(monkeypatch):
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    monkeypatch.setenv("DASH_TOKEN", "test-operator-token-with-32-characters")
    client = TestClient(dashboard.app, raise_server_exceptions=False)
    assert client.get("/api/v1/bootstrap", params={"token": "wrong-\u00e9"}).status_code == 401
    assert client.get("/api/v1/auth/session", params={"token": "wrong-\u00e9"}).json()["authenticated"] is False


def test_login_rejects_excess_form_fields_without_crashing(monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "test-operator-token-with-32-characters")
    monkeypatch.setattr(dashboard, "_login_rate", {})
    response = TestClient(dashboard.app, raise_server_exceptions=False).post(
        "/login", data={f"field{i}": "value" for i in range(11)}
    )
    assert response.status_code == 400


@pytest.mark.parametrize("route", ["/api/scan", "/api/settings", "/api/managed-domains"])
@pytest.mark.parametrize("body", [None, [], "text", 42, True])
def test_json_routes_require_objects(isolated_api, route, body):
    client, database, scanner = isolated_api
    response = client.post(route, content=json.dumps(body), headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert database.get_all_settings() == {}
    scanner.assert_not_called()


@pytest.mark.parametrize("domains", [42, True, {"example.com": "value"}])
def test_scan_rejects_non_list_domain_collections(isolated_api, domains):
    client, _, scanner = isolated_api
    assert client.post("/api/scan", json={"domains": domains}).status_code == 400
    scanner.assert_not_called()


def test_oversized_json_login_is_bounded_before_parsing(monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "test-operator-token-with-32-characters")
    response = TestClient(dashboard.app, raise_server_exceptions=False).post(
        "/api/v1/auth/login", json={"token": "x" * 70000}
    )
    assert response.status_code == 413
    assert len(response.content) < 200


def test_chunked_oversized_body_is_bounded(isolated_api):
    client, _, scanner = isolated_api
    response = client.post(
        "/api/scan", content=(b" " * 8192 for _ in range(9)),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    scanner.assert_not_called()


def test_settings_validation_cannot_partially_save(isolated_api):
    client, database, _ = isolated_api
    database.set_setting("cf_zone_id", "previous-zone")
    response = client.post("/api/settings", json={
        "cf_zone_id": "new-zone", "monitor_interval": "not-valid",
    })
    assert response.status_code == 400
    assert database.get_setting("cf_zone_id") == "previous-zone"


@pytest.mark.parametrize("value", [{"enabled": True}, [True], "maybe", None])
def test_settings_reject_invalid_safety_switch_values(isolated_api, value):
    client, database, _ = isolated_api
    response = client.post("/api/settings", json={"automatic_remediation": value})
    assert response.status_code == 400
    assert database.get_setting("automatic_remediation") == ""


def test_settings_reject_oversized_text(isolated_api):
    client, database, _ = isolated_api
    response = client.post("/api/settings", json={"org_name": "x" * 10001})
    assert response.status_code == 400
    assert database.get_setting("org_name") == ""


def test_domain_validation_enforces_dns_total_length():
    too_long = ".".join(["a" * 63] * 4)
    _, error = dashboard._sanitize_domain(too_long)
    assert error


def test_domain_validation_rejects_non_string_values():
    for value in (42, True, ["example.com"], {"domain": "example.com"}):
        _, error = dashboard._sanitize_domain(value)
        assert error


def test_settings_database_write_rolls_back_the_whole_batch(tmp_path):
    database = NorthFluxDatabase(tmp_path / "atomic-settings.db")
    try:
        database.set_setting("org_name", "Before")
        database.conn.execute("""CREATE TRIGGER reject_interval BEFORE INSERT ON settings
            WHEN NEW.key = 'monitor_interval' BEGIN SELECT RAISE(ABORT, 'test failure'); END""")
        with pytest.raises(sqlite3.IntegrityError):
            database.set_settings({"org_name": "After", "monitor_interval": "12"})
        database.set_setting("unrelated", "committed")
        assert database.get_setting("org_name") == "Before"
        assert database.get_setting("monitor_interval") == ""
    finally:
        database.close()


@pytest.mark.parametrize("body", [[], {"domain": "example.com", "fix_types": []},
    {"domain": "example.com", "fix_types": "SPF"},
    {"domain": "example.com", "fix_types": ["unknown"]}])
def test_invalid_fix_request_cannot_contact_provider(isolated_api, monkeypatch, body):
    client, _, _ = isolated_api
    provider = Mock(side_effect=AssertionError("Must validate before contacting provider"))
    monkeypatch.setattr(dashboard, "get_cloudflare_client", provider)
    response = client.post("/api/apply-fix", json=body)
    assert response.status_code == 400
    provider.assert_not_called()


def test_remediation_does_not_block_the_event_loop(isolated_api, monkeypatch):
    _, _, scanner = isolated_api
    event_loop_thread = threading.get_ident()
    provider_threads = []
    provider = Mock()
    provider.validate_connection.side_effect = lambda: (
        provider_threads.append(threading.get_ident()) or True, "Connected"
    )
    provider.verify_domain_ownership.return_value = (True, "Owned")
    provider.generate_fixes.return_value = []
    monkeypatch.setattr(dashboard, "get_cloudflare_client", lambda: provider)
    scanner.side_effect = None
    scanner.return_value = {"domain": "example.com"}

    async def receive():
        return {"type": "http.request", "body": b'{"domain":"example.com"}'}

    request = Request({"type": "http", "method": "POST", "path": "/api/apply-fix",
        "headers": []}, receive)
    result = asyncio.run(dashboard.api_apply_fix(request))
    assert result["status"] == "no_action"
    assert provider_threads and event_loop_thread not in provider_threads
