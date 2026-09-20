from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import app.dashboard as dashboard
import app.dns_fix as dns_fix
from app.database import NorthFluxDatabase
from app.dns_fix import CloudflareDNS


def test_txt_update_selects_matching_protocol_record(monkeypatch):
    client = CloudflareDNS(api_token="token", zone_id="zone")
    client.zone_name = "example.com"
    writes = []

    def request(method, url, data=None):
        if method == "GET":
            return True, {
                "result": [
                    {"id": "verification", "content": "site-verification=keep-me"},
                    {"id": "spf", "content": "v=spf1 ~all"},
                ]
            }
        writes.append((method, url, data))
        return True, {"result": {}}

    monkeypatch.setattr(client, "_request", request)
    ok, _ = client.create_or_update_txt("example.com", "v=spf1 -all")

    assert ok is True
    assert writes[0][0] == "PUT"
    assert writes[0][1].endswith("/spf")
    assert writes[0][2]["content"] == "v=spf1 -all"


def test_txt_update_refuses_duplicate_protocol_records(monkeypatch):
    client = CloudflareDNS(api_token="token", zone_id="zone")
    client.zone_name = "example.com"
    monkeypatch.setattr(
        client,
        "_request",
        lambda method, url, data=None: (
            True,
            {"result": [
                {"id": "one", "content": "v=spf1 include:a.example -all"},
                {"id": "two", "content": "v=spf1 include:b.example -all"},
            ]},
        ),
    )

    ok, message = client.create_or_update_txt("example.com", "v=spf1 -all")

    assert ok is False
    assert "multiple v=spf1" in message


def test_dmarc_policy_change_preserves_existing_tags(monkeypatch):
    client = CloudflareDNS(api_token="token", zone_id="zone")
    client.zone_name = "example.com"
    monkeypatch.setattr(
        client,
        "get_txt_record",
        lambda name, prefix="": {
            "content": "v=DMARC1; p=none; rua=mailto:reports@example.com; adkim=s; aspf=s; fo=1"
        },
    )
    captured = {}

    def write(name, content, comment=""):
        captured["name"] = name
        captured["content"] = content
        return True, "updated"

    monkeypatch.setattr(client, "create_or_update_txt", write)
    ok, _ = client.fix_dmarc("example.com", policy="reject")

    assert ok is True
    assert "p=reject" in captured["content"]
    assert "rua=mailto:reports@example.com" in captured["content"]
    assert "adkim=s" in captured["content"]
    assert "aspf=s" in captured["content"]
    assert "fo=1" in captured["content"]


def test_dkim_requires_provider_supplied_records(monkeypatch):
    client = CloudflareDNS(api_token="token", zone_id="zone")
    client.zone_name = "example.com"
    writer = MagicMock()
    monkeypatch.setattr(client, "create_or_update_cname", writer)

    ok, message = client.fix_dkim(
        "example.com", {"mx_hosts": "example-com.mail.protection.outlook.com"}
    )

    assert ok is False
    assert "admin console" in message
    writer.assert_not_called()


def test_onboarding_does_not_remediate_by_default(tmp_path, monkeypatch):
    database = NorthFluxDatabase(tmp_path / "northflux.db")
    monkeypatch.setenv("DASH_TOKEN", "")
    monkeypatch.setattr(dashboard, "get_database", lambda: database)
    monkeypatch.setattr(
        dashboard,
        "scan_domain",
        lambda domain, check_starttls=False: {"domain": domain},
    )
    monkeypatch.setattr(
        dashboard,
        "evaluate",
        lambda result: {"grade": "F", "score": 10, "severity": "HIGH", "violations": []},
    )
    remediation = MagicMock()
    monkeypatch.setattr(dashboard, "_auto_fix_domain", remediation)

    response = TestClient(dashboard.app).post(
        "/api/managed-domains", json={"domain": "example.com"}
    )

    assert response.status_code == 200
    assert "auto_fix" not in response.json()
    remediation.assert_not_called()
    database.close()


def test_demo_reset_hidden_without_demo_mode(monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "")
    monkeypatch.delenv("NORTHFLUX_DEMO_MODE", raising=False)
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)

    response = TestClient(dashboard.app).post("/api/demo/reset", json={})

    assert response.status_code == 404


def test_production_requires_authentication_token(monkeypatch):
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    monkeypatch.delenv("DASH_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="DASH_TOKEN is required"):
        with TestClient(dashboard.app):
            pass


def test_production_requires_strong_authentication_token(monkeypatch):
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    monkeypatch.setenv("DASH_TOKEN", "too-short")

    with pytest.raises(RuntimeError, match="at least 32 characters"):
        with TestClient(dashboard.app):
            pass


def test_invalid_legacy_managed_domain_is_not_rendered(monkeypatch):
    class FakeDatabase:
        def get_managed_domains(self):
            return [{"domain": '\"><img src=x onerror=alert(1)>', "last_score": 0}]

        def get_alerts(self, **kwargs):
            return []

    monkeypatch.setenv("DASH_TOKEN", "")
    monkeypatch.setattr(dashboard, "get_database", lambda: FakeDatabase())

    response = TestClient(dashboard.app).get("/domains")

    assert response.status_code == 200
    assert "<img src=x onerror=alert(1)>" not in response.text


def test_environment_cloudflare_token_is_not_persisted(tmp_path, monkeypatch):
    database = NorthFluxDatabase(tmp_path / "northflux.db")
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    monkeypatch.setenv("CF_API_TOKEN", "runtime-only-cloudflare-token")
    monkeypatch.setattr(dns_fix, "CF_API_TOKEN", "")

    dashboard._load_cf_runtime_settings(database)

    assert dns_fix.CF_API_TOKEN == "runtime-only-cloudflare-token"
    assert database.get_setting("cf_api_token", "") == ""


def test_production_ignores_stored_cloudflare_secret(tmp_path, monkeypatch):
    database = NorthFluxDatabase(tmp_path / "northflux.db")
    database.set_setting("cf_api_token", "legacy-plaintext-token")
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    monkeypatch.delenv("CF_API_TOKEN", raising=False)
    monkeypatch.setattr(dns_fix, "CF_API_TOKEN", "legacy-plaintext-token")

    dashboard._load_cf_runtime_settings(database)

    assert dns_fix.CF_API_TOKEN == ""


def test_production_migrates_cloudflare_secret_out_of_database(tmp_path, monkeypatch):
    database = NorthFluxDatabase(tmp_path / "northflux.db")
    database.set_setting("cf_api_token", "legacy-plaintext-token")
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    monkeypatch.setenv("CF_API_TOKEN", "replacement-runtime-token")
    monkeypatch.setattr(dns_fix, "CF_API_TOKEN", "")

    dashboard._load_cf_runtime_settings(database)

    assert dns_fix.CF_API_TOKEN == "replacement-runtime-token"
    assert database.get_setting("cf_api_token", "") == ""
