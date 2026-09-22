"""DNS writes must fail closed without touching a provider during tests."""

from unittest.mock import Mock

import pytest

from app.dns_fix import CloudflareDNS


@pytest.fixture
def client():
    result = CloudflareDNS(api_token="test-only-token", zone_id="test-zone")
    result.zone_name = "example.com"
    return result


def test_txt_lookup_failure_never_creates_duplicate_record(client, monkeypatch):
    request = Mock(side_effect=[(False, {"errors": [{"message": "lookup failed"}]}), (True, {"result": {}})])
    monkeypatch.setattr(client, "_request", request)
    assert client.create_or_update_txt("example.com", "v=spf1 -all")[0] is False
    assert request.call_count == 1


def test_a_write_requires_zone_ownership(client, monkeypatch):
    request = Mock(return_value=(True, {"result": []}))
    monkeypatch.setattr(client, "_request", request)
    assert client.create_or_update_a("mta-sts.evil.example", "192.0.2.1")[0] is False
    request.assert_not_called()


def test_a_delete_requires_zone_ownership(client, monkeypatch):
    request = Mock(return_value=(True, {"result": [{"id": "existing", "content": "192.0.2.1"}]}))
    monkeypatch.setattr(client, "_request", request)
    client._delete_a_record("mta-sts.evil.example")
    request.assert_not_called()


def test_worker_deploy_checks_ownership_before_account_or_dns(client, monkeypatch):
    account = Mock(return_value=None)
    monkeypatch.setattr(client, "get_account_id", account)
    assert client.deploy_mta_sts_worker("evil.example", "mail.evil.example")[0] is False
    account.assert_not_called()


def test_worker_refuses_missing_mx_instead_of_inventing_policy(client, monkeypatch):
    account = Mock(return_value=None)
    monkeypatch.setattr(client, "get_account_id", account)
    ok, message = client.deploy_mta_sts_worker("example.com", "")
    assert ok is False
    assert "MX" in message
    account.assert_not_called()


def test_missing_spf_never_guesses_google_as_authorised_sender(client):
    fix = next(item for item in client.generate_fixes({"domain": "example.com"}) if item["type"] == "SPF")
    assert fix["auto_fix"] is None
    assert fix["manual"] is True
    assert "_spf.google.com" not in fix["recommended"]


def test_dkim_guidance_does_not_advertise_guessed_automatic_fix(client):
    fix = next(item for item in client.generate_fixes({"domain": "example.com", "mx_hosts": "aspmx.l.google.com"}) if item["type"] == "DKIM")
    assert fix["auto_fix"] is None
    assert fix["manual"] is True


def test_worker_preserves_existing_host_record(client, monkeypatch):
    monkeypatch.setattr(client, "get_account_id", lambda: "account")
    monkeypatch.setattr(client, "get_a_record", lambda name: {"id": "existing", "content": "8.8.8.8", "proxied": True})
    writer = Mock(return_value=(False, "must not write"))
    monkeypatch.setattr(client, "create_or_update_a", writer)
    ok, message = client.deploy_mta_sts_worker("example.com", "mx.example.com")
    assert ok is False
    assert "existing" in message.lower()
    writer.assert_not_called()


def test_worker_conflicting_route_is_not_reported_as_our_deployment(client, monkeypatch):
    monkeypatch.setattr(client, "get_account_id", lambda: "account")
    monkeypatch.setattr(client, "get_a_record", lambda name: None)
    monkeypatch.setattr(client, "_request", lambda *args: (True, {"result": [{"pattern": "mta-sts.example.com/*", "script": "someone-elses-worker"}]}))
    writer = Mock(return_value=(False, "must not write"))
    monkeypatch.setattr(client, "create_or_update_a", writer)
    ok, message = client.deploy_mta_sts_worker("example.com", "mx.example.com")
    assert ok is False
    assert "another Worker" in message
    writer.assert_not_called()


def test_txt_pagination_cannot_hide_duplicate_records(client, monkeypatch):
    request = Mock(return_value=(True, {"result": [], "result_info": {"total_pages": 2}}))
    monkeypatch.setattr(client, "_request", request)
    assert client.create_or_update_txt("example.com", "v=spf1 -all")[0] is False
    assert request.call_count == 1


@pytest.mark.parametrize("records,metadata", [
    ([{"id": "dummy", "content": "192.0.2.1", "proxied": True}, {"id": "real", "content": "8.8.8.8", "proxied": True}], {}),
    ([{"id": "dummy", "content": "192.0.2.1", "proxied": True}], {"total_pages": 2}),
    ([], {"total_pages": 2}),
    ([{"id": "dummy", "content": "192.0.2.1", "proxied": True}], {"total_pages": "unknown"}),
])
def test_worker_ambiguous_or_incomplete_a_read_never_writes(client, monkeypatch, records, metadata):
    monkeypatch.setattr(client, "get_account_id", lambda: "account")
    request = Mock(return_value=(True, {"result": records, "result_info": metadata}))
    monkeypatch.setattr(client, "_request", request)
    writer = Mock(return_value=(False, "must not write"))
    monkeypatch.setattr(client, "create_or_update_a", writer)
    ok, message = client.deploy_mta_sts_worker("example.com", "mx.example.com")
    assert ok is False
    assert "A record" in message
    writer.assert_not_called()
    assert request.call_count == 1
