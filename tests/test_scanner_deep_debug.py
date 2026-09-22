"""Deterministic regressions for scan boundaries and false-positive protocol checks."""

from unittest.mock import Mock

import pytest

import app.scanner as scanner
from app.dns_fix import CloudflareDNS
from app.rules import evaluate


def test_domain_validator_rejects_trailing_newline_and_excess_length():
    assert not scanner.is_valid_domain("example.com\n")
    assert not scanner.is_valid_domain(".".join(["a" * 63] * 4) + ".com")


def test_starttls_does_not_connect_to_private_mx(monkeypatch):
    resolver = Mock()
    resolver.resolve.return_value = ["127.0.0.1"]
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    connection = Mock()
    connection.recv.return_value = b"220 local SMTP\r\n"
    connect = Mock(return_value=connection)
    monkeypatch.setattr(scanner.socket, "socket", connect)
    scanner._starttls_check("mail.example.com")
    connect.assert_not_called()


@pytest.mark.parametrize("body", [
    b"<html>not a policy</html>",
    b"version: STSv1\nmode: enforce\nmax_age: 86400\n",  # missing MX
    b"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: -1\n",
])
def test_mta_sts_does_not_accept_invalid_policy(monkeypatch, body):
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=STSv1; id=abc123"])
    monkeypatch.setattr(scanner, "_fetch_mta_sts_policy", lambda _: body.decode())
    assert scanner._mta_sts("example.com")[0] is False


def test_mta_sts_duplicate_dns_records_are_not_valid(monkeypatch):
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=STSv1; id=one", "v=STSv1; id=two"])
    fetch = Mock(return_value="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1")
    monkeypatch.setattr(scanner, "_fetch_mta_sts_policy", fetch)
    assert scanner._mta_sts("example.com")[0] is False
    fetch.assert_not_called()


def test_spf_qualified_mechanisms_count_towards_lookup_limit(monkeypatch):
    monkeypatch.setattr(scanner, "_spf_fetch", lambda name: "v=spf1 +a ~mx -exists:example.net ?include:child.example -all" if name == "example.com" else "v=spf1 -all")
    assert scanner._spf_count("example.com")[0] == 4


def test_dkim_revoked_empty_key_is_not_reported_available(monkeypatch):
    monkeypatch.setattr(scanner, "SELECTOR_CANDIDATES", ["default"])
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=DKIM1; k=rsa; p="])
    assert scanner._dkim_discover("example.com")[0] == []


def test_multiple_spf_records_are_not_silently_selected(monkeypatch):
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=spf1 +all", "v=spf1 -all"])
    assert scanner._spf_fetch("example.com") is None


def test_spamhaus_error_response_is_not_a_blacklist_listing(monkeypatch):
    resolver = Mock()
    resolver.resolve.return_value = ["127.255.255.254"]
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    monkeypatch.setattr(scanner, "_DNSBL_ZONES", ["zen.spamhaus.org"])
    assert scanner._check_rbl("8.8.8.8") == []


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.2", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_network_boundary_rejects_non_public_answers(monkeypatch, address):
    resolver = Mock()
    resolver.resolve.return_value = [address]
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    with pytest.raises(ValueError, match="network destinations"):
        scanner._public_addresses("mx.example.com")


def test_connection_uses_pinned_ip_not_second_hostname_resolution(monkeypatch):
    monkeypatch.setattr(scanner, "_public_addresses", lambda _: ["8.8.8.8"])
    connection = Mock()
    monkeypatch.setattr(scanner.socket, "socket", Mock(return_value=connection))
    assert scanner._connect_public("mx.example.com", 25, 2) is connection
    connection.connect.assert_called_once_with(("8.8.8.8", 25))


@pytest.fixture
def policy_transport(monkeypatch):
    raw = Mock()
    secure = Mock()
    context = Mock()
    context.wrap_socket.return_value = secure
    connection = Mock()
    response = Mock(status=200)
    response.getheader.return_value = "text/plain; charset=utf-8"
    response.read.return_value = b"version: STSv1\nmode: none\nmax_age: 0\n"
    connection.getresponse.return_value = response
    monkeypatch.setattr(scanner, "_connect_public", Mock(return_value=raw))
    monkeypatch.setattr(scanner.ssl, "create_default_context", Mock(return_value=context))
    monkeypatch.setattr(scanner.http.client, "HTTPSConnection", Mock(return_value=connection))
    monkeypatch.setattr(scanner, "_socket_deadline", lambda *args: Mock())
    return raw, secure, context, connection, response


def test_https_pinning_retains_original_hostname_and_closes_transport(policy_transport):
    raw, secure, context, connection, response = policy_transport
    assert "STSv1" in scanner._fetch_mta_sts_policy("mta-sts.example.com")
    context.wrap_socket.assert_called_once_with(raw, server_hostname="mta-sts.example.com")
    assert connection.sock is secure
    connection.request.assert_called_once_with("GET", "/.well-known/mta-sts.txt", headers={"Accept": "text/plain"})
    response.read.assert_called_once_with(10_241)
    connection.close.assert_called_once()
    raw.close.assert_called_once()


@pytest.mark.parametrize("status", [301, 302, 307, 404, 500])
def test_https_policy_never_follows_redirect_or_accepts_error(policy_transport, status):
    raw, _, _, connection, response = policy_transport
    response.status = status
    with pytest.raises(ValueError, match="HTTP 200"):
        scanner._fetch_mta_sts_policy("mta-sts.example.com")
    response.read.assert_not_called()
    connection.close.assert_called_once()


def test_https_policy_rejects_oversized_body_without_unbounded_read(policy_transport):
    response = policy_transport[-1]
    response.read.return_value = b"x" * 10_241
    with pytest.raises(ValueError, match="10 KiB"):
        scanner._fetch_mta_sts_policy("mta-sts.example.com")
    response.read.assert_called_once_with(10_241)


def test_valid_sts_policy_accepts_first_value_and_none_mode(monkeypatch):
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=STSv1; id=Abc123"])
    monkeypatch.setattr(scanner, "_fetch_mta_sts_policy", lambda _: "version: STSv1\nmode: none\nmode: enforce\nmax_age: 0\n")
    assert scanner._mta_sts("example.com")[:3] == (True, "none", 0)


def test_dns_timeout_marks_scan_incomplete_and_prevents_automatic_fixes(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = scanner.dns.resolver.LifetimeTimeout
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    result = scanner.scan_domain("example.com")
    assert result["scan_incomplete"] is True
    assert "lookup could not be completed" in result["notes"]
    fixes = CloudflareDNS(api_token="test-only", zone_id="test-zone").generate_fixes(result)
    assert fixes and all(item["auto_fix"] is None for item in fixes)
    evaluation = evaluate(result)
    assert evaluation["severity"] == "ERROR"
    assert evaluation["scan_incomplete"] is True
    assert "provisional" in evaluation["advice"]


def test_nxdomain_is_absence_not_timeout(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = scanner.dns.resolver.NXDOMAIN
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    assert scanner.scan_domain("example.com")["scan_incomplete"] is False


def test_scan_budget_expiry_does_not_start_new_dns_query(monkeypatch):
    monkeypatch.setattr(scanner, "SCAN_TIMEOUT", -1)
    resolver = Mock()
    monkeypatch.setattr(scanner.dns.resolver, "Resolver", Mock(return_value=resolver))
    result = scanner.scan_domain("example.com")
    assert result["scan_incomplete"] is True
    assert "time limit" in result["notes"]
    resolver.resolve.assert_not_called()


@pytest.fixture
def isolated_scan(monkeypatch):
    monkeypatch.setattr(scanner, "_domain_exists", lambda _: True)
    monkeypatch.setattr(scanner, "_mx", lambda _: [])
    monkeypatch.setattr(scanner, "_txt", lambda _: [])
    monkeypatch.setattr(scanner, "_spf_fetch", lambda _: None)
    monkeypatch.setattr(scanner, "_mta_sts", lambda _: (False, "", 0, ""))


@pytest.mark.parametrize("records", [
    ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
    ["v=DMARC1; rua=mailto:reports@example.com"],
    ["v=DMARC1; p=reject; pct=invalid"],
    ["v=DMARC1; p=reject; p=none"],
])
def test_ambiguous_dmarc_does_not_earn_verified_policy(monkeypatch, isolated_scan, records):
    monkeypatch.setattr(scanner, "_txt", lambda name: records if name == "_dmarc.example.com" else [])
    result = scanner.scan_domain("example.com")
    assert result["dmarc_present"] is False
    assert result["scan_incomplete"] is True


def test_bare_spf_all_is_permissive_and_later_all_does_not_override(monkeypatch, isolated_scan):
    monkeypatch.setattr(scanner, "_spf_fetch", lambda _: "v=spf1 all -all")
    monkeypatch.setattr(scanner, "_spf_count", lambda _: (0, ""))
    result = scanner.scan_domain("example.com")
    assert result["spf_all"] == "+all"
    assert "R3B_SPF_PERMISSIVE" in evaluate(result)["violations"]


def assert_incomplete_blocks_automatic_fixes(result):
    assert result["scan_incomplete"] is True
    assert evaluate(result)["severity"] == "ERROR"
    fixes = CloudflareDNS(api_token="test-only", zone_id="test-zone").generate_fixes(result)
    assert fixes and all(item["auto_fix"] is None for item in fixes)


@pytest.mark.parametrize("failure", [scanner.socket.timeout("timeout"), ConnectionRefusedError("refused"), scanner.ssl.SSLError("TLS failed")])
def test_starttls_operational_failure_blocks_automatic_fixes(monkeypatch, isolated_scan, failure):
    monkeypatch.setattr(scanner, "_mx", lambda _: ["mx.example.com"])
    monkeypatch.setattr(scanner, "_mx_blacklist_check", lambda _: (0, []))
    monkeypatch.setattr(scanner, "_connect_public", Mock(side_effect=failure))
    result = scanner.scan_domain("example.com", check_starttls=True)
    assert_incomplete_blocks_automatic_fixes(result)
    assert "STARTTLS check could not be completed" in result["notes"]


def test_mx_address_timeout_blocks_automatic_fixes(monkeypatch, isolated_scan):
    monkeypatch.setattr(scanner, "_mx", lambda _: ["mx.example.com"])
    resolver = Mock()
    resolver.resolve.side_effect = scanner.dns.resolver.LifetimeTimeout
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    result = scanner.scan_domain("example.com")
    assert_incomplete_blocks_automatic_fixes(result)
    assert "MX address lookup could not be completed" in result["notes"]


@pytest.mark.parametrize("response", [None, ["127.255.255.254"], ["8.8.4.4"]])
def test_rbl_operational_or_provider_error_blocks_automatic_fixes(monkeypatch, isolated_scan, response):
    monkeypatch.setattr(scanner, "_mx", lambda _: ["mx.example.com"])
    monkeypatch.setattr(scanner, "_resolve_a", lambda _: ["8.8.8.8"])
    monkeypatch.setattr(scanner, "_DNSBL_ZONES", ["zen.spamhaus.org"])
    resolver = Mock()
    if response is None:
        resolver.resolve.side_effect = scanner.dns.resolver.LifetimeTimeout
    else:
        resolver.resolve.return_value = response
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    result = scanner.scan_domain("example.com")
    assert result["rbl_listings"] == 0
    assert_incomplete_blocks_automatic_fixes(result)
    assert "DNSBL" in result["notes"]


@pytest.mark.parametrize("failure", [scanner.dns.resolver.NXDOMAIN, scanner.dns.resolver.NoAnswer])
@pytest.mark.parametrize("lookup", ["address", "rbl"])
def test_negative_dns_answers_are_not_operational_failure(monkeypatch, isolated_scan, failure, lookup):
    monkeypatch.setattr(scanner, "_mx", lambda _: ["mx.example.com"])
    monkeypatch.setattr(scanner, "_DNSBL_ZONES", ["zen.spamhaus.org"])
    if lookup == "rbl":
        monkeypatch.setattr(scanner, "_resolve_a", lambda _: ["8.8.8.8"])
    resolver = Mock()
    resolver.resolve.side_effect = failure
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    assert scanner.scan_domain("example.com")["scan_incomplete"] is False
def test_retired_sorbs_service_is_not_queried():
    assert "dnsbl.sorbs.net" not in scanner._DNSBL_ZONES
