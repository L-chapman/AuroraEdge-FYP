"""Mocked protocol cases taken from the RFCs, not from vendor scoring formulas."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import app.scanner as scanner
from app.dns_fix import CloudflareDNS
from app.rules import evaluate, generate_remediation, get_severity_explanation, rule_bimi_missing


@pytest.fixture
def isolated_scan(monkeypatch):
    monkeypatch.setattr(scanner, "_domain_exists", lambda _: True)
    monkeypatch.setattr(scanner, "_mx", lambda _: [])
    monkeypatch.setattr(scanner, "_txt", lambda _: [])
    monkeypatch.setattr(scanner, "_spf_fetch", lambda _: None)
    monkeypatch.setattr(scanner, "_mta_sts", lambda _: (False, "", 0, ""))


def test_smtp_fragmented_multiline_replies_still_find_starttls(monkeypatch):
    socket = Mock()
    socket.recv.side_effect = [b"22", b"0 mx.example.com\r\n", b"250-mx.example.com\r\n250-", b"START", b"TLS\r\n250 SIZE 1000\r\n", b"220 Ready\r\n"]
    monkeypatch.setattr(scanner, "_connect_public", lambda *args: socket)
    monkeypatch.setattr(scanner, "_socket_deadline", lambda *args: Mock())
    secure = Mock()
    secure.version.return_value = "TLSv1.3"
    secure.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    context = Mock()
    context.wrap_socket.return_value = secure
    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda: context)
    assert scanner._starttls_check("mx.example.com")[0] == "A+"
    assert socket.sendall.call_args_list[-1].args == (b"STARTTLS\r\n",)
    secure.close.assert_called_once()


def test_smtp_extension_name_must_match_not_contain_starttls(monkeypatch):
    socket = Mock()
    socket.recv.side_effect = [b"220 Ready\r\n", b"250-XSTARTTLS-NOTSUPPORTED\r\n250 SIZE 1\r\n", b"220 Ready\r\n"]
    monkeypatch.setattr(scanner, "_connect_public", lambda *args: socket)
    monkeypatch.setattr(scanner, "_socket_deadline", lambda *args: Mock())
    result = scanner._starttls_check("mx.example.com")
    assert result == ("F", "", "STARTTLS not advertised")
    assert socket.sendall.call_count == 1


def test_spf_counts_repeated_include_evaluations(monkeypatch):
    records = {"example.com": "v=spf1 include:child.example include:child.example -all", "child.example": "v=spf1 a mx -all"}
    monkeypatch.setattr(scanner, "_spf_fetch", records.get)
    assert scanner._spf_count("example.com")[0] == 6


def test_spf_ignores_unreachable_terms_and_redirect_when_all_exists(monkeypatch):
    fetch = Mock(return_value="v=spf1 redirect=other.example -all include:late.example mx")
    monkeypatch.setattr(scanner, "_spf_fetch", fetch)
    assert scanner._spf_count("example.com")[0] == 0
    fetch.assert_called_once_with("example.com")


def test_spf_cycle_is_explicitly_incomplete(monkeypatch, isolated_scan):
    monkeypatch.setattr(scanner, "_spf_fetch", lambda _: "v=spf1 include:example.com -all")
    result = scanner.scan_domain("example.com")
    assert result["scan_incomplete"] is True
    assert "cycle" in result["notes"].lower()


@pytest.mark.parametrize("record", ["p=AQID", "k=rsa; p=AQID", "v=DKIM1; p=AQID"])
def test_dkim_version_and_key_type_defaults(monkeypatch, record):
    monkeypatch.setattr(scanner, "SELECTOR_CANDIDATES", ["default"])
    monkeypatch.setattr(scanner, "_txt", lambda _: [record])
    selectors, algorithms, _ = scanner._dkim_discover("example.com")
    assert selectors == ["default"]
    assert algorithms == ["rsa"]


@pytest.mark.parametrize("record", ["v=DKIM10; p=AQID", "v=DKIM1; p=%%bad%%", "v=DKIM1; p=AQID; p=", "v=DKIM1; k=unknown; p=AQID"])
def test_invalid_dkim_key_record_does_not_earn_credit(monkeypatch, record):
    monkeypatch.setattr(scanner, "SELECTOR_CANDIDATES", ["default"])
    monkeypatch.setattr(scanner, "_txt", lambda _: [record])
    assert scanner._dkim_discover("example.com")[0] == []


def test_dkim_test_flag_is_a_token_not_substring(monkeypatch):
    monkeypatch.setattr(scanner, "SELECTOR_CANDIDATES", ["default"])
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=DKIM1; p=AQID; t=company"])
    assert "default:test" not in scanner._dkim_discover("example.com")[2]


@pytest.mark.parametrize("records", [["v=TLSRPTv1; rua="], ["v=TLSRPTv1; rua=not-a-uri"], ["v=TLSRPTv1; rua=http://example.com/reports"], ["v=TLSRPTv1; rua=mailto:r@example.com", "v=TLSRPTv1; rua=mailto:other@example.com"]])
def test_tls_rpt_rejects_invalid_or_ambiguous_records(monkeypatch, records):
    monkeypatch.setattr(scanner, "_txt", lambda _: records)
    assert scanner._tls_rpt("example.com")[0] is False


def test_dmarc_whitespace_parses_consistently(monkeypatch, isolated_scan):
    record = "v = DMARC1 ; p = reject; pct = 50; aspf = s; rua = mailto:r@example.com"
    monkeypatch.setattr(scanner, "_txt", lambda name: [record] if name.startswith("_dmarc.") else [])
    result = scanner.scan_domain("example.com")
    assert result["dmarc_present"] is True
    assert result["dmarc_policy"] == "reject"
    assert result["dmarc_pct"] == 50
    assert result["dmarc_aspf"] == "s"
    assert result["dmarc_rua"] == "mailto:r@example.com"


def test_null_mx_does_not_become_empty_hostname(monkeypatch):
    resolver = Mock()
    resolver.resolve.return_value = [SimpleNamespace(exchange=".", preference=0)]
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    assert scanner._mx("example.com") == ["."]


def test_address_only_subdomain_exists(monkeypatch):
    monkeypatch.setattr(scanner, "_mx", lambda _: [])
    monkeypatch.setattr(scanner, "_txt", lambda _: [])
    resolver = Mock()
    def resolve(name, kind):
        if kind == "A":
            return ["8.8.8.8"]
        raise scanner.dns.resolver.NoAnswer
    resolver.resolve.side_effect = resolve
    monkeypatch.setattr(scanner, "_fresh_resolver", lambda: resolver)
    assert scanner._domain_exists("sub.example.com") is True


def test_bimi_enforcement_percentage_is_not_ignored():
    assert rule_bimi_missing({"dmarc_present": True, "dmarc_policy": "reject", "dmarc_pct": 20})[1] == "OK"


def test_error_severity_is_not_explained_as_passed():
    assert get_severity_explanation("ERROR")["title"] != "Passed"


@pytest.mark.parametrize("host", ["google.com.attacker.example", "notgoogle.com", "mail.protection.outlook.com.evil.example"])
def test_provider_detection_requires_dns_label_boundary(host):
    assert CloudflareDNS.detect_email_provider(host)["provider"] == "unknown"


def test_google_dkim_guidance_uses_txt_not_invented_cname():
    provider = CloudflareDNS.detect_email_provider("aspmx.l.google.com")
    assert provider["dkim_type"] == "TXT"
    assert "cname_suffix" not in provider


def test_tls_rpt_writer_preserves_https_destination(monkeypatch):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    client.zone_name = "example.com"
    write = Mock(return_value=(True, "updated"))
    monkeypatch.setattr(client, "create_or_update_txt", write)
    assert client.fix_tls_rpt("example.com", "https://reports.example.net/tls")[0] is True
    assert write.call_args.args[1] == "v=TLSRPTv1; rua=https://reports.example.net/tls"


@pytest.mark.parametrize("policy", [None, "none", "quarantine"])
def test_dmarc_suggestions_require_sender_review(policy):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    fixes = client.generate_fixes({"domain": "example.com", "dmarc_present": policy is not None, "dmarc_policy": policy})
    fix = next(item for item in fixes if item["type"] == "DMARC")
    assert fix["auto_fix"] is None
    assert fix["manual"] is True
    assert "dmarc@example.com" not in fix["recommended"]


def test_spf_hardening_requires_confirmed_senders():
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    fix = next(item for item in client.generate_fixes({"domain": "example.com", "spf_present": True, "spf_record": "v=spf1 a ~all"}) if item["type"] == "SPF")
    assert fix["auto_fix"] is None
    assert fix["manual"] is True


def test_tls_rpt_suggestion_does_not_invent_a_mailbox():
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    fix = next(item for item in client.generate_fixes({"domain": "example.com"}) if item["type"] == "TLS-RPT")
    assert fix["auto_fix"] is None
    assert fix["manual"] is True
    assert "tlsrpt@example.com" not in fix["recommended"]


def test_worker_name_is_unique_for_previously_colliding_domains():
    assert CloudflareDNS._mta_worker_name("a.b-example.com") != CloudflareDNS._mta_worker_name("a-b.example.com")
    assert len(CloudflareDNS._mta_worker_name("a" * 63 + "." + "b" * 63 + ".com")) <= 63


def test_worker_does_not_overwrite_existing_unrelated_script(monkeypatch):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    client.zone_name = "example.com"
    monkeypatch.setattr(client, "get_account_id", lambda: "account")
    monkeypatch.setattr(client, "get_a_record", lambda _: None)
    worker_name = CloudflareDNS._mta_worker_name("example.com")
    request = Mock(side_effect=[(True, {"result": []}), (True, {"result": [{"id": worker_name}]})])
    monkeypatch.setattr(client, "_request", request)
    writer = Mock()
    monkeypatch.setattr(client, "create_or_update_a", writer)
    ok, message = client.deploy_mta_sts_worker("example.com", "mx.example.com")
    assert not ok
    assert "existing Worker" in message
    writer.assert_not_called()


@pytest.mark.parametrize("field", ["t=y", "np=reject", "psd=y"])
def test_new_dmarc_semantics_are_not_silently_graded_as_supported(monkeypatch, isolated_scan, field):
    monkeypatch.setattr(scanner, "_txt", lambda name: [f"v=DMARC1; p=reject; {field}"] if name.startswith("_dmarc.") else [])
    result = scanner.scan_domain("example.com")
    assert result["dmarc_present"] is True  # Direct-record observation, not a full verdict.
    assert result["scan_incomplete"] is True
    assert "9989" in result["notes"]


def test_txt_protocol_prefix_does_not_match_different_version(monkeypatch):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    client.zone_name = "example.com"
    monkeypatch.setattr(client, "get_txt_records", lambda _: [{"id": "unrelated", "content": "v=spf10 keep-me"}])
    request = Mock(return_value=(True, {"result": {}}))
    monkeypatch.setattr(client, "_request", request)
    assert client.create_or_update_txt("example.com", "v=spf1 -all")[0]
    assert request.call_args.args[0] == "POST"


def test_dmarc_writer_keeps_whitespace_separated_fields(monkeypatch):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    client.zone_name = "example.com"
    monkeypatch.setattr(client, "get_txt_record", lambda *args: {"content": "v = DMARC1; p = none; adkim = s; rua = mailto:reports@example.net"})
    write = Mock(return_value=(True, "updated"))
    monkeypatch.setattr(client, "create_or_update_txt", write)
    assert client.fix_dmarc("example.com", policy="quarantine")[0]
    content = write.call_args.args[1]
    assert "p=quarantine" in content and "p = none" not in content
    assert "adkim=s" in content and "rua=mailto:reports@example.net" in content


@pytest.mark.parametrize("policy,pct", [("reject; sp=none", 100), ("reject", -1), ("reject", 101), ("reject", None)])
def test_dmarc_writer_validates_before_any_write(monkeypatch, policy, pct):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    client.zone_name = "example.com"
    write = Mock()
    monkeypatch.setattr(client, "create_or_update_txt", write)
    monkeypatch.setattr(client, "get_txt_record", lambda *args: None)
    assert not client.fix_dmarc("example.com", policy=policy, pct=pct)[0]
    write.assert_not_called()


def test_null_mx_skips_only_inbound_checks(monkeypatch, isolated_scan):
    monkeypatch.setattr(scanner, "_mx", lambda _: ["."])
    smtp = Mock()
    blacklist = Mock()
    monkeypatch.setattr(scanner, "_check_mx_starttls", smtp)
    monkeypatch.setattr(scanner, "_mx_blacklist_check", blacklist)
    result = scanner.scan_domain("example.com", check_starttls=True)
    assert result["null_mx"] is True
    assert result["mx_present"] is False and result["mx_hosts"] == ""
    assert result["scan_incomplete"] is False
    smtp.assert_not_called()
    blacklist.assert_not_called()
    violations = evaluate(result)["violations"]
    assert "R2_SPF_MISSING" in violations and "R4_DMARC_MISSING" in violations
    assert not any(rule in violations for rule in ("R1_MX", "R8_MTA", "R10_TLS"))
    assert not any(item["rule"] in {"R1_MX_MISSING", "R8_MTA_STS_MISSING", "R10_TLS_RPT_MISSING"} for item in generate_remediation(result))
    fixes = CloudflareDNS(api_token="test-only", zone_id="zone").generate_fixes({**result, "domain": "example.com"})
    assert not any(item["type"] in {"MTA-STS", "MTA-STS-HTTPS", "TLS-RPT"} for item in fixes)


@pytest.mark.parametrize("chunks", [[b"250-one\r\n550 wrong\r\n"], [b"250-one\r\n", b""], [b"x" * 4096] * 5])
def test_smtp_reply_bounds_and_malformed_data(chunks):
    connection = Mock()
    connection.recv.side_effect = chunks
    with pytest.raises(ValueError):
        scanner._smtp_reply(connection)


def test_valid_multi_destination_tls_rpt(monkeypatch):
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=TLSRPTv1; rua=mailto:r@example.com,https://reports.example.net/tls"])
    assert scanner._tls_rpt("example.com") == (True, "mailto:r@example.com,https://reports.example.net/tls")


def test_spf_redirect_evaluated_when_no_all(monkeypatch):
    monkeypatch.setattr(scanner, "_spf_fetch", {"example.com": "v=spf1 a redirect=other.example", "other.example": "v=spf1 mx -all"}.get)
    assert scanner._spf_count("example.com") == (3, "")


def test_spf_cap_is_incomplete_and_bounded(monkeypatch, isolated_scan):
    monkeypatch.setattr(scanner, "MAX_SPF_FETCHES", 3)
    fetch = Mock(return_value="v=spf1 include:child.example -all")
    def records(name):
        return "v=spf1 " + " ".join(f"include:child{i}.example" for i in range(10)) + " -all"
    fetch.side_effect = records
    monkeypatch.setattr(scanner, "_spf_fetch", fetch)
    result = scanner.scan_domain("example.com")
    assert result["scan_incomplete"] is True
    assert fetch.call_count <= 4  # Initial presence check plus three unique reads.


def test_mta_sts_dns_version_allows_delimiter_whitespace(monkeypatch):
    monkeypatch.setattr(scanner, "_txt", lambda _: ["v=STSv1 \t; id=abc123"])
    monkeypatch.setattr(scanner, "_fetch_mta_sts_policy", lambda _: "version: STSv1\nmode: none\nmax_age: 60\n")
    assert scanner._mta_sts("example.com")[:3] == (True, "none", 60)


def test_generated_recommendations_never_assume_mail_or_tls_readiness():
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    fixes = client.generate_fixes({"domain": "example.com", "mx_hosts": "mx.example.com"})
    assert {item["type"] for item in fixes} >= {"SPF", "DMARC", "DKIM", "TLS-RPT", "MTA-STS", "MTA-STS-HTTPS"}
    assert all(item["auto_fix"] is None and item["manual"] for item in fixes)


@pytest.mark.parametrize("script_response", [
    {"result": [{}]}, {"result": [{"id": ""}]}, {"result": [{"id": 3}]},
    {"result": [], "result_info": {"total_pages": 2}},
    {"result": [], "result_info": {"total_count": 1}},
    {"result": [], "result_info": {"page": "unknown"}},
])
def test_worker_script_inventory_must_be_complete_and_well_formed(monkeypatch, script_response):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    client.zone_name = "example.com"
    monkeypatch.setattr(client, "get_account_id", lambda: "account")
    monkeypatch.setattr(client, "get_a_record", lambda _: None)
    monkeypatch.setattr(client, "_request", Mock(side_effect=[(True, {"result": []}), (True, script_response)]))
    writer = Mock(return_value=(False, "unexpected write"))
    monkeypatch.setattr(client, "create_or_update_a", writer)
    assert client.deploy_mta_sts_worker("example.com", "mx.example.com")[0] is False
    writer.assert_not_called()


def test_worker_route_inventory_rejects_malformed_items(monkeypatch):
    client = CloudflareDNS(api_token="test-only", zone_id="zone")
    client.zone_name = "example.com"
    monkeypatch.setattr(client, "get_account_id", lambda: "account")
    monkeypatch.setattr(client, "get_a_record", lambda _: None)
    monkeypatch.setattr(client, "_request", lambda *args: (True, {"result": [None]}))
    writer = Mock()
    monkeypatch.setattr(client, "create_or_update_a", writer)
    assert client.deploy_mta_sts_worker("example.com", "mx.example.com")[0] is False
    writer.assert_not_called()
