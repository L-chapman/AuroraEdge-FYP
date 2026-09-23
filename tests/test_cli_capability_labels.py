"""Offline checks for truthful CLI capabilities and the retained compatibility path."""

import sys
from unittest.mock import Mock

import pytest

from app import cli
from app.dns_fix import CloudflareDNS


def test_help_explains_manual_advice_and_retained_cloudflare_flag(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["northflux", "--help"])
    scan = Mock()
    provider = Mock()
    monkeypatch.setattr(cli, "scan_domains", scan)
    monkeypatch.setattr(cli, "get_cloudflare_client", provider)

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == 0
    output = " ".join(capsys.readouterr().out.split())
    assert "--apply-fix" in output
    assert "compatibility workflow" in output
    assert "manual-only" in output
    assert "--remediation" in output
    assert "requires Rich" in output
    assert "CF_API_TOKEN and CF_ZONE_ID" in output
    assert "Automatically apply" not in output
    scan.assert_not_called()
    provider.assert_not_called()


@pytest.mark.parametrize("quiet", [False, True])
@pytest.mark.parametrize("configured", [False, True])
def test_compatibility_credential_and_connection_failures_still_stop(
    monkeypatch, capsys, quiet, configured,
):
    provider = Mock()
    provider.validate_connection.return_value = (False, "Synthetic read denied")
    monkeypatch.setattr(cli, "get_cloudflare_client", lambda: provider if configured else None)

    assert cli.apply_dns_fixes([("example.com", {}, {"severity": "HIGH"})], quiet=quiet) == 0

    provider.generate_fixes.assert_not_called()
    if configured:
        provider.validate_connection.assert_called_once_with()
    else:
        provider.validate_connection.assert_not_called()
    output = capsys.readouterr().out
    if quiet:
        assert output == ""
    else:
        assert "manual-only" in output
        assert "--remediation" in output
        assert "requires Rich" in output
        expected_error = "Synthetic read denied" if configured else "CF_API_TOKEN and CF_ZONE_ID"
        assert expected_error in output
        assert "Auto-Fix" not in output
        assert "&#" not in output


@pytest.mark.parametrize("scan", [
    {},
    {"spf_present": True, "spf_record": "v=spf1 ~all", "dmarc_present": True, "dmarc_policy": "none"},
    {"dmarc_present": True, "dmarc_policy": "quarantine", "mx_hosts": "aspmx.l.google.com"},
    {"scan_incomplete": True},
])
def test_real_generated_recommendations_never_write_and_explain_manual_path(
    monkeypatch, capsys, scan,
):
    # Bypass credential/directory setup; real recommendation generation is local.
    provider = CloudflareDNS.__new__(CloudflareDNS)
    read_check = Mock(return_value=(True, "Synthetic zone read succeeded"))
    request = Mock(side_effect=AssertionError("No provider requests allowed"))
    generate = Mock(wraps=provider.generate_fixes)
    monkeypatch.setattr(provider, "validate_connection", read_check)
    monkeypatch.setattr(provider, "_request", request)
    monkeypatch.setattr(provider, "generate_fixes", generate)
    monkeypatch.setattr(cli, "get_cloudflare_client", lambda: provider)

    assert cli.apply_dns_fixes([("example.com", scan, {"severity": "HIGH"})]) == 0

    read_check.assert_called_once_with()
    generate.assert_called_once_with({**scan, "domain": "example.com"})
    recommendations = CloudflareDNS.generate_fixes(provider, {**scan, "domain": "example.com"})
    assert recommendations
    assert all(item["manual"] and item["auto_fix"] is None for item in recommendations)
    request.assert_not_called()
    output = capsys.readouterr().out
    assert "Cloudflare DNS compatibility workflow (--apply-fix)" in output
    assert "manual-only" in output
    assert "--remediation" in output
    assert "Read-only Cloudflare connection check" in output
    assert "does not verify DNS or Worker write permissions" in output
    assert "Applied 0 fix(es)" in output
    assert "Auto-Fix" not in output
    assert "&#" not in output


@pytest.mark.parametrize("quiet", [False, True])
def test_supplied_compatibility_callbacks_and_applied_count_are_preserved(monkeypatch, capsys, quiet):
    succeeded = Mock(return_value=(True, "Synthetic callback completed"))
    declined = Mock(return_value=(False, "Synthetic guard declined"))
    failed = Mock(side_effect=RuntimeError("Synthetic callback error"))
    provider = Mock()
    provider.validate_connection.return_value = (True, "Synthetic zone read succeeded")
    provider.generate_fixes.return_value = [
        {"type": "MANUAL", "auto_fix": None},
        {"type": "SUCCESS", "auto_fix": succeeded},
        {"type": "DECLINED", "auto_fix": declined},
        {"type": "ERROR", "auto_fix": failed},
    ]
    monkeypatch.setattr(cli, "get_cloudflare_client", lambda: provider)

    count = cli.apply_dns_fixes([
        ("example.com", {}, {"severity": "HIGH"}),
        ("example.net", {}, {"severity": "OK"}),
    ], quiet=quiet)

    assert count == 1
    provider.generate_fixes.assert_called_once_with({"domain": "example.com"})
    for callback in (succeeded, declined, failed):
        callback.assert_called_once_with()
    output = capsys.readouterr().out
    if quiet:
        assert output == ""
    else:
        assert "Synthetic callback completed" in output
        assert "Synthetic guard declined" in output
        assert "Synthetic callback error" in output
        assert "Applied 1 fix(es)" in output
        assert "&#" not in output


@pytest.mark.parametrize("quiet", [False, True])
def test_remediation_displays_manual_advice_without_cloudflare(monkeypatch, tmp_path, capsys, quiet):
    if not cli.HAS_RICH:
        pytest.skip("Rich is not installed")
    args = ["northflux", "--domain", "example.com", "--remediation", "--no-db", "--outdir", str(tmp_path)]
    if quiet:
        args.append("--quiet")
    monkeypatch.setattr(sys, "argv", args)
    scan = Mock(return_value=[("example.com", {}, {"severity": "HIGH", "score": 20, "grade": "F"})])
    provider = Mock()
    guidance = Mock(return_value=[{
        "priority": "HIGH", "description": "Review authorised senders", "example": "Provider-supplied SPF record",
    }])
    monkeypatch.setattr(cli, "scan_domains", scan)
    monkeypatch.setattr(cli, "get_cloudflare_client", provider)
    monkeypatch.setattr(cli, "generate_remediation", guidance)
    monkeypatch.setattr(cli, "print_summary", lambda *args: None)

    cli.main()

    scan.assert_called_once_with(["example.com"], check_starttls=False, save_to_db=False, show_remediation=True)
    provider.assert_not_called()
    assert len(list(tmp_path.glob("northflux_results_*.csv"))) == 1
    assert len(list(tmp_path.glob("northflux_results_*.md"))) == 1
    output = capsys.readouterr().out
    if quiet:
        guidance.assert_not_called()
        assert output == ""
    else:
        guidance.assert_called_once_with({"domain": "example.com"})
        assert "Manual-review recommendations" in output
        assert "These recommendations do not change DNS" in output
        assert "Review authorised senders" in output
