"""Failure-path checks for scheduled work and post-change verification.

All provider calls, network scans and waits are synthetic.
"""

import asyncio
import time
from unittest.mock import Mock

import pytest

import app.dashboard as dashboard
from app.database import NorthFluxDatabase


@pytest.fixture
def operator(tmp_path, monkeypatch):
    database = NorthFluxDatabase(tmp_path / "operator.db")
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "HAS_SCANNER", True)
    monkeypatch.setattr(dashboard, "HAS_DNS_FIX", True)
    monkeypatch.setattr(dashboard, "get_database", lambda: database)
    monkeypatch.setattr(dashboard, "_apply_cf_settings", lambda db: None)
    monkeypatch.setattr(dashboard, "evaluate", lambda scan: {
        "score": scan["test_score"], "grade": "A" if scan["test_score"] >= 85 else "F",
        "severity": "WARN", "violation_count": 1,
    })
    provider = Mock()
    provider.validate_connection.return_value = (True, "Connected")
    provider.verify_domain_ownership.return_value = (True, "Owned")
    provider.generate_fixes.return_value = [
        {"type": "DMARC", "auto_fix": lambda: (True, "Submitted")}
    ]
    provider.get_txt_record.return_value = {"content": "v=DMARC1; p=reject"}
    monkeypatch.setattr(dashboard, "get_cloudflare_client", lambda: provider)
    monkeypatch.setattr(time, "sleep", lambda _: None)
    try:
        yield database, provider
    finally:
        database.close()


def observation(score, incomplete=False):
    return {"domain": "example.com", "test_score": score,
            "scan_incomplete": incomplete, "notes": "Timeout" if incomplete else ""}


def test_partial_high_score_cannot_be_claimed_as_verified(operator, monkeypatch):
    database, _ = operator
    partial = {**observation(95, True), "spf_all": "-all", "dmarc_policy": "reject",
               "dmarc_pct": 100, "mta_sts_present": True}
    scanner = Mock(side_effect=[observation(40)] + [partial] * 6)
    monkeypatch.setattr(dashboard, "scan_domain", scanner)
    result = dashboard._apply_fix_sync("example.com", None)
    assert result["status"] == "partial"
    assert result["verification_status"] == "incomplete"
    assert "incomplete" in result["verification"].lower()
    assert "DNS changes verified" not in result["verification"]
    assert result["score"] is None
    assert result["grade"] is None
    assert result["history_saved"] is True
    assert database.get_domain_history("example.com")[0]["score"] is None
    assert scanner.call_count == 7


def test_latest_verification_is_not_replaced_by_a_better_earlier_score(operator, monkeypatch):
    database, _ = operator
    scanner = Mock(side_effect=[observation(50), observation(90)] + [observation(30)] * 5)
    monkeypatch.setattr(dashboard, "scan_domain", scanner)
    result = dashboard._apply_fix_sync("example.com", None)
    assert result["score"] == 30
    assert "lower" in result["verification"].lower()
    assert database.get_domain_history("example.com")[0]["score"] == 30


def test_late_verification_timeout_cannot_reuse_a_confident_earlier_grade(operator, monkeypatch):
    database, _ = operator
    scanner = Mock(side_effect=[observation(50), observation(90)] + [observation(20, True)] * 5)
    monkeypatch.setattr(dashboard, "scan_domain", scanner)
    result = dashboard._apply_fix_sync("example.com", None)
    assert result["score"] is None
    assert result["verification_status"] == "incomplete"
    assert database.get_domain_history("example.com")[0]["scan_incomplete"] == 1


def test_verification_exception_reports_submitted_but_unverified(operator, monkeypatch):
    _, _provider = operator
    scanner = Mock(side_effect=[observation(50), RuntimeError("synthetic failure")])
    monkeypatch.setattr(dashboard, "scan_domain", scanner)
    result = dashboard._apply_fix_sync("example.com", None)
    assert result["status"] == "partial"
    assert result["verification_status"] == "failed"
    assert result["score"] is None
    assert result["history_saved"] is False


def run_one_monitor_cycle(monkeypatch):
    async def fake_sleep(delay):
        if delay > 2:
            raise asyncio.CancelledError()
    monkeypatch.setattr(dashboard.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(dashboard._monitoring_loop())


@pytest.mark.parametrize("stop_action", ["disable", "remove", "clear"])
def test_monitor_stops_after_operator_changes_state_during_scan(operator, monkeypatch, stop_action):
    database, _ = operator
    database.set_settings({"monitoring_enabled": "true", "automatic_remediation": "true"})
    database.add_managed_domain("example.com")
    database.add_managed_domain("other.example.com")
    def scan(*args):
        if stop_action == "disable":
            database.set_setting("monitoring_enabled", "false")
        elif stop_action == "remove":
            database.remove_managed_domain("example.com")
        else:
            database.clear_scan_data()
        return observation(30)
    scanner = Mock(side_effect=scan)
    fixer = Mock(return_value={"applied": [], "failed": []})
    monkeypatch.setattr(dashboard, "scan_domain", scanner)
    monkeypatch.setattr(dashboard, "_auto_fix_domain", fixer)
    run_one_monitor_cycle(monkeypatch)
    assert scanner.call_count == 1
    fixer.assert_not_called()
    assert database.get_statistics()["total_results"] == 0


def test_monitor_keeps_partial_scan_as_ungraded_and_never_fixes(operator, monkeypatch):
    database, _ = operator
    database.set_settings({"monitoring_enabled": "true", "automatic_remediation": "true"})
    database.add_managed_domain("example.com")
    monkeypatch.setattr(dashboard, "scan_domain", Mock(return_value=observation(30, True)))
    fixer = Mock()
    monkeypatch.setattr(dashboard, "_auto_fix_domain", fixer)
    run_one_monitor_cycle(monkeypatch)
    fixer.assert_not_called()
    assert database.get_domain_history("example.com")[0]["score"] is None
    assert database.get_alerts()[0]["alert_type"] == "scan_incomplete"


@pytest.mark.parametrize("stop_action", ["monitoring", "remediation", "remove"])
def test_monitor_rechecks_stop_after_slow_provider_validation(operator, monkeypatch, stop_action):
    database, provider = operator
    database.set_settings({"monitoring_enabled": "true", "automatic_remediation": "true"})
    database.add_managed_domain("example.com")
    def validate():
        if stop_action == "remove":
            database.remove_managed_domain("example.com")
        else:
            database.set_setting("monitoring_enabled" if stop_action == "monitoring" else "automatic_remediation", "false")
        return True, "Connected"
    provider.validate_connection.side_effect = validate
    writer = Mock(return_value=(True, "Submitted"))
    provider.generate_fixes.return_value = [{"type": "DMARC", "auto_fix": writer}]
    monkeypatch.setattr(dashboard, "scan_domain", Mock(return_value=observation(30)))
    run_one_monitor_cycle(monkeypatch)
    provider.validate_connection.assert_called_once()
    writer.assert_not_called()


def test_connection_probe_does_not_claim_write_permissions(operator, monkeypatch):
    _, provider = operator
    provider.zone_name = "example.com"
    provider.api_token = "synthetic-provider-token"
    provider.base_url = "https://api.example.invalid/records"
    provider.get_account_id.return_value = "synthetic-account"
    response = Mock()
    response.json.return_value = {"success": True}
    import requests
    monkeypatch.setattr(requests, "get", Mock(return_value=response))
    result = dashboard.api_test_cloudflare()
    assert result["permissions"]["dns_edit"] is None
    assert result["permissions"]["dns_read"] is True
    assert result["permissions"]["workers_edit"] is None
    assert "write permission is not tested" in result["message"].lower()
