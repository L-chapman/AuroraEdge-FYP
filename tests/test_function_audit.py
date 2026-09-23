"""Second-pass API/storage regressions; no real DNS, accounts or user data."""

import json
import sqlite3
import time
import threading
import asyncio
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import app.dashboard as dashboard
from app.database import NorthFluxDatabase


@pytest.fixture
def operator(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "")
    monkeypatch.setenv("NORTHFLUX_ENV", "development")
    db = NorthFluxDatabase(tmp_path / "operator.db")
    monkeypatch.setattr(dashboard, "get_database", lambda: db)
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "HAS_SCANNER", True)
    monkeypatch.setattr(dashboard, "_apply_cf_settings", lambda db: None)
    monkeypatch.setattr(dashboard, "REPORTS_ROOT", tmp_path / "reports")
    monkeypatch.setattr(dashboard, "REPORTS", tmp_path / "reports" / "indexed")
    # Do not start background work for the actual requests.
    client = TestClient(dashboard.app, raise_server_exceptions=False)
    try:
        yield client, db
    finally:
        client.close()
        db.close()


def save(db, domain="example.com", result=None, evaluation=None):
    db.write_scan_results(
        [(domain, result or {}, evaluation or {"grade": "B", "score": 75, "severity": "WARN"})],
        notes="Isolated audit test",
    )


def test_search_handles_incomplete_results_without_crashing(operator):
    client, db = operator
    save(db, result={"scan_incomplete": True})
    response = client.get("/api/search", params={"grade": "B"})
    assert response.status_code == 200
    assert response.json()["results"] == []
    response = client.get("/api/search")
    assert response.status_code == 200
    assert response.json()["results"][0]["score"] is None
    assert client.get("/api/search?min_score=0").json()["results"] == []


def test_search_does_not_resurrect_deleted_data_from_csv(operator, monkeypatch):
    client, _ = operator
    csv_reader = Mock(return_value=[{"domain": "deleted.example", "score": "100"}])
    monkeypatch.setattr(dashboard, "_latest_pair", lambda: ("stale.csv", None))
    monkeypatch.setattr(dashboard, "load_csv", csv_reader)
    assert client.get("/api/search").json()["results"] == []
    csv_reader.assert_not_called()


def test_search_reports_storage_failure_not_empty_success(operator, monkeypatch):
    client, db = operator
    monkeypatch.setattr(db, "get_latest_results", Mock(side_effect=sqlite3.OperationalError("unavailable")))
    assert client.get("/api/search").status_code == 500


@pytest.mark.parametrize("route", ["/api/domain/example.com", "/api/history/example.com", "/api/search"])
def test_saved_results_keep_extended_evidence_and_authoritative_grade(operator, route):
    client, db = operator
    save(db, result={"scan_incomplete": True, "null_mx": True, "bimi_logo": "https://example.com/logo.svg"})
    response = client.get(route)
    assert response.status_code == 200
    body = response.json()
    row = body["result"] if "result" in body else (body.get("history") or body["results"])[0]
    assert row["null_mx"] is True
    assert row["bimi_logo"] == "https://example.com/logo.svg"
    assert row["grade"] is None
    assert row["score"] is None


def test_failed_individual_save_is_rolled_back(operator):
    _, db = operator
    scan_id = db.start_scan()
    db.conn.execute("""CREATE TRIGGER reject_domain BEFORE INSERT ON domains
                       BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
    db.conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        db.save_result(scan_id, "example.com", {}, {"grade": "B", "score": 75})
    db.set_setting("org_name", "Unrelated later write")
    assert db.get_latest_results() == []
    assert db.conn.in_transaction is False


def test_history_deletion_preserves_unrelated_in_progress_scan(operator):
    _, db = operator
    save(db)
    in_progress = db.start_scan(notes="Unrelated CLI work")
    db.delete_domain_history("example.com")
    assert in_progress in {row["scan_id"] for row in db.get_scans()}
    db.save_result(in_progress, "other.example", {}, {"grade": "B", "score": 75})


def test_history_deletion_recounts_surviving_batch(operator):
    _, db = operator
    db.write_scan_results([
        ("example.com", {}, {"grade": "B", "score": 75}),
        ("other.example", {}, {"grade": "B", "score": 75}),
    ], notes="Batch")
    db.delete_domain_history("example.com")
    assert db.get_scans()[0]["domain_count"] == 1


def test_open_development_mode_rejects_foreign_browser_writes(operator):
    client, db = operator
    response = client.post("/api/settings", content=json.dumps({"automatic_remediation": True}),
                           headers={"Origin": "https://unrelated.example", "Content-Type": "text/plain"})
    assert response.status_code == 403
    assert db.get_setting("automatic_remediation") == ""


@pytest.mark.parametrize("scores", [["NaN"], ["Infinity"], ["-Infinity"], [None], [""], [101], [-1]])
def test_legacy_score_summary_ignores_unknown_or_invalid_scores(scores):
    rows = [{"score": score} for score in scores] + [{"score": "80"}]
    assert dashboard._score_stats(rows) == {"avg": 80.0, "min": 80.0, "max": 80.0, "count": 1}


def test_legacy_score_summary_ignores_incomplete_provisional_grade():
    rows = [{"score": "100", "grade": "A+", "scan_incomplete": "True"}, {"score": "80", "grade": "B"}]
    assert dashboard._score_stats(rows)["avg"] == 80
    assert dashboard._grade_counts(rows)["A+"] == 0


@pytest.fixture
def provider(operator, monkeypatch):
    _, db = operator
    cf = Mock()
    cf.validate_connection.return_value = (True, "Connected")
    cf.verify_domain_ownership.return_value = (True, "Owned")
    writer = Mock(return_value=(True, "Submitted"))
    cf.generate_fixes.return_value = [{"type": "DMARC", "auto_fix": writer}]
    cf.get_txt_record.return_value = None
    monkeypatch.setattr(dashboard, "HAS_DNS_FIX", True)
    monkeypatch.setattr(dashboard, "get_cloudflare_client", lambda: cf)
    monkeypatch.setattr(dashboard, "scan_domain", Mock(return_value={"domain": "example.com"}))
    monkeypatch.setattr(dashboard, "evaluate", lambda row: {"grade": "F", "score": 30, "severity": "HIGH"})
    monkeypatch.setattr(time, "sleep", lambda _: None)
    return cf, writer, db


@pytest.mark.parametrize("action", ["disable", "remove", "clear"])
def test_onboarding_rechecks_operator_stop_after_provider_reads(operator, provider, action):
    client, db = operator
    cf, writer, _ = provider
    db.set_setting("automatic_remediation", "true")

    def provider_read():
        if action == "disable":
            db.set_setting("automatic_remediation", "false")
        elif action == "remove":
            db.remove_managed_domain("example.com")
        else:
            db.clear_scan_data()
        return True, "Connected"

    cf.validate_connection.side_effect = provider_read
    response = client.post("/api/managed-domains", json={"domain": "example.com", "automatic_remediation": True})
    assert response.status_code in {200, 409}
    writer.assert_not_called()


def test_onboarding_incomplete_post_fix_scan_is_ungraded(operator, monkeypatch):
    client, db = operator
    db.set_setting("automatic_remediation", "true")
    monkeypatch.setattr(dashboard, "scan_domain", Mock(side_effect=[{}, {"scan_incomplete": True}]))
    monkeypatch.setattr(dashboard, "evaluate", lambda row: {"grade": "A+", "score": 100, "severity": "OK"})
    monkeypatch.setattr(dashboard, "_auto_fix_domain", Mock(return_value={"applied": [{"type": "DMARC"}]}))
    async def no_wait(_):
        pass
    monkeypatch.setattr(dashboard.asyncio, "sleep", no_wait)
    response = client.post("/api/managed-domains", json={"domain": "example.com", "automatic_remediation": True})
    post = response.json()["post_fix_scan"]
    assert post["scan_incomplete"] is True
    assert post.get("grade") is None
    assert post.get("score") is None
    assert post.get("improved", False) is False


def test_manual_fix_stops_after_history_clear_during_provider_read(provider):
    cf, writer, db = provider
    cf.validate_connection.side_effect = lambda: (db.clear_scan_data() or True, "Connected")
    result = dashboard._apply_fix_sync("example.com", None)
    writer.assert_not_called()
    assert result["status"] == "failed"
    assert "cancel" in result["failed"][0]["message"].lower()


def test_manual_fix_does_not_use_stale_credentials_after_settings_failure(provider, monkeypatch):
    cf, writer, _ = provider
    monkeypatch.setattr(dashboard, "_apply_cf_settings", Mock(side_effect=sqlite3.OperationalError("read failed")))
    with pytest.raises(dashboard.HTTPException) as error:
        dashboard._apply_fix_sync("example.com", None)
    assert error.value.status_code == 503
    cf.validate_connection.assert_not_called()
    writer.assert_not_called()


def test_retired_demo_endpoint_has_no_database_or_provider_side_effect(operator, monkeypatch):
    client, db = operator
    monkeypatch.setenv("NORTHFLUX_DEMO_MODE", "true")
    response = client.post("/api/demo/reset", json={})
    assert response.status_code == 410
    assert db.get_managed_domains() == []


def test_download_rejects_unrelated_files_and_disallows_caching(operator):
    client, _ = operator
    dashboard.REPORTS.mkdir(parents=True)
    (dashboard.REPORTS / "private.env").write_text("synthetic secret", encoding="utf-8")
    (dashboard.REPORTS / "northflux_results_sample.csv").write_text("domain\nexample.com\n", encoding="utf-8")
    assert client.get("/download/private.env").status_code == 404
    response = client.get("/download/northflux_results_sample.csv")
    assert response.status_code == 200
    assert "no-store" in response.headers["cache-control"]


def test_report_discovery_ignores_directories(operator):
    client, _ = operator
    (dashboard.REPORTS / "northflux_results_directory.csv").mkdir(parents=True)
    assert dashboard.list_csvs() == []
    assert client.get("/download/latest").status_code == 404


@pytest.mark.parametrize("suffix", ["csv", "md"])
def test_latest_report_cannot_follow_an_external_file_link(operator, tmp_path, suffix):
    client, _ = operator
    dashboard.REPORTS.mkdir(parents=True)
    external = tmp_path / "private-data.txt"
    external.write_text("synthetic private content", encoding="utf-8")
    if suffix == "md":
        (dashboard.REPORTS / "northflux_results_sample.csv").write_text("domain\nexample.com\n", encoding="utf-8")
    try:
        (dashboard.REPORTS / f"northflux_results_sample.{suffix}").symlink_to(external)
    except OSError:
        pytest.skip("File symlink creation is unavailable on this host")
    assert client.get(f"/download/latest?kind={suffix}").status_code == 404


def test_manual_and_automatic_changes_cannot_overlap_for_same_domain(provider):
    cf, writer, _ = provider
    entered = threading.Event()
    release = threading.Event()
    outcomes = []

    def slow_validation():
        entered.set()
        assert release.wait(5), "test failed to release fake provider"
        return True, "Connected"

    cf.validate_connection.side_effect = slow_validation
    worker = threading.Thread(target=lambda: outcomes.append(dashboard._apply_fix_sync("example.com", None)))
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(dashboard.HTTPException) as error:
            dashboard._auto_fix_domain("EXAMPLE.COM", {})
        assert error.value.status_code == 409
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert len(outcomes) == 1
    assert writer.call_count == 1


def test_failed_change_releases_domain_slot(provider):
    cf, _, _ = provider
    cf.validate_connection.side_effect = [(False, "offline"), (True, "Connected")]
    with pytest.raises(dashboard.HTTPException):
        dashboard._apply_fix_sync("example.com", None)
    assert dashboard._apply_fix_sync("example.com", None)["status"] == "success"


@pytest.mark.parametrize("incomplete", [False, True])
def test_real_generated_guidance_is_manual_review_not_failed(provider, monkeypatch, incomplete):
    from app.dns_fix import CloudflareDNS

    cf, writer, _ = provider
    cf.generate_fixes.side_effect = lambda scan: CloudflareDNS.generate_fixes(cf, scan)
    cf.detect_email_provider.return_value = {"provider": "unknown"}
    monkeypatch.setattr(dashboard, "scan_domain", Mock(return_value={"scan_incomplete": incomplete}))
    result = dashboard._apply_fix_sync("example.com", None)
    assert result["status"] == "manual_review"
    assert result["manual_actions"]
    assert result["applied"] == []
    assert result["failed"] == []
    writer.assert_not_called()
    if incomplete:
        assert result["grade"] is None
        assert result["score"] is None
        assert result["pre_fix_grade"] is None
        assert result["pre_fix_score"] is None


def test_event_stream_stops_after_session_revocation(monkeypatch):
    from starlette.requests import Request

    token = "synthetic-stream-operator-token"
    monkeypatch.setenv("DASH_TOKEN", token)
    monkeypatch.setattr(dashboard, "_sessions", {})
    session, _ = dashboard._create_session(token)
    request = Request({
        "type": "http", "method": "GET", "path": "/api/stream", "query_string": b"",
        "headers": [(b"cookie", f"northflux_session={session}".encode())],
        "server": ("testserver", 80), "client": ("testclient", 1), "scheme": "http",
    })
    reads = Mock(return_value=(False, 0.0))
    monkeypatch.setattr(dashboard, "_check_for_updates", reads)
    async def no_wait(_):
        pass
    monkeypatch.setattr(dashboard.asyncio, "sleep", no_wait)

    async def exercise():
        response = await dashboard.stream_updates(request)
        iterator = response.body_iterator
        assert "heartbeat" in await anext(iterator)
        dashboard._sessions.pop(session)
        assert "session_expired" in await anext(iterator)
        with pytest.raises(StopAsyncIteration):
            await anext(iterator)

    asyncio.run(exercise())
    assert reads.call_count == 1
