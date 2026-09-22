"""Incomplete network observations must not become confident stored grades."""

import sqlite3

from fastapi.testclient import TestClient

import app.dashboard as dashboard
from app.database import NorthFluxDatabase


def test_incomplete_results_are_saved_without_grades_or_average_contamination(tmp_path):
    database = NorthFluxDatabase(tmp_path / "incomplete.db")
    complete = {"domain": "example.com", "spf_present": True}
    incomplete = {**complete, "scan_incomplete": True, "notes": "DNS lookup timed out"}
    evaluation = {"score": 80, "grade": "B", "severity": "WARN"}
    try:
        database.write_scan_results([("example.com", complete, evaluation)], notes="Complete", manage_domains=True)
        database.write_scan_results([("example.com", incomplete, evaluation)], notes="Interrupted", update_managed=True)
        # Clocks can produce identical timestamps for fast consecutive saves.
        database.conn.execute("UPDATE results SET scanned_at = '2026-09-22T20:00:00+00:00'")
        database.conn.commit()
        history = database.get_domain_history("example.com")
        assert history[0]["score"] is None
        assert history[0]["grade"] is None
        assert history[0]["scan_incomplete"] == 1
        assert history[1]["score"] == 80
        assert database.get_statistics()["score_stats"]["avg_score"] == 80
        managed = database.get_managed_domains()[0]
        assert managed["last_scan_incomplete"] == 1
        assert managed["last_score"] is None
        assert managed["last_grade"] is None
        assert managed["previous_score"] == 80
        database.write_scan_results([("example.com", complete, evaluation)], notes="Recovered", update_managed=True)
        assert database.get_managed_domains()[0]["last_scan_incomplete"] == 0
        assert database.get_domains_by_grade("B")[0]["latest_score"] == 80
    finally:
        database.close()


def test_incomplete_first_scan_can_be_followed_by_a_complete_scan(tmp_path):
    database = NorthFluxDatabase(tmp_path / "first.db")
    try:
        scan = {"domain": "example.com", "scan_incomplete": True}
        evaluation = {"score": 10, "grade": "F", "severity": "ERROR"}
        database.write_scan_results([("example.com", scan, evaluation)], notes="Incomplete", manage_domains=True)
        assert database.get_statistics()["score_stats"]["avg_score"] is None
        database.write_scan_results([("example.com", {"domain": "example.com"},
            {"score": 90, "grade": "A", "severity": "OK"})], notes="Complete", update_managed=True)
        assert database.get_domains_by_grade("A")[0]["latest_score"] == 90
    finally:
        database.close()


def test_existing_database_gains_flags_without_losing_results(tmp_path):
    path = tmp_path / "legacy.db"
    database = NorthFluxDatabase(path)
    database.write_scan_results([("example.com", {}, {"score": 90, "grade": "A"})], notes="Legacy", manage_domains=True)
    database.close()
    with sqlite3.connect(path) as connection:
        # Remove the new fields to represent an installation from the prior release.
        for table, column in [("results", "scan_incomplete"), ("managed_domains", "last_scan_incomplete")]:
            fields = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            if column in fields:
                connection.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    database = NorthFluxDatabase(path)
    try:
        assert database.get_domain_history("example.com")[0]["scan_incomplete"] == 0
        assert database.get_managed_domains()[0]["last_scan_incomplete"] == 0
        assert database.get_statistics()["total_results"] == 1
        database.delete_domain_history("example.com")
        assert database.get_managed_domains()[0]["last_scan_incomplete"] == 0
    finally:
        database.close()


def test_dashboard_exposes_incomplete_state_without_a_failing_grade(tmp_path, monkeypatch):
    database = NorthFluxDatabase(tmp_path / "api.db")
    monkeypatch.setattr(dashboard, "get_database", lambda: database)
    monkeypatch.setenv("DASH_TOKEN", "")
    monkeypatch.delenv("NORTHFLUX_ENV", raising=False)
    try:
        database.write_scan_results([("example.com", {"scan_incomplete": True},
            {"score": 10, "grade": "F", "severity": "ERROR"})], notes="Timed out", manage_domains=True)
        response = TestClient(dashboard.app).get("/api/v1/dashboard")
        assert response.status_code == 200
        payload = response.json()
        assert payload["domains"][0]["last_scan_incomplete"] is True
        assert payload["domains"][0]["last_grade"] is None
        assert payload["stats"]["failing_domains"] == 0
        assert payload["stats"]["score_stats"]["avg_score"] is None
    finally:
        database.close()
