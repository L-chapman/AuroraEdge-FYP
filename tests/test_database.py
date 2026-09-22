"""
Tests for the database module.

Note: We use tempfile.mkdtemp() with shutil.rmtree(ignore_errors=True)
instead of tempfile.TemporaryDirectory() because on Windows, SQLite WAL
journal files may still be locked when the context manager tries to
clean up, causing PermissionError.
"""
import gc
import shutil
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest


def _make_tmp_db():
    """Create a temp dir + DB path. Returns (db, tmpdir_path)."""
    from app.database import AuroraDatabase

    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "test.db"
    return AuroraDatabase(db_path), tmpdir


def _cleanup(db, tmpdir):
    """Close the database and remove the temp directory (best-effort)."""
    db.close()
    gc.collect()  # Release any lingering references (helps on Windows)
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_database_init_and_save():
    """Test database initialization and result saving."""
    db, tmpdir = _make_tmp_db()
    try:
        # Start a scan
        scan_id = db.start_scan(notes="Test scan")
        assert scan_id is not None
        assert len(scan_id) > 0

        # Save a result
        result = {
            "spf_present": True,
            "mx_present": True,
            "dmarc_present": True,
            "dmarc_policy": "reject",
            "dkim_present": True,
            "mta_sts_present": True,
            "mta_sts_mode": "enforce",
            "tls_rpt_present": True,
        }
        evaluation = {
            "severity": "OK",
            "score": 100,
            "grade": "A+",
            "violations": "",
            "violation_count": 0,
        }

        db.save_result(scan_id, "example.com", result, evaluation)
        db.complete_scan(scan_id, 1)

        # Query results
        results = db.get_latest_results()
        assert len(results) == 1
        assert results[0]["domain"] == "example.com"
        assert results[0]["score"] == 100

        # Query domain history
        history = db.get_domain_history("example.com")
        assert len(history) == 1

        # FastAPI can request the latest result and its history at the same
        # time. The shared SQLite connection must serialise those reads.
        with ThreadPoolExecutor(max_workers=8) as pool:
            concurrent_history = list(
                pool.map(
                    lambda _index: db.get_domain_history("example.com"),
                    range(512),
                )
            )
        assert all(len(rows) == 1 for rows in concurrent_history)

        # Query scans
        scans = db.get_scans()
        assert len(scans) == 1
        assert scans[0]["scan_id"] == scan_id

        # Query statistics
        stats = db.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["unique_domains"] == 1
    finally:
        _cleanup(db, tmpdir)


def test_database_multiple_scans():
    """Test saving multiple scans for the same domain."""
    db, tmpdir = _make_tmp_db()
    try:
        # First scan with low score
        scan_id1 = db.start_scan()
        result1 = {"spf_present": False, "mx_present": True, "dmarc_present": False}
        eval1 = {"severity": "HIGH", "score": 50, "grade": "D", "violations": "R2,R4", "violation_count": 2}
        db.save_result(scan_id1, "test.com", result1, eval1)
        db.complete_scan(scan_id1, 1)

        # Second scan with better score
        scan_id2 = db.start_scan()
        result2 = {"spf_present": True, "mx_present": True, "dmarc_present": True}
        eval2 = {"severity": "OK", "score": 90, "grade": "A", "violations": "", "violation_count": 0}
        db.save_result(scan_id2, "test.com", result2, eval2)
        db.complete_scan(scan_id2, 1)

        # Check domain history shows both
        history = db.get_domain_history("test.com")
        assert len(history) == 2

        # Check improvement candidates
        candidates = db.get_improvement_candidates(max_score=60)
        # Latest score is 90, so should not appear
        assert len(candidates) == 0
    finally:
        _cleanup(db, tmpdir)


def test_score_zero_tracking():
    """Regression test: worst_score of 0 must not be lost on rescan.

    Previously, ``min(existing['worst_score'] or 100, score)`` treated
    0 as falsy and defaulted to 100, corrupting the historical minimum.
    """
    db, tmpdir = _make_tmp_db()
    try:
        base_result = {"spf_present": False, "mx_present": False, "dmarc_present": False}

        # First scan: score 0
        sid1 = db.start_scan()
        db.save_result(sid1, "zero.test", base_result, {
            "severity": "CRITICAL", "score": 0, "grade": "F",
            "violations": "R1,R2,R3", "violation_count": 3,
        })
        db.complete_scan(sid1, 1)

        # Second scan: score 50
        sid2 = db.start_scan()
        db.save_result(sid2, "zero.test", base_result, {
            "severity": "HIGH", "score": 50, "grade": "D",
            "violations": "R2", "violation_count": 1,
        })
        db.complete_scan(sid2, 1)

        # Worst score must still be 0, not 50
        cur = db.conn.cursor()
        cur.execute("SELECT best_score, worst_score FROM domains WHERE domain = ?", ("zero.test",))
        row = cur.fetchone()
        assert row["worst_score"] == 0, f"worst_score should be 0, got {row['worst_score']}"
        assert row["best_score"] == 50, f"best_score should be 50, got {row['best_score']}"
    finally:
        _cleanup(db, tmpdir)


def test_clear_invalidates_inflight_scan_persistence():
    """A scan started before a clear must not repopulate deleted data."""
    db, tmpdir = _make_tmp_db()
    try:
        generation = db.get_data_generation()
        db.clear_scan_data()
        saved = db.write_scan_results(
            [("example.com", {"spf_present": True}, {
                "severity": "INFO", "score": 80, "grade": "B",
                "violations": "", "violation_count": 0,
            })],
            notes="stale scan",
            expected_generation=generation,
        )
        assert saved is False
        assert db.get_domain_history("example.com") == []
        assert db.get_scans() == []
    finally:
        _cleanup(db, tmpdir)


def test_deleting_history_resets_managed_domain_metadata():
    """A monitored domain must not retain a deleted grade or score."""
    db, tmpdir = _make_tmp_db()
    try:
        generation = db.get_data_generation()
        assert db.write_scan_results(
            [("example.com", {"spf_present": True}, {
                "severity": "INFO", "score": 95, "grade": "A",
                "violations": "", "violation_count": 0,
            })],
            notes="managed baseline",
            expected_generation=generation,
            save_history=True,
            manage_domains=True,
            update_managed=True,
            managed_notes="Primary domain",
        )
        assert db.delete_domain_history("example.com") == 1
        managed = db.get_managed_domains()
        assert len(managed) == 1
        assert managed[0]["last_scan_at"] is None
        assert managed[0]["last_grade"] is None
        assert managed[0]["last_score"] is None
        assert db.get_domain_history("example.com") == []
        assert db.get_scans() == []
    finally:
        _cleanup(db, tmpdir)


def test_deleting_history_invalidates_inflight_scan_persistence():
    """An earlier scan must not recreate history after operator deletion."""
    db, tmpdir = _make_tmp_db()
    try:
        generation = db.get_data_generation()
        assert db.delete_domain_history("example.com") == 0
        assert db.write_scan_results(
            [("example.com", {"spf_present": True}, {
                "severity": "INFO", "score": 80, "grade": "B",
                "violations": "", "violation_count": 0,
            })],
            notes="stale scan",
            expected_generation=generation,
        ) is False
        assert db.get_domain_history("example.com") == []
    finally:
        _cleanup(db, tmpdir)


def test_removing_managed_domain_invalidates_inflight_reenrolment():
    """An earlier enrolment request must not undo an operator removal."""
    db, tmpdir = _make_tmp_db()
    try:
        entry = ("example.com", {"spf_present": True}, {
            "severity": "INFO", "score": 80, "grade": "B",
            "violations": "", "violation_count": 0,
        })
        assert db.write_scan_results(
            [entry],
            notes="initial enrolment",
            save_history=False,
            manage_domains=True,
        )
        generation = db.get_data_generation()
        assert db.remove_managed_domain("example.com") is True

        assert db.write_scan_results(
            [entry],
            notes="stale enrolment",
            expected_generation=generation,
            save_history=False,
            manage_domains=True,
        ) is False
        assert db.get_managed_domains() == []
        assert db.get_managed_domains(active_only=False)[0]["is_active"] == 0
    finally:
        _cleanup(db, tmpdir)


def test_atomic_scan_write_rolls_back_non_sqlite_failure():
    """Data-shape errors cannot leave a partial scan transaction open."""
    db, tmpdir = _make_tmp_db()
    try:
        with pytest.raises(TypeError):
            db.write_scan_results(
                [("example.com", {"unexpected": object()}, {
                    "severity": "INFO", "score": 80, "grade": "B",
                    "violations": "", "violation_count": 0,
                })],
                notes="invalid scanner payload",
            )
        assert db.get_domain_history("example.com") == []
        assert db.get_scans() == []
    finally:
        _cleanup(db, tmpdir)


def test_clear_scan_data_rolls_back_as_one_transaction():
    """A failed clear cannot leave only part of the operator's data deleted."""
    db, tmpdir = _make_tmp_db()
    try:
        assert db.write_scan_results(
            [("example.com", {"spf_present": True}, {
                "severity": "INFO", "score": 80, "grade": "B",
                "violations": "", "violation_count": 0,
            })],
            notes="baseline",
        )
        db.conn.execute(
            """CREATE TRIGGER reject_domain_delete
               BEFORE DELETE ON domains
               BEGIN
                   SELECT RAISE(ABORT, 'blocked by test');
               END"""
        )
        db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match="blocked by test"):
            db.clear_scan_data()

        assert len(db.get_domain_history("example.com")) == 1
        assert len(db.get_scans()) == 1
    finally:
        _cleanup(db, tmpdir)


def test_delete_domain_history_rolls_back_as_one_transaction():
    """A failed domain deletion cannot leave its result rows half-removed."""
    db, tmpdir = _make_tmp_db()
    try:
        assert db.write_scan_results(
            [("example.com", {"spf_present": True}, {
                "severity": "INFO", "score": 80, "grade": "B",
                "violations": "", "violation_count": 0,
            })],
            notes="baseline",
        )
        db.conn.execute(
            """CREATE TRIGGER reject_one_domain_delete
               BEFORE DELETE ON domains
               WHEN OLD.domain = 'example.com'
               BEGIN
                   SELECT RAISE(ABORT, 'blocked by test');
               END"""
        )
        db.conn.commit()

        with pytest.raises(sqlite3.IntegrityError, match="blocked by test"):
            db.delete_domain_history("example.com")

        assert len(db.get_domain_history("example.com")) == 1
        assert len(db.get_scans()) == 1
    finally:
        _cleanup(db, tmpdir)
