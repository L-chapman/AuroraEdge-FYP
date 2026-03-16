"""
Tests for the database module.

Note: We use tempfile.mkdtemp() with shutil.rmtree(ignore_errors=True)
instead of tempfile.TemporaryDirectory() because on Windows, SQLite WAL
journal files may still be locked when the context manager tries to
clean up, causing PermissionError.
"""
import gc
import shutil
import tempfile
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
