"""
Backend Quality & Assurance Tests &#8212; Stage 15
Covers improvements from the backend audit:
  - Domain validation (scanner.is_valid_domain)
  - Database thread safety, WAL mode, context manager, composite index
  - Scanner: exp= not counted, socket safety, invalid domain handling
  - Rules: spf_lookups ValueError guard, DKIM :test detection,
           expanded remediations, ERROR severity in SEVERITY_ORDER
  - DNS fix: _extract_error safety, ownership enforcement on every fix method
  - Analysis: correct median, filename-based CSV sort
  - CLI: csv.writer output, CRITICAL severity for errors
"""
import csv
import io
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Domain&#8208;validation tests
# ---------------------------------------------------------------------------

class TestDomainValidation:
    """Verify the new is_valid_domain helper in scanner.py."""

    def test_valid_domains(self):
        from app.scanner import is_valid_domain
        for d in ("example.com", "sub.example.co.uk", "a-b.c.d"):
            assert is_valid_domain(d), f"{d} should be valid"

    def test_invalid_domains(self):
        from app.scanner import is_valid_domain
        for bad in ("", "http://example.com", "127.0.0.1", "-bad.com",
                     "no_underscores.com", "just-a-word", ".leading-dot.com"):
            assert not is_valid_domain(bad), f"{bad} should be invalid"

    def test_scan_domain_rejects_invalid(self):
        from app.scanner import scan_domain
        result = scan_domain("not-a-domain")
        assert result["notes"] == "Invalid domain format"
        assert result["spf_present"] is False


# ---------------------------------------------------------------------------
# Database improvements
# ---------------------------------------------------------------------------

class TestDatabaseImprovements:
    """Thread safety, WAL, composite index, context manager."""

    def _make_db(self, tmpdir):
        from app.database import AuroraDatabase
        return AuroraDatabase(Path(tmpdir) / "test.db")

    def test_wal_mode_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = self._make_db(tmpdir)
            cur = db.conn.execute("PRAGMA journal_mode")
            mode = cur.fetchone()[0].lower()
            assert mode == "wal", f"Expected WAL, got {mode}"
            db.close()

    def test_composite_index_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = self._make_db(tmpdir)
            cur = db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_results_domain_scanned'"
            )
            assert cur.fetchone() is not None, "Composite index missing"
            db.close()

    def test_alerts_created_at_index_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = self._make_db(tmpdir)
            cur = db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='idx_alerts_created'"
            )
            assert cur.fetchone() is not None, "Alerts created_at index missing"
            db.close()

    def test_context_manager(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from app.database import AuroraDatabase
            with AuroraDatabase(Path(tmpdir) / "test.db") as db:
                scan_id = db.start_scan(notes="ctx test")
                assert scan_id
            # After exiting, conn should be None
            assert db.conn is None

    def test_thread_safe_singleton(self):
        """Two threads calling get_database should get the same instance."""
        import app.database as dbmod
        dbmod._db_instance = None  # reset

        results = []
        with tempfile.TemporaryDirectory() as tmpdir:
            def worker():
                results.append(
                    dbmod.get_database(Path(tmpdir) / "singleton.db")
                )
            threads = [threading.Thread(target=worker) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # All must be the same object
            assert all(r is results[0] for r in results)
            results[0].close()
            dbmod._db_instance = None  # cleanup

    def test_concurrent_writes(self):
        """Multiple threads writing shouldn't raise OperationalError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = self._make_db(tmpdir)
            scan_id = db.start_scan(notes="thread test")
            errors = []

            def write_result(i):
                try:
                    res = {"spf_present": True, "mx_present": True, "dmarc_present": True}
                    ev = {"severity": "OK", "score": 80+i, "grade": "A",
                          "violations": "", "violation_count": 0}
                    db.save_result(scan_id, f"domain{i}.com", res, ev)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=write_result, args=(i,)) for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert errors == [], f"Concurrent write errors: {errors}"
            results = db.get_scan_results(scan_id)
            assert len(results) == 8
            db.close()

    def test_create_alert_returns_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = self._make_db(tmpdir)
            aid = db.create_alert("test.com", "grade_drop", "HIGH", "Grade dropped")
            assert isinstance(aid, int) and aid > 0
            db.close()


# ---------------------------------------------------------------------------
# Scanner improvements
# ---------------------------------------------------------------------------

class TestScannerImprovements:
    """exp= not counted, type-hint consistency, socket fix."""

    def test_exp_not_counted_as_lookup(self):
        """exp= modifier must NOT count toward DNS lookup limit (RFC 7208 &#167;4.6.4)."""
        from app.scanner import _spf_count

        with patch("app.scanner._spf_fetch") as mock_fetch:
            # SPF with only exp= should return 0 lookups
            mock_fetch.side_effect = lambda d: (
                "v=spf1 exp=explain._spf.example.com -all" if d == "example.com" else None
            )
            count, note = _spf_count("example.com")
            assert count == 0, f"exp= was counted: {count}"

    def test_exp_not_counted_with_other_mechanisms(self):
        from app.scanner import _spf_count

        with patch("app.scanner._spf_fetch") as mock_fetch:
            mock_fetch.side_effect = lambda d: (
                "v=spf1 include:other.com exp=explain._spf.example.com -all"
                if d == "example.com" else None
            )
            count, note = _spf_count("example.com")
            # include: counts as 1, exp= should NOT count
            assert count == 1, f"Expected 1 lookup, got {count}"


# ---------------------------------------------------------------------------
# Rules improvements
# ---------------------------------------------------------------------------

class TestRulesImprovements:
    """ValueError guard, DKIM :test detection, ERROR in SEVERITY_ORDER."""

    def test_severity_order_includes_error(self):
        from app.rules import SEVERITY_ORDER
        assert "ERROR" in SEVERITY_ORDER
        assert SEVERITY_ORDER["ERROR"] > SEVERITY_ORDER["CRITICAL"]

    def test_spf_lookups_handles_non_numeric(self):
        from app.rules import rule_spf_lookups
        r = {"spf_present": True, "spf_lookups": "not-a-number"}
        rid, sev, msg = rule_spf_lookups(r)
        assert sev == "OK", "Non-numeric spf_lookups should not crash"

    def test_spf_lookups_handles_none(self):
        from app.rules import rule_spf_lookups
        r = {"spf_present": True, "spf_lookups": None}
        rid, sev, msg = rule_spf_lookups(r)
        assert sev == "OK"

    def test_dkim_test_detection_specific(self):
        """Only ':test' marker from scanner should trigger, not random 'test' words."""
        from app.rules import rule_dkim_test

        # Actual DKIM test-mode marker from scanner
        r1 = {"notes": "selector1:test", "dkim_present": True}
        assert rule_dkim_test(r1)[1] == "WARN"

        # False positive text should NOT trigger
        r2 = {"notes": "latest test scan completed", "dkim_present": True}
        assert rule_dkim_test(r2)[1] == "OK"

    def test_expanded_remediations_cover_all_rules(self):
        """Worst-case domain should produce remediations for all check categories."""
        from app.rules import generate_remediation
        result = {
            "domain": "bad.com",
            "mx_present": False,
            "spf_present": False,
            "dmarc_present": False,
            "dkim_present": False,
            "mta_sts_present": False,
            "tls_rpt_present": False,
            "starttls_worst": "F",
        }
        remediations = generate_remediation(result)
        rules_covered = {r["rule"] for r in remediations}
        expected = {
            "R1_MX_MISSING", "R2_SPF_MISSING", "R4_DMARC_MISSING",
            "R6_DKIM_NOT_FOUND", "R8_MTA_STS_MISSING", "R10_TLS_RPT_MISSING",
            "R11_STARTTLS_WEAK",
        }
        assert expected.issubset(rules_covered), f"Missing: {expected - rules_covered}"

    def test_remediation_dmarc_quarantine(self):
        from app.rules import generate_remediation
        result = {
            "domain": "x.com", "mx_present": True, "spf_present": True,
            "spf_all": "-all", "dmarc_present": True, "dmarc_policy": "quarantine",
            "dmarc_pct": 100, "dmarc_rua": "mailto:x@x.com",
            "dkim_present": True, "mta_sts_present": True, "mta_sts_mode": "enforce",
            "tls_rpt_present": True, "starttls_worst": "A", "notes": "",
        }
        rems = generate_remediation(result)
        assert any(r["rule"] == "R5B_DMARC_QUARANTINE" for r in rems)

    def test_remediation_dmarc_pct(self):
        from app.rules import generate_remediation
        result = {
            "domain": "x.com", "mx_present": True, "spf_present": True,
            "spf_all": "-all", "dmarc_present": True, "dmarc_policy": "reject",
            "dmarc_pct": 50, "dmarc_rua": "mailto:x@x.com",
            "dkim_present": True, "mta_sts_present": True, "mta_sts_mode": "enforce",
            "tls_rpt_present": True, "starttls_worst": "A", "notes": "",
        }
        rems = generate_remediation(result)
        assert any(r["rule"] == "R5C_DMARC_PCT" for r in rems)

    def test_remediation_dmarc_no_rua(self):
        from app.rules import generate_remediation
        result = {
            "domain": "x.com", "mx_present": True, "spf_present": True,
            "spf_all": "-all", "dmarc_present": True, "dmarc_policy": "reject",
            "dmarc_pct": 100, "dmarc_rua": "",
            "dkim_present": True, "mta_sts_present": True, "mta_sts_mode": "enforce",
            "tls_rpt_present": True, "starttls_worst": "A", "notes": "",
        }
        rems = generate_remediation(result)
        assert any(r["rule"] == "R5D_DMARC_NO_RUA" for r in rems)

    def test_remediation_spf_softfail(self):
        from app.rules import generate_remediation
        result = {
            "domain": "x.com", "mx_present": True, "spf_present": True,
            "spf_all": "~all", "spf_lookups": 5,
            "dmarc_present": True, "dmarc_policy": "reject",
            "dmarc_pct": 100, "dmarc_rua": "mailto:x@x.com",
            "dkim_present": True, "mta_sts_present": True, "mta_sts_mode": "enforce",
            "tls_rpt_present": True, "starttls_worst": "A", "notes": "",
        }
        rems = generate_remediation(result)
        assert any(r["rule"] == "R3C_SPF_SOFTFAIL" for r in rems)

    def test_remediation_mta_sts_mode_testing(self):
        from app.rules import generate_remediation
        result = {
            "domain": "x.com", "mx_present": True, "spf_present": True,
            "spf_all": "-all", "dmarc_present": True, "dmarc_policy": "reject",
            "dmarc_pct": 100, "dmarc_rua": "mailto:x@x.com",
            "dkim_present": True, "mta_sts_present": True, "mta_sts_mode": "testing",
            "tls_rpt_present": True, "starttls_worst": "A", "notes": "",
        }
        rems = generate_remediation(result)
        assert any(r["rule"] == "R9_MTA_STS_MODE" for r in rems)

    def test_remediation_no_strict_policy(self):
        from app.rules import generate_remediation
        result = {
            "domain": "x.com", "mx_present": True, "spf_present": True,
            "spf_all": "~all", "spf_lookups": 5,
            "dmarc_present": True, "dmarc_policy": "quarantine",
            "dmarc_pct": 100, "dmarc_rua": "mailto:x@x.com",
            "dkim_present": True, "mta_sts_present": True, "mta_sts_mode": "enforce",
            "tls_rpt_present": True, "starttls_worst": "A", "notes": "",
        }
        rems = generate_remediation(result)
        assert any(r["rule"] == "R12_NO_STRICT_POLICY" for r in rems)


# ---------------------------------------------------------------------------
# DNS fix improvements
# ---------------------------------------------------------------------------

class TestDnsFixImprovements:
    """_extract_error safety and ownership enforcement."""

    def test_extract_error_empty_list(self):
        from app.dns_fix import CloudflareDNS
        # Empty errors list should NOT raise IndexError
        assert CloudflareDNS._extract_error({"errors": []}) != ""

    def test_extract_error_normal(self):
        from app.dns_fix import CloudflareDNS
        result = {"errors": [{"message": "bad token"}]}
        assert CloudflareDNS._extract_error(result) == "bad token"

    def test_extract_error_no_errors_key(self):
        from app.dns_fix import CloudflareDNS
        assert CloudflareDNS._extract_error({}) != ""

    def test_ownership_enforced_on_fix_spf(self):
        from app.dns_fix import CloudflareDNS
        cf = CloudflareDNS(api_token="test", zone_id="test")
        cf.zone_name = "myzone.com"
        ok, msg = cf.fix_spf("evil.com", ["_spf.google.com"])
        assert not ok
        assert "does not belong" in msg

    def test_ownership_enforced_on_fix_dmarc(self):
        from app.dns_fix import CloudflareDNS
        cf = CloudflareDNS(api_token="test", zone_id="test")
        cf.zone_name = "myzone.com"
        ok, msg = cf.fix_dmarc("evil.com", "reject")
        assert not ok
        assert "does not belong" in msg

    def test_ownership_enforced_on_fix_tls_rpt(self):
        from app.dns_fix import CloudflareDNS
        cf = CloudflareDNS(api_token="test", zone_id="test")
        cf.zone_name = "myzone.com"
        ok, msg = cf.fix_tls_rpt("evil.com", "mailto:x@evil.com")
        assert not ok
        assert "does not belong" in msg

    def test_ownership_enforced_on_fix_mta_sts_dns(self):
        from app.dns_fix import CloudflareDNS
        cf = CloudflareDNS(api_token="test", zone_id="test")
        cf.zone_name = "myzone.com"
        ok, msg = cf.fix_mta_sts_dns("evil.com")
        assert not ok
        assert "does not belong" in msg

    def test_ownership_allows_zone_domain(self):
        """fix_spf should pass ownership check for the zone domain itself."""
        from app.dns_fix import CloudflareDNS
        cf = CloudflareDNS(api_token="test", zone_id="test")
        cf.zone_name = "myzone.com"
        # Will fail at API call but ownership should pass
        ok, msg = cf.fix_spf("myzone.com", ["_spf.google.com"])
        # The error should be about API, not ownership
        assert "does not belong" not in msg


# ---------------------------------------------------------------------------
# Analysis improvements
# ---------------------------------------------------------------------------

class TestAnalysisImprovements:
    """Correct median, logging instead of print."""

    def test_median_odd(self):
        from app.analysis import _median
        assert _median([10, 20, 30]) == 20

    def test_median_even(self):
        from app.analysis import _median
        assert _median([10, 20, 30, 40]) == 25.0

    def test_median_single(self):
        from app.analysis import _median
        assert _median([42]) == 42

    def test_median_empty(self):
        from app.analysis import _median
        assert _median([]) == 0.0

    def test_calculate_statistics_median(self):
        from app.analysis import calculate_statistics
        rows = [
            {"score": "10", "grade": "F", "severity": "HIGH"},
            {"score": "20", "grade": "D", "severity": "WARN"},
            {"score": "30", "grade": "C", "severity": "WARN"},
            {"score": "40", "grade": "B", "severity": "OK"},
        ]
        stats = calculate_statistics(rows)
        assert stats["score_median"] == 25.0


# ---------------------------------------------------------------------------
# CLI improvements
# ---------------------------------------------------------------------------

class TestCLIImprovements:
    """csv.writer output and CRITICAL severity on error."""

    def test_csv_writer_escaping(self):
        """CSV with commas and quotes in values should be properly escaped."""
        from app.cli import write_csv

        rows = [
            (
                "evil.com",
                {
                    "spf_present": True,
                    "spf_record": 'v=spf1 include:"weird,host" -all',
                    "notes": 'Has "quotes" and, commas',
                },
                {"severity": "WARN", "score": 60, "grade": "C",
                 "violations": "R3C", "violation_count": 1, "advice": "fix it"},
            )
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.csv"
            write_csv(rows, path)
            # Read back with csv module to verify correctness
            with path.open("r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                row = next(reader)
                assert header[0] == "domain"
                assert row[0] == "evil.com"
                # Should not crash during parsing
                assert len(row) == len(header)

    def test_error_severity_is_critical(self):
        """When a scan raises an exception, severity should be CRITICAL, not ERROR."""
        from app.cli import scan_domains
        with patch("app.cli.scan_domain", side_effect=RuntimeError("boom")):
            results = scan_domains(["test.com"], save_to_db=False)
            assert len(results) == 1
            _, _, ev = results[0]
            assert ev["severity"] == "CRITICAL"
            assert ev["grade"] == "F"
            assert ev["score"] == 0
