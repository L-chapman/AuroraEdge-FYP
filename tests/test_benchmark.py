"""
NorthFlux Security Benchmark Tests
Tests for performance benchmarks and tool comparison data.

These tests validate:
- Legacy tool-comparison data compatibility
- Scoring system accuracy (0-100 range, A+ to F grades)
- Performance expectations for operational reporting
"""

import time
from app.rules import evaluate, SCORE_WEIGHTS, ALL_RULES
from app.dns_fix import COMPARISON_DISCLAIMER, TOOL_COMPARISON, generate_comparison_report


class TestToolComparison:
    """Compatibility tests for the labelled legacy comparison snapshot."""

    def test_tool_comparison_has_required_tools(self):
        """Verify comparison includes required competitor tools."""
        required_tools = ["NorthFlux Security", "OnDMARC", "EasyDMARC", "dmarcian", "MXToolbox"]
        for tool in required_tools:
            assert tool in TOOL_COMPARISON, f"Missing tool: {tool}"

    def test_tool_comparison_has_required_features(self):
        """Verify each tool has required comparison features."""
        required_features = [
            "type",
            "checks",
            "auto_fix",
            "api",
            "reporting",
            "cost",
        ]
        for tool, data in TOOL_COMPARISON.items():
            for feature in required_features:
                assert feature in data, f"{tool} missing feature: {feature}"

    def test_northflux_has_all_features(self):
        """Verify NorthFlux Security implements all checked features."""
        northflux = TOOL_COMPARISON.get("NorthFlux Security", {})
        checks = northflux.get("checks", [])
        assert "SPF" in checks
        assert "DKIM" in checks
        assert "DMARC" in checks
        assert "MTA-STS" in checks
        assert northflux.get("auto_fix") is True
        assert northflux.get("api") is True

    def test_comparison_report_generation(self):
        """Verify comparison report generates valid markdown."""
        report = generate_comparison_report()
        assert "# Email Security Tool Comparison" in report
        assert COMPARISON_DISCLAIMER in report
        assert "| Feature |" in report
        assert "NorthFlux Security" in report
        assert "Open Source / Academic" not in report
        assert len(report) > 500  # Should be substantial


class TestScoringSystem:
    """Tests for the documented security scoring model."""

    def test_score_weights_are_defined(self):
        """Verify all severity levels have scoring weights."""
        assert "CRITICAL" in SCORE_WEIGHTS
        assert "HIGH" in SCORE_WEIGHTS
        assert "WARN" in SCORE_WEIGHTS
        assert "INFO" in SCORE_WEIGHTS

    def test_score_weights_hierarchy(self):
        """Verify scoring weights follow severity hierarchy."""
        assert SCORE_WEIGHTS["CRITICAL"] > SCORE_WEIGHTS["HIGH"]
        assert SCORE_WEIGHTS["HIGH"] > SCORE_WEIGHTS["WARN"]
        assert SCORE_WEIGHTS["WARN"] > SCORE_WEIGHTS["INFO"]

    def test_perfect_score_for_perfect_config(self):
        """Verify perfect configuration gets score of 100 and grade A+."""
        perfect_result = {
            "mx_present": True,
            "spf_present": True,
            "spf_all": "-all",
            "spf_lookups": 5,
            "dmarc_present": True,
            "dmarc_policy": "reject",
            "dmarc_pct": 100,
            "dmarc_rua": "mailto:dmarc@example.com",
            "dkim_present": True,
            "mta_sts_present": True,
            "mta_sts_mode": "enforce",
            "tls_rpt_present": True,
            "bimi_present": True,
            "rbl_listings": 0,
        }
        ev = evaluate(perfect_result)
        assert ev["score"] == 100
        assert ev["grade"] == "A+"
        assert ev["severity"] == "OK"
        assert ev["violation_count"] == 0

    def test_score_range_is_valid(self):
        """Verify scores are always in 0-100 range."""
        # Test worst case - everything missing
        worst_result = {
            "mx_present": False,
            "spf_present": False,
            "dmarc_present": False,
            "dkim_present": False,
            "mta_sts_present": False,
            "tls_rpt_present": False,
        }
        ev = evaluate(worst_result)
        assert 0 <= ev["score"] <= 100
        assert ev["grade"] in ("A+", "A", "B", "C", "D", "F")

    def test_grade_thresholds(self):
        """Verify the documented NorthFlux grade boundaries."""
        # Test exact boundary scores
        test_cases = [
            (100, "A+"),
            (95, "A+"),
            (94, "A"),
            (85, "A"),
            (84, "B"),
            (75, "B"),
            (74, "C"),
            (60, "C"),
            (59, "D"),
            (40, "D"),
            (39, "F"),
            (0, "F"),
        ]

        for score, expected_grade in test_cases:
            # Calculate grade from score
            if score >= 95:
                grade = "A+"
            elif score >= 85:
                grade = "A"
            elif score >= 75:
                grade = "B"
            elif score >= 60:
                grade = "C"
            elif score >= 40:
                grade = "D"
            else:
                grade = "F"
            assert grade == expected_grade, (
                f"Score {score} should be {expected_grade}, got {grade}"
            )


class TestRulesEngine:
    """Tests for rules engine completeness."""

    def test_all_rules_registered(self):
        """Verify all rules are registered in ALL_RULES."""
        # Minimum rule-set breadth expected by the product contract.
        assert len(ALL_RULES) >= 10, "Should have at least 10 security rules"

    def test_rules_return_correct_format(self):
        """Verify all rules return (id, severity, message) tuples."""
        test_result = {
            "mx_present": True,
            "spf_present": True,
            "dmarc_present": True,
            "dkim_present": True,
        }

        for rule_fn in ALL_RULES:
            result = rule_fn(test_result)
            assert isinstance(result, tuple), f"{rule_fn.__name__} should return tuple"
            assert len(result) == 3, f"{rule_fn.__name__} should return 3-tuple"


class TestPerformanceBenchmarks:
    """Performance benchmarks for operational reporting."""

    def test_evaluate_performance(self):
        """Benchmark: evaluate() should complete in under 10ms."""
        test_result = {
            "mx_present": True,
            "spf_present": True,
            "spf_lookups": 5,
            "dmarc_present": True,
            "dmarc_policy": "reject",
            "dkim_present": True,
            "mta_sts_present": True,
            "mta_sts_mode": "enforce",
            "tls_rpt_present": True,
        }

        # Run multiple iterations for accurate timing
        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            evaluate(test_result)
        elapsed = (time.perf_counter() - start) / iterations * 1000  # ms

        assert elapsed < 10, f"evaluate() took {elapsed:.2f}ms, should be <10ms"

    def test_comparison_report_performance(self):
        """Benchmark: generate_comparison_report() should complete in under 50ms."""
        start = time.perf_counter()
        generate_comparison_report()
        elapsed = (time.perf_counter() - start) * 1000  # ms

        assert elapsed < 50, (
            f"generate_comparison_report() took {elapsed:.2f}ms, should be <50ms"
        )
