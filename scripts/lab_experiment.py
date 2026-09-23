#!/usr/bin/env python3
"""
NorthFlux Security Lab Experiment Protocol
==================================

Legacy live-mutation experiments are disabled. Use --dry-run for read-only
detection; no accuracy or restoration guarantee is made by this historical tool.

This script implements the recommended lab evaluation protocol from the
verification report. It measures detection time, fix time, and accuracy
for controlled email security misconfigurations.

Usage:
    python scripts/lab_experiment.py --domain test.example.com --dry-run

Requirements:
    - An authorised test domain
    - Network access for read-only DNS/HTTPS checks (dry-run is not offline)

Reference: docs/academic/archive/VERIFICATION_REPORT.md Section 5
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# Add src to path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from app.scanner import scan_domain
from app.rules import evaluate
from app.dns_fix import CloudflareDNS, get_cloudflare_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("lab_experiment")
DISABLED_MESSAGE = (
    "Legacy lab DNS mutation is disabled: its historical setup/restore sequence "
    "does not safely preserve existing records. Use --dry-run for read-only "
    "detection, or the validated dashboard operator workflow with an authorised "
    "test zone and a recovery plan."
)


class LabExperiment:
    """
    Controlled lab experiment for measuring NorthFlux Security detection and fix performance.
    """
    
    # Known good baseline configurations
    BASELINE_SPF = "v=spf1 include:_spf.google.com ~all"
    BASELINE_DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}"
    
    def __init__(self, domain: str, cf_client: CloudflareDNS):
        self.domain = domain
        self.cf = cf_client
        self.results: List[Dict] = []
    
    def run_detection_test(self, condition: str, expected_violations: List[str]) -> Dict:
        """
        Run a single detection test and measure timing.
        
        Args:
            condition: Description of the test condition
            expected_violations: List of expected rule IDs to be triggered
        
        Returns:
            Test result dictionary
        """
        logger.info(f"Testing: {condition}")
        
        # Measure detection time
        start_time = time.perf_counter()
        scan_result = scan_domain(self.domain)
        evaluation = evaluate(scan_result)
        detection_time = time.perf_counter() - start_time
        
        violations = (evaluation.get("violations") or "").split(",")
        violations = [v.strip() for v in violations if v.strip()]
        
        # Calculate accuracy
        expected_set = set(expected_violations)
        detected_set = set(violations)
        
        true_positives = len(expected_set & detected_set)
        false_positives = len(detected_set - expected_set)
        false_negatives = len(expected_set - detected_set)
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        
        result = {
            "condition": condition,
            "timestamp": datetime.utcnow().isoformat(),
            "detection_time_ms": round(detection_time * 1000, 2),
            "score": evaluation.get("score", 0),
            "grade": evaluation.get("grade", "F"),
            "expected_violations": expected_violations,
            "detected_violations": violations,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
        }
        
        logger.info(f"  Detection time: {result['detection_time_ms']}ms, Score: {result['score']}, Grade: {result['grade']}")
        logger.info(f"  Expected: {expected_violations}")
        logger.info(f"  Detected: {violations}")
        
        return result
    
    def run_fix_test(self, fix_type: str) -> Dict:
        """
        Run a fix test and measure timing.
        
        Args:
            fix_type: Type of fix (SPF, DMARC, TLS-RPT, MTA-STS)
        
        Returns:
            Fix result dictionary
        """
        raise RuntimeError(DISABLED_MESSAGE)

        logger.info(f"Applying fix: {fix_type}")
        
        start_time = time.perf_counter()
        
        if fix_type == "SPF":
            success, message = self.cf.fix_spf(self.domain, ["_spf.google.com"])
        elif fix_type == "DMARC":
            success, message = self.cf.fix_dmarc(self.domain, "reject", f"dmarc@{self.domain}")
        elif fix_type == "TLS-RPT":
            success, message = self.cf.fix_tls_rpt(self.domain, f"tlsrpt@{self.domain}")
        elif fix_type == "MTA-STS":
            success, message = self.cf.fix_mta_sts_dns(self.domain)
        else:
            success, message = False, f"Unknown fix type: {fix_type}"
        
        fix_time = time.perf_counter() - start_time
        
        result = {
            "fix_type": fix_type,
            "timestamp": datetime.utcnow().isoformat(),
            "fix_time_ms": round(fix_time * 1000, 2),
            "success": success,
            "message": message,
        }
        
        logger.info(f"  Fix time: {result['fix_time_ms']}ms, Success: {success}")
        
        return result
    
    def wait_for_dns_propagation(self, seconds: int = 10):
        """Wait for DNS changes to propagate."""
        logger.info(f"Waiting {seconds}s for DNS propagation...")
        time.sleep(seconds)
    
    def run_full_experiment(self, iterations: int = 5, dns_wait: int = 10) -> Dict:
        """
        Run the complete lab experiment protocol.
        
        Protocol:
        1. Baseline scan (known-good config)
        2. Introduce synthetic misconfigs (one at a time)
        3. Measure detection time and accuracy
        4. Apply fix
        5. Measure fix time
        6. Verify fix was applied
        7. Repeat n times
        
        Args:
            iterations: Number of times to repeat each test
            dns_wait: Seconds to wait for DNS propagation
        
        Returns:
            Complete experiment results
        """
        raise RuntimeError(DISABLED_MESSAGE)

        experiment_start = datetime.utcnow().isoformat()
        all_results = {
            "experiment_start": experiment_start,
            "domain": self.domain,
            "iterations": iterations,
            "dns_wait_seconds": dns_wait,
            "tests": [],
        }
        
        # Test conditions
        conditions = [
            {
                "name": "baseline",
                "description": "Known-good configuration",
                "expected_violations": [],  # Should detect MTA-STS/TLS-RPT if not set
            },
            {
                "name": "missing_spf",
                "description": "SPF record removed",
                "expected_violations": ["R2_SPF_MISSING"],
                "break_action": lambda: self.cf._request("DELETE", f"{self.cf.base_url}?type=TXT&name={self.domain}"),
                "fix_type": "SPF",
            },
            {
                "name": "weak_dmarc",
                "description": "DMARC policy set to p=none",
                "expected_violations": ["R5_DMARC_NONE"],
                "break_action": lambda: self.cf.fix_dmarc(self.domain, "none"),
                "fix_type": "DMARC",
            },
        ]
        
        for iteration in range(iterations):
            logger.info(f"\n{'='*60}")
            logger.info(f"ITERATION {iteration + 1}/{iterations}")
            logger.info(f"{'='*60}")
            
            for condition in conditions:
                test_result = {
                    "iteration": iteration + 1,
                    "condition": condition["name"],
                    "description": condition["description"],
                    "detection_results": [],
                    "fix_results": [],
                }
                
                # Apply break action if specified (to introduce misconfig)
                if "break_action" in condition:
                    logger.info(f"Breaking: {condition['description']}")
                    condition["break_action"]()
                    self.wait_for_dns_propagation(dns_wait)
                
                # Run detection test
                detection = self.run_detection_test(
                    condition["description"],
                    condition["expected_violations"]
                )
                test_result["detection_results"].append(detection)
                
                # Apply fix if specified
                if "fix_type" in condition:
                    fix = self.run_fix_test(condition["fix_type"])
                    test_result["fix_results"].append(fix)
                    
                    # Wait and verify
                    self.wait_for_dns_propagation(dns_wait)
                    
                    # Verify fix was applied
                    verification = self.run_detection_test(
                        f"Verify {condition['fix_type']} fix",
                        []  # After fix, should have fewer/no violations
                    )
                    test_result["verification"] = verification
                
                all_results["tests"].append(test_result)
        
        all_results["experiment_end"] = datetime.utcnow().isoformat()
        
        return all_results
    
    def generate_report(self, results: Dict, output_path: Path) -> str:
        """Generate markdown report from experiment results."""
        lines = [
            "# NorthFlux Security Lab Experiment Report",
            "",
            f"**Domain:** {results['domain']}",
            f"**Start:** {results['experiment_start']}",
            f"**End:** {results.get('experiment_end', 'N/A')}",
            f"**Iterations:** {results['iterations']}",
            "",
            "## Results Summary",
            "",
            "| Condition | Avg Detection (ms) | Avg Precision | Avg Recall |",
            "|-----------|-------------------|---------------|------------|",
        ]
        
        # Aggregate by condition
        condition_stats = {}
        for test in results["tests"]:
            cond = test["condition"]
            if cond not in condition_stats:
                condition_stats[cond] = {"detection_times": [], "precisions": [], "recalls": []}
            
            for det in test["detection_results"]:
                condition_stats[cond]["detection_times"].append(det["detection_time_ms"])
                condition_stats[cond]["precisions"].append(det["precision"])
                condition_stats[cond]["recalls"].append(det["recall"])
        
        for cond, stats in condition_stats.items():
            avg_time = sum(stats["detection_times"]) / len(stats["detection_times"]) if stats["detection_times"] else 0
            avg_prec = sum(stats["precisions"]) / len(stats["precisions"]) if stats["precisions"] else 0
            avg_recall = sum(stats["recalls"]) / len(stats["recalls"]) if stats["recalls"] else 0
            lines.append(f"| {cond} | {avg_time:.1f} | {avg_prec:.3f} | {avg_recall:.3f} |")
        
        lines.extend([
            "",
            "## Fix Performance",
            "",
            "| Fix Type | Avg Time (ms) | Success Rate |",
            "|----------|---------------|--------------|",
        ])
        
        # Aggregate fix stats
        fix_stats = {}
        for test in results["tests"]:
            for fix in test.get("fix_results", []):
                ft = fix["fix_type"]
                if ft not in fix_stats:
                    fix_stats[ft] = {"times": [], "successes": []}
                fix_stats[ft]["times"].append(fix["fix_time_ms"])
                fix_stats[ft]["successes"].append(1 if fix["success"] else 0)
        
        for ft, stats in fix_stats.items():
            avg_time = sum(stats["times"]) / len(stats["times"]) if stats["times"] else 0
            success_rate = sum(stats["successes"]) / len(stats["successes"]) if stats["successes"] else 0
            lines.append(f"| {ft} | {avg_time:.1f} | {success_rate:.0%} |")
        
        lines.extend([
            "",
            "## Raw Data",
            "",
            "```json",
            json.dumps(results, indent=2),
            "```",
        ])
        
        report = "\n".join(lines)
        output_path.write_text(report, encoding="utf-8")
        logger.info(f"Report written to: {output_path}")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description="NorthFlux read-only lab detection; legacy mutation experiments are disabled",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    python scripts/lab_experiment.py --domain test.example.com --dry-run
    
Requirements:
    Use an authorised TEST domain. --dry-run performs real read-only DNS/HTTPS
    checks but never loads provider credentials. It is not an offline simulation.
        """
    )
    
    parser.add_argument("--domain", required=True, help="Test domain to use (must be in your Cloudflare zone)")
    parser.add_argument("--iterations", type=int, default=5, help="Number of test iterations (default: 5)")
    parser.add_argument("--dns-wait", type=int, default=10, help="Seconds to wait for DNS propagation (default: 10)")
    parser.add_argument("--output", default="reports/lab_experiment.md", help="Output report path")
    parser.add_argument("--dry-run", action="store_true", help="Required: real read-only DNS/HTTPS checks, no provider credentials or DNS changes")
    
    args = parser.parse_args()

    if not args.dry_run:
        parser.error(DISABLED_MESSAGE)
    
    # Check Cloudflare credentials
    cf = None  # Read-only detection must never load provider credentials.
    if not cf and not args.dry_run:
        print("&#10060; Cloudflare API not configured.")
        print("   Set CF_API_TOKEN and CF_ZONE_ID environment variables.")
        print("   Or use --dry-run for detection tests only.")
        sys.exit(1)
    
    if cf:
        ok, msg = cf.validate_connection()
        if not ok:
            print(f"&#10060; Cloudflare connection failed: {msg}")
            sys.exit(1)
        print(f"&#9989; {msg}")
    
    print(f"\n&#129514; NorthFlux Security Lab Experiment")
    print(f"   Domain: {args.domain}")
    print(f"   Iterations: {args.iterations}")
    print(f"   DNS Wait: {args.dns_wait}s")
    print()
    
    if args.dry_run:
        # Simple detection test only
        print("Running detection test (dry run)...")
        scan_result = scan_domain(args.domain)
        evaluation = evaluate(scan_result)
        if scan_result.get("scan_incomplete"):
            print("Incomplete scan: no grade or score assigned. " + str(scan_result.get("notes") or "Retry the scan."))
        else:
            print(f"\nScore: {evaluation.get('score')}")
            print(f"Grade: {evaluation.get('grade')}")
        print(f"Violations: {evaluation.get('violations')}")
    else:
        # Full experiment
        experiment = LabExperiment(args.domain, cf)
        results = experiment.run_full_experiment(
            iterations=args.iterations,
            dns_wait=args.dns_wait
        )
        
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        experiment.generate_report(results, output_path)
        
        print(f"\n&#9989; Experiment complete. Report: {output_path}")


if __name__ == "__main__":
    main()
