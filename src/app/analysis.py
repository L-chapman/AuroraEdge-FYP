"""Statistics and chart helpers used in the AuroraEdge reports."""

import csv
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone
from collections import Counter

logger = logging.getLogger("auroraedge.analysis")

# Try to import plotting libraries (optional)
try:
    import matplotlib

    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt

    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    plt = None


# Project paths
ROOT = Path(__file__).resolve().parents[2]
REPORTS_ROOT = ROOT / "reports"
REPORTS = REPORTS_ROOT / "indexed"
FIGURES = ROOT / "docs" / "figures"


def ensure_figures_dir():
    """Create figures directory if it doesn't exist."""
    FIGURES.mkdir(parents=True, exist_ok=True)


def load_latest_csv() -> List[Dict]:
    """Load the most recent CSV report."""
    csvs = sorted(REPORTS.glob("*_results_*.csv"), key=lambda p: p.name, reverse=True)
    if not csvs:
        csvs = sorted(
            REPORTS_ROOT.glob("*_results_*.csv"), key=lambda p: p.name, reverse=True
        )
    if not csvs:
        return []

    with csvs[0].open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def _median(values: List[float]) -> float:
    """Compute a correct median (averages middle two values for even-length lists)."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2
    return s[mid]


def calculate_statistics(rows: List[Dict]) -> Dict:
    """Calculate aggregate statistics from scan results."""
    if not rows:
        return {}

    # Score statistics
    scores = []
    for r in rows:
        try:
            scores.append(float(r.get("score", 0)))
        except (ValueError, TypeError):
            continue

    # Grade distribution
    grade_counts = Counter(r.get("grade", "F") for r in rows)

    # Severity distribution
    severity_counts = Counter(r.get("severity", "OK") for r in rows)

    # Violation analysis
    all_violations = []
    for r in rows:
        violations = r.get("violations", "")
        if violations:
            all_violations.extend(v.strip() for v in violations.split(",") if v.strip())
    violation_counts = Counter(all_violations)

    # Check presence rates
    checks = {
        "spf": sum(1 for r in rows if r.get("spf_present") == "True"),
        "dmarc": sum(1 for r in rows if r.get("dmarc_present") == "True"),
        "dkim": sum(1 for r in rows if r.get("dkim_present") == "True"),
        "mta_sts": sum(1 for r in rows if r.get("mta_sts_present") == "True"),
        "tls_rpt": sum(1 for r in rows if r.get("tls_rpt_present") == "True"),
    }

    # DMARC policy distribution
    dmarc_policies = Counter()
    for r in rows:
        if r.get("dmarc_present") == "True":
            pol = r.get("dmarc_policy", "unknown").lower()
            dmarc_policies[pol] += 1

    return {
        "total_domains": len(rows),
        "score_avg": sum(scores) / len(scores) if scores else 0,
        "score_min": min(scores) if scores else 0,
        "score_max": max(scores) if scores else 0,
        "score_median": _median(scores),
        "grade_distribution": dict(grade_counts),
        "severity_distribution": dict(severity_counts),
        "violation_frequency": dict(violation_counts.most_common(15)),
        "check_presence": checks,
        "check_presence_pct": {k: (v / len(rows) * 100) for k, v in checks.items()},
        "dmarc_policies": dict(dmarc_policies),
    }


def generate_grade_chart(
    stats: Dict, output_path: Optional[Path] = None
) -> Optional[Path]:
    """Generate a bar chart of grade distribution."""
    if not HAS_MATPLOTLIB:
        logger.warning("matplotlib not installed - cannot generate charts")
        return None

    ensure_figures_dir()
    output_path = output_path or FIGURES / "grade_distribution.png"

    grades = ["A+", "A", "B", "C", "D", "F"]
    grade_dist = stats.get("grade_distribution", {})
    counts = [grade_dist.get(g, 0) for g in grades]
    colors = ["#22c55e", "#4ade80", "#22d3ee", "#fbbf24", "#fb923c", "#ef4444"]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(grades, counts, color=colors, edgecolor="black", linewidth=1.2)

    # Add value labels on bars
    for bar, count in zip(bars, counts):
        if count > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                str(count),
                ha="center",
                va="bottom",
                fontweight="bold",
                fontsize=12,
            )

    ax.set_xlabel("Security Grade", fontsize=12)
    ax.set_ylabel("Number of Domains", fontsize=12)
    ax.set_title("Email Security Grade Distribution", fontsize=14, fontweight="bold")
    ax.set_ylim(0, max(counts) * 1.2 if counts else 10)

    # Add grid
    ax.yaxis.grid(True, linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    logger.info("Saved: %s", output_path)
    return output_path


def generate_check_presence_chart(
    stats: Dict, output_path: Optional[Path] = None
) -> Optional[Path]:
    """Generate a bar chart showing percentage of domains with each security check."""
    if not HAS_MATPLOTLIB:
        return None

    ensure_figures_dir()
    output_path = output_path or FIGURES / "check_presence.png"

    checks = ["SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT"]
    check_keys = ["spf", "dmarc", "dkim", "mta_sts", "tls_rpt"]
    pcts = stats.get("check_presence_pct", {})
    values = [pcts.get(k, 0) for k in check_keys]

    # Color based on adoption rate
    colors = []
    for v in values:
        if v >= 80:
            colors.append("#22c55e")  # Green
        elif v >= 50:
            colors.append("#fbbf24")  # Yellow
        else:
            colors.append("#ef4444")  # Red

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(checks, values, color=colors, edgecolor="black", linewidth=1.2)

    # Add percentage labels
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{val:.1f}%",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=11,
        )

    ax.set_xlabel("Security Check", fontsize=12)
    ax.set_ylabel("Adoption Rate (%)", fontsize=12)
    ax.set_title("Email Security Check Adoption Rates", fontsize=14, fontweight="bold")
    ax.set_ylim(0, 110)

    # Add reference line at 100%
    ax.axhline(y=100, color="gray", linestyle="--", alpha=0.5)
    ax.yaxis.grid(True, linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    logger.info("Saved: %s", output_path)
    return output_path


def generate_violation_chart(
    stats: Dict, output_path: Optional[Path] = None
) -> Optional[Path]:
    """Generate a horizontal bar chart of most common violations."""
    if not HAS_MATPLOTLIB:
        return None

    ensure_figures_dir()
    output_path = output_path or FIGURES / "violation_frequency.png"

    violations = stats.get("violation_frequency", {})
    if not violations:
        return None

    # Sort by count
    sorted_violations = sorted(violations.items(), key=lambda x: x[1], reverse=True)[
        :10
    ]
    labels = [v[0] for v in sorted_violations]
    counts = [v[1] for v in sorted_violations]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.barh(labels, counts, color="#e94560", edgecolor="black", linewidth=1)

    # Add count labels
    for bar, count in zip(bars, counts):
        ax.text(
            bar.get_width() + 0.3,
            bar.get_y() + bar.get_height() / 2,
            str(count),
            ha="left",
            va="center",
            fontsize=10,
        )

    ax.set_xlabel("Number of Occurrences", fontsize=12)
    ax.set_ylabel("Violation Rule", fontsize=12)
    ax.set_title("Most Common Security Violations", fontsize=14, fontweight="bold")
    ax.invert_yaxis()  # Highest at top

    ax.xaxis.grid(True, linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    logger.info("Saved: %s", output_path)
    return output_path


def generate_dmarc_policy_chart(
    stats: Dict, output_path: Optional[Path] = None
) -> Optional[Path]:
    """Generate a pie chart of DMARC policy distribution."""
    if not HAS_MATPLOTLIB:
        return None

    ensure_figures_dir()
    output_path = output_path or FIGURES / "dmarc_policies.png"

    policies = stats.get("dmarc_policies", {})
    if not policies:
        return None

    labels = []
    sizes = []
    colors = []

    policy_colors = {
        "reject": "#22c55e",
        "quarantine": "#fbbf24",
        "none": "#ef4444",
    }

    for pol, count in policies.items():
        labels.append(f"p={pol} ({count})")
        sizes.append(count)
        colors.append(policy_colors.get(pol, "#94a3b8"))

    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        pctdistance=0.85,
        wedgeprops=dict(width=0.5, edgecolor="white"),
    )

    for autotext in autotexts:
        autotext.set_fontsize(11)
        autotext.set_fontweight("bold")

    ax.set_title("DMARC Policy Distribution", fontsize=14, fontweight="bold")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    logger.info("Saved: %s", output_path)
    return output_path


def generate_score_histogram(
    rows: List[Dict], output_path: Optional[Path] = None
) -> Optional[Path]:
    """Generate a histogram of security scores."""
    if not HAS_MATPLOTLIB:
        return None

    ensure_figures_dir()
    output_path = output_path or FIGURES / "score_histogram.png"

    scores = []
    for r in rows:
        try:
            scores.append(float(r.get("score", 0)))
        except (ValueError, TypeError):
            continue

    if not scores:
        return None

    fig, ax = plt.subplots(figsize=(10, 6))

    # Create histogram with custom bins
    bins = [0, 20, 40, 60, 75, 85, 95, 100]
    n, bins_out, patches = ax.hist(scores, bins=bins, edgecolor="black", linewidth=1.2)

    # Color bins by score range
    colors = [
        "#ef4444",
        "#fb923c",
        "#fbbf24",
        "#fcd34d",
        "#22d3ee",
        "#4ade80",
        "#22c55e",
    ]
    for patch, color in zip(patches, colors):
        patch.set_facecolor(color)

    ax.set_xlabel("Security Score", fontsize=12)
    ax.set_ylabel("Number of Domains", fontsize=12)
    ax.set_title(
        "Distribution of Email Security Scores", fontsize=14, fontweight="bold"
    )

    # Add grade labels
    grade_labels = ["F", "D", "C", "B", "A", "A+"]
    for i, (left, right) in enumerate(zip(bins[:-1], bins[1:])):
        if i < len(grade_labels):
            ax.text(
                (left + right) / 2,
                ax.get_ylim()[1] * 0.95,
                grade_labels[i],
                ha="center",
                va="top",
                fontsize=10,
                fontweight="bold",
                alpha=0.7,
            )

    ax.yaxis.grid(True, linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()

    logger.info("Saved: %s", output_path)
    return output_path


def generate_all_charts(rows: Optional[List[Dict]] = None) -> List[Path]:
    """Generate all charts for academic reporting."""
    if rows is None:
        rows = load_latest_csv()

    if not rows:
        logger.warning("No data available for chart generation")
        return []

    stats = calculate_statistics(rows)
    charts = []

    chart = generate_grade_chart(stats)
    if chart:
        charts.append(chart)

    chart = generate_check_presence_chart(stats)
    if chart:
        charts.append(chart)

    chart = generate_violation_chart(stats)
    if chart:
        charts.append(chart)

    chart = generate_dmarc_policy_chart(stats)
    if chart:
        charts.append(chart)

    chart = generate_score_histogram(rows)
    if chart:
        charts.append(chart)

    return charts


def generate_summary_report(
    rows: Optional[List[Dict]] = None, output_path: Optional[Path] = None
) -> Path:
    """Generate a comprehensive Markdown summary report."""
    if rows is None:
        rows = load_latest_csv()

    output_path = output_path or ROOT / "docs" / "SCAN_ANALYSIS.md"
    stats = calculate_statistics(rows)

    lines = [
        "# AuroraEdge Scan Analysis Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"**Total Domains Scanned:** {stats.get('total_domains', 0)}",
        "",
        "## Executive Summary",
        "",
        f"This report presents the email security posture analysis of {stats.get('total_domains', 0)} domains.",
        "",
        "### Key Findings",
        "",
        f"- **Average Security Score:** {stats.get('score_avg', 0):.1f}/100",
        f"- **Score Range:** {stats.get('score_min', 0):.0f} to {stats.get('score_max', 0):.0f}",
        "",
        "### Security Check Adoption",
        "",
        "| Check | Adoption Rate |",
        "|-------|--------------|",
    ]

    pcts = stats.get("check_presence_pct", {})
    for check, key in [
        ("SPF", "spf"),
        ("DMARC", "dmarc"),
        ("DKIM", "dkim"),
        ("MTA-STS", "mta_sts"),
        ("TLS-RPT", "tls_rpt"),
    ]:
        lines.append(f"| {check} | {pcts.get(key, 0):.1f}% |")

    lines.extend(
        [
            "",
            "### Grade Distribution",
            "",
            "| Grade | Count | Percentage |",
            "|-------|-------|------------|",
        ]
    )

    grade_dist = stats.get("grade_distribution", {})
    total = sum(grade_dist.values())
    for grade in ["A+", "A", "B", "C", "D", "F"]:
        count = grade_dist.get(grade, 0)
        pct = (count / total * 100) if total > 0 else 0
        lines.append(f"| {grade} | {count} | {pct:.1f}% |")

    lines.extend(
        [
            "",
            "### Most Common Violations",
            "",
            "| Violation | Occurrences |",
            "|-----------|-------------|",
        ]
    )

    violations = stats.get("violation_frequency", {})
    for v, count in list(violations.items())[:10]:
        lines.append(f"| {v} | {count} |")

    lines.extend(
        [
            "",
            "### DMARC Policy Distribution",
            "",
            "| Policy | Count |",
            "|--------|-------|",
        ]
    )

    dmarc = stats.get("dmarc_policies", {})
    for pol, count in dmarc.items():
        lines.append(f"| p={pol} | {count} |")

    lines.extend(
        [
            "",
            "## Methodology",
            "",
            "This analysis was conducted using the AuroraEdge Security Scanner, which performs:",
            "",
            "1. **SPF Analysis** - Validates Sender Policy Framework records (RFC 7208)",
            "2. **DKIM Discovery** - Checks common DKIM selectors (RFC 6376)",
            "3. **DMARC Evaluation** - Assesses policy strength and reporting (RFC 7489)",
            "4. **MTA-STS Check** - Verifies transport security policy (RFC 8461)",
            "5. **TLS-RPT Detection** - Confirms TLS reporting configuration (RFC 8460)",
            "",
            "## Recommendations",
            "",
            "Based on the findings, the following actions are recommended:",
            "",
            "1. **Domains with p=none DMARC** should upgrade to p=quarantine or p=reject",
            "2. **Missing MTA-STS** should be deployed to enforce TLS for mail delivery",
            "3. **Missing TLS-RPT** records should be added to receive delivery reports",
            "4. **DKIM configuration** should be verified for all mail-sending services",
            "",
            "---",
            "",
            "*Report generated by AuroraEdge Security Scanner*",
            "*Leon Chapman - Belfast Met - FYP 2025/2026*",
        ]
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Saved: %s", output_path)
    return output_path


def main():
    """Main entry point for analysis."""
    logger.info("AuroraEdge Analysis Tool")

    rows = load_latest_csv()
    if not rows:
        logger.warning("No scan data found. Run a scan first.")
        return

    logger.info("Loaded %d domain results", len(rows))

    # Generate statistics
    stats = calculate_statistics(rows)
    logger.info("Average Score: %.1f", stats.get('score_avg', 0))
    logger.info("Grade Distribution: %s", stats.get('grade_distribution', {}))

    # Generate charts
    logger.info("Generating charts...")
    charts = generate_all_charts(rows)
    logger.info("Generated %d charts", len(charts))

    # Generate summary report
    logger.info("Generating summary report...")
    generate_summary_report(rows)

    logger.info("Analysis complete!")


if __name__ == "__main__":
    main()
