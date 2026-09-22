"""Command-line scanner and report writer for NorthFlux Security."""

import argparse
import csv as csv_mod
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Dict, Any

from app.scanner import scan_domain, is_valid_domain
from app.rules import evaluate, generate_remediation
from app.database import get_database
from app.dns_fix import get_cloudflare_client
from app.runtime_paths import INDEXED_REPORTS_DIR

logger = logging.getLogger("northflux.cli")

# Rich console for pretty output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
    )
    from rich import box

    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    Console = None


def get_severity_color(severity: str) -> str:
    """Map severity to Rich colour."""
    colors = {
        "OK": "green",
        "INFO": "blue",
        "WARN": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }
    return colors.get(severity, "white")


def get_grade_color(grade: str) -> str:
    """Map letter grade to Rich colour."""
    if grade in ("A+", "A"):
        return "green"
    elif grade == "B":
        return "cyan"
    elif grade == "C":
        return "yellow"
    elif grade == "D":
        return "orange1"
    else:
        return "red"


def apply_dns_fixes(rows: List[Tuple[str, Dict, Dict]], quiet: bool = False) -> int:
    """
    Apply DNS fixes via Cloudflare API for domains with issues.

    Args:
        rows: List of (domain, scan_result, evaluation) tuples
        quiet: Suppress output

    Returns:
        Number of fixes applied
    """
    cf = get_cloudflare_client()
    if not cf:
        if not quiet:
            print(
                "\n&#9888;&#65039;  Cloudflare API not configured. Set CF_API_TOKEN and CF_ZONE_ID environment variables."
            )
            print("   See docs/INTEGRATIONS.md for setup instructions.")
        return 0

    # Validate connection
    success, message = cf.validate_connection()
    if not success:
        if not quiet:
            print(f"\n&#10060; Cloudflare connection failed: {message}")
        return 0

    if not quiet:
        print("\n&#128295; Cloudflare DNS Auto-Fix")
        print(f"   {message}")
        print()

    fixes_applied = 0

    for domain, res, ev in rows:
        if ev.get("severity") == "OK":
            continue  # Skip domains with no findings to show

        # Add domain to scan result for generate_fixes
        res_with_domain = {**res, "domain": domain}
        fixes = cf.generate_fixes(res_with_domain)

        if not fixes:
            continue

        if not quiet:
            print(f"   &#128205; {domain}:")

        for fix in fixes:
            fix_type = fix.get("type", "Unknown")
            _priority = fix.get("priority", "INFO")  # noqa: F841 - reserved for future priority filtering

            try:
                auto_fix_fn = fix.get("auto_fix")
                if auto_fix_fn:
                    ok, msg = auto_fix_fn()
                    if ok:
                        fixes_applied += 1
                        if not quiet:
                            print(f"      &#9989; {fix_type}: {msg}")
                    else:
                        if not quiet:
                            print(f"      &#10060; {fix_type}: {msg}")
            except Exception as e:
                if not quiet:
                    print(f"      &#10060; {fix_type}: Error - {e}")

    if not quiet:
        print(f"\n   Applied {fixes_applied} fix(es)")

    return fixes_applied


def scan_domains(
    targets: List[str],
    check_starttls: bool = False,
    save_to_db: bool = True,
    show_remediation: bool = False,
) -> List[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """
    Scan a list of domains and return results.

    Args:
        targets: List of domain names to scan
        check_starttls: Whether to perform STARTTLS checks (slower)
        save_to_db: Whether to save results to database
        show_remediation: Whether to generate remediation suggestions

    Returns:
        List of (domain, scan_result, evaluation) tuples
    """
    results = []
    db = None
    scan_id = None

    if save_to_db:
        try:
            db = get_database()
            scan_id = db.start_scan(notes=f"CLI scan of {len(targets)} domain(s)")
        except Exception as e:
            logger.warning(f"Could not initialise database: {e}")
            db = None

    if HAS_RICH:
        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning domains...", total=len(targets))

            for domain in targets:
                progress.update(task, description=f"Scanning {domain}...")
                try:
                    res = scan_domain(domain, check_starttls=check_starttls)
                    ev = evaluate(res)
                    results.append((domain, res, ev))

                    if db and scan_id:
                        db.save_result(scan_id, domain, res, ev)

                except Exception as e:
                    logger.error(f"Error scanning {domain}: {e}")
                    results.append(
                        (
                            domain,
                            {"error": str(e)},
                            {"severity": "CRITICAL", "score": 0, "grade": "F",
                             "violations": "", "violation_count": 0, "advice": str(e)},
                        )
                    )

                progress.advance(task)
    else:
        for i, domain in enumerate(targets, 1):
            print(f"[{i}/{len(targets)}] Scanning {domain}...")
            try:
                res = scan_domain(domain, check_starttls=check_starttls)
                ev = evaluate(res)
                results.append((domain, res, ev))

                if db and scan_id:
                    db.save_result(scan_id, domain, res, ev)

            except Exception as e:
                logger.error(f"Error scanning {domain}: {e}")
                results.append(
                    (
                        domain,
                        {"error": str(e)},
                        {"severity": "CRITICAL", "score": 0, "grade": "F",
                         "violations": "", "violation_count": 0, "advice": str(e)},
                    )
                )

    if db and scan_id:
        db.complete_scan(scan_id, len(results))

    return results


def write_csv(rows: List[Tuple[str, Dict, Dict]], path: Path):
    """Write results to CSV file using csv.writer for safe escaping."""
    csv_cols = [
        "domain",
        "grade",
        "score",
        "severity",
        "violations",
        "violation_count",
        "spf_present",
        "spf_lookups",
        "spf_all",
        "mx_present",
        "mx_count",
        "dmarc_present",
        "dmarc_policy",
        "dmarc_pct",
        "dmarc_rua",
        "dkim_present",
        "dkim_selectors",
        "dkim_algos",
        "mta_sts_present",
        "mta_sts_mode",
        "tls_rpt_present",
        "tls_rpt_rua",
        "starttls_grade",
        "starttls_worst",
        "notes",
        "advice",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv_mod.writer(f)
        writer.writerow(csv_cols)
        for domain, res, ev in rows:
            combined = {**res, **ev, "domain": domain}
            writer.writerow([
                str(combined.get(col, "") or "") for col in csv_cols
            ])


def write_markdown(rows: List[Tuple[str, Dict, Dict]], path: Path, scan_ts: str):
    """Write results to Markdown file."""
    lines = [
        "# NorthFlux Security Scan Results",
        "",
        f"**Scan Time:** {scan_ts} UTC",
        f"**Domains Scanned:** {len(rows)}",
        "",
        "## Summary Statistics",
        "",
    ]

    # Calculate statistics
    scores = [ev.get("score", 0) for _, _, ev in rows]
    avg_score = sum(scores) / len(scores) if scores else 0

    severity_counts = {"OK": 0, "INFO": 0, "WARN": 0, "HIGH": 0, "CRITICAL": 0}
    grade_counts = {"A+": 0, "A": 0, "B": 0, "C": 0, "D": 0, "F": 0}

    for _, _, ev in rows:
        sev = ev.get("severity", "OK")
        grade = ev.get("grade", "F")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        grade_counts[grade] = grade_counts.get(grade, 0) + 1

    lines.extend(
        [
            "| Metric | Value |",
            "|--------|-------|",
            f"| Average Score | {avg_score:.1f} |",
            f"| Min Score | {min(scores) if scores else 0} |",
            f"| Max Score | {max(scores) if scores else 0} |",
            "",
            "### Grade Distribution",
            "",
            "| Grade | Count |",
            "|-------|-------|",
        ]
    )
    for grade in ["A+", "A", "B", "C", "D", "F"]:
        lines.append(f"| {grade} | {grade_counts.get(grade, 0)} |")

    lines.extend(
        [
            "",
            "### Severity Distribution",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
    )
    for sev in ["OK", "INFO", "WARN", "HIGH", "CRITICAL"]:
        lines.append(f"| {sev} | {severity_counts.get(sev, 0)} |")

    # Detailed results table
    lines.extend(
        [
            "",
            "## Detailed Results",
            "",
            "| Domain | Grade | Score | Severity | SPF | DMARC | DKIM | MTA-STS | TLS-RPT | Violations |",
            "|--------|-------|-------|----------|-----|-------|------|---------|---------|------------|",
        ]
    )

    for domain, res, ev in rows:
        spf = "Y" if res.get("spf_present") else "N"
        dmarc = res.get("dmarc_policy", "N") if res.get("dmarc_present") else "N"
        dkim = "Y" if res.get("dkim_present") else "N"
        sts = res.get("mta_sts_mode", "N") if res.get("mta_sts_present") else "N"
        tls = "Y" if res.get("tls_rpt_present") else "N"
        violations = ev.get("violation_count", 0)

        lines.append(
            f"| {domain} | {ev.get('grade', 'F')} | {ev.get('score', 0)} | {ev.get('severity', 'OK')} | "
            f"{spf} | {dmarc} | {dkim} | {sts} | {tls} | {violations} |"
        )

    # Common violations section
    violation_counts = {}
    for _, _, ev in rows:
        for v in (ev.get("violations", "") or "").split(","):
            if v.strip():
                violation_counts[v.strip()] = violation_counts.get(v.strip(), 0) + 1

    if violation_counts:
        lines.extend(
            [
                "",
                "## Common Violations",
                "",
                "| Violation | Count |",
                "|-----------|-------|",
            ]
        )
        for v, count in sorted(
            violation_counts.items(), key=lambda x: x[1], reverse=True
        ):
            lines.append(f"| {v} | {count} |")

    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def print_summary(rows: List[Tuple[str, Dict, Dict]], console: "Console"):
    """Print Rich console summary table."""
    table = Table(
        title="NorthFlux Security Email Scan",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Domain", style="bold", no_wrap=True)
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Severity", justify="center")
    table.add_column("SPF", justify="center")
    table.add_column("DMARC", justify="center")
    table.add_column("DKIM", justify="center")
    table.add_column("MTA-STS", justify="center")
    table.add_column("Violations", justify="right")

    for domain, res, ev in rows:
        grade = ev.get("grade", "F")
        severity = ev.get("severity", "OK")

        # Format checkmarks/crosses with colours
        spf = "[green]Y[/]" if res.get("spf_present") else "[red]N[/]"
        dmarc_pol = res.get("dmarc_policy", "")
        if res.get("dmarc_present"):
            if dmarc_pol == "reject":
                dmarc = "[green]reject[/]"
            elif dmarc_pol == "quarantine":
                dmarc = "[yellow]quarantine[/]"
            else:
                dmarc = "[orange1]none[/]"
        else:
            dmarc = "[red]N[/]"
        dkim = "[green]Y[/]" if res.get("dkim_present") else "[red]N[/]"

        sts_mode = res.get("mta_sts_mode", "")
        if res.get("mta_sts_present"):
            sts = (
                f"[green]{sts_mode}[/]"
                if sts_mode == "enforce"
                else f"[yellow]{sts_mode}[/]"
            )
        else:
            sts = "[red]N[/]"

        table.add_row(
            domain,
            f"[{get_grade_color(grade)}]{grade}[/]",
            str(ev.get("score", 0)),
            f"[{get_severity_color(severity)}]{severity}[/]",
            spf,
            dmarc,
            dkim,
            sts,
            str(ev.get("violation_count", 0)),
        )

    console.print()
    console.print(table)

    # Print summary stats
    scores = [ev.get("score", 0) for _, _, ev in rows]
    avg_score = sum(scores) / len(scores) if scores else 0

    console.print()
    console.print(
        Panel(
            f"[bold]Domains scanned:[/] {len(rows)}  |  "
            f"[bold]Average score:[/] {avg_score:.1f}  |  "
            f"[bold]Min:[/] {min(scores) if scores else 0}  |  "
            f"[bold]Max:[/] {max(scores) if scores else 0}",
            title="Summary",
            border_style="cyan",
        )
    )


def print_remediation(rows: List[Tuple[str, Dict, Dict]], console: "Console"):
    """Print remediation recommendations for domains with issues."""
    console.print()
    console.print("[bold cyan]Remediation Recommendations[/]")
    console.print()

    for domain, res, ev in rows:
        if ev.get("severity") in ("WARN", "HIGH", "CRITICAL"):
            res_with_domain = {**res, "domain": domain}
            remediations = generate_remediation(res_with_domain)

            if remediations:
                console.print(
                    f"[bold]{domain}[/] (Score: {ev.get('score', 0)}, Grade: {ev.get('grade', 'F')})"
                )
                for r in remediations:
                    priority_color = {
                        "HIGH": "red",
                        "WARN": "yellow",
                        "INFO": "blue",
                    }.get(r["priority"], "white")
                    console.print(f"  [{priority_color}]>[/] {r['description']}")
                    console.print(f"    [dim]Example: {r['example']}[/]")
                console.print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="NorthFlux Security - self-hosted email security assessment and remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m app.cli --domain example.com
  python -m app.cli --domains domains.txt
  python -m app.cli --domains domains.txt --starttls --remediation

Checks: SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489),
        MTA-STS (RFC 8461), and TLS-RPT (RFC 8460).
        """,
    )

    parser.add_argument("--domain", help="Single domain to scan")
    parser.add_argument("--domains", help="Path to text file with one domain per line")
    parser.add_argument(
        "--outdir",
        default=str(INDEXED_REPORTS_DIR),
        help=(
            "Output folder for reports "
            "(default: NORTHFLUX_REPORTS_DIR/indexed or reports/indexed)"
        ),
    )
    parser.add_argument(
        "--starttls",
        action="store_true",
        help="Perform STARTTLS checks (slower, requires port 25)",
    )
    parser.add_argument(
        "--no-db", action="store_true", help="Don't save results to database"
    )
    parser.add_argument(
        "--remediation", action="store_true", help="Show remediation recommendations"
    )
    parser.add_argument(
        "--apply-fix",
        action="store_true",
        help="Automatically apply DNS fixes via Cloudflare (requires CF_API_TOKEN and CF_ZONE_ID)",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Collect target domains
    targets = []
    if args.domain:
        targets.append(args.domain.strip())
    if args.domains:
        p = Path(args.domains)
        if p.exists():
            raw_lines = [
                line.strip()
                for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            for line in raw_lines:
                if is_valid_domain(line):
                    targets.append(line)
                else:
                    logger.warning("Skipping invalid domain: %s", line)
        else:
            print(f"Error: File not found: {args.domains}")
            sys.exit(1)

    if not targets:
        print("No domains provided. Use --domain example.com or --domains path.txt")
        parser.print_help()
        sys.exit(1)

    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for t in targets:
        if t.lower() not in seen:
            seen.add(t.lower())
            unique_targets.append(t)
    targets = unique_targets

    # Create output directory
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Generate timestamp for filenames
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    csv_path = outdir / f"northflux_results_{ts}.csv"
    md_path = outdir / f"northflux_results_{ts}.md"

    # Run scans
    logger.info(f"Starting scan of {len(targets)} domain(s)")
    rows = scan_domains(
        targets,
        check_starttls=args.starttls,
        save_to_db=not args.no_db,
        show_remediation=args.remediation,
    )

    # Write output files
    write_csv(rows, csv_path)
    write_markdown(rows, md_path, ts)

    if not args.quiet:
        print("\nReports written:")
        print(f"  CSV: {csv_path}")
        print(f"  Markdown: {md_path}")

    # Print console summary
    if HAS_RICH and not args.quiet:
        console = Console()
        print_summary(rows, console)

        if args.remediation:
            print_remediation(rows, console)
    elif not args.quiet:
        print("\nResults:")
        for domain, res, ev in rows:
            print(
                f"  {domain}: Grade={ev.get('grade', 'F')} Score={ev.get('score', 0)} Severity={ev.get('severity', 'OK')}"
            )

    # Apply DNS fixes if requested (Gap G1 - Auto-fix workflow integration)
    if args.apply_fix:
        apply_dns_fixes(rows, quiet=args.quiet)

    logger.info("Scan complete")


if __name__ == "__main__":
    main()
