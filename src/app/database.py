"""
AuroraEdge Database Module
SQLite storage for persistent scan history and trend analysis.

This module provides:
- Scan result persistence
- Historical trend queries
- Domain tracking over time
- Export capabilities

Reference: SQLite is chosen for simplicity and portability (no server required).
"""

import sqlite3
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("auroraedge.database")

# Default database path relative to project root
DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "state" / "auroraedge.db"


class AuroraDatabase:
    """SQLite database for AuroraEdge scan results."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file. Defaults to state/auroraedge.db
        """
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit — close connection."""
        self.close()
        return False

    def _init_db(self):
        """Create database tables if they don't exist."""
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()

        cursor = self.conn.cursor()

        # Scans table - stores each scan run
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                domain_count INTEGER DEFAULT 0,
                source_file TEXT,
                notes TEXT
            )
        """
        )

        # Results table - stores individual domain results
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                
                -- Core fields
                spf_present INTEGER,
                spf_record TEXT,
                spf_lookups INTEGER,
                spf_includes TEXT,
                spf_all TEXT,
                
                mx_present INTEGER,
                mx_count INTEGER,
                mx_hosts TEXT,
                
                dmarc_present INTEGER,
                dmarc_policy TEXT,
                dmarc_strength TEXT,
                dmarc_sp TEXT,
                dmarc_aspf TEXT,
                dmarc_adkim TEXT,
                dmarc_pct INTEGER,
                dmarc_rua TEXT,
                dmarc_ruf TEXT,
                
                dkim_present INTEGER,
                dkim_selectors TEXT,
                dkim_algos TEXT,
                
                mta_sts_present INTEGER,
                mta_sts_mode TEXT,
                mta_sts_max_age INTEGER,
                
                tls_rpt_present INTEGER,
                tls_rpt_rua TEXT,
                
                starttls_grade TEXT,
                starttls_worst TEXT,
                
                -- Evaluation results
                severity TEXT,
                score INTEGER,
                grade TEXT,
                violations TEXT,
                violation_count INTEGER,
                advice TEXT,
                notes TEXT,
                
                -- Full JSON for extensibility
                raw_json TEXT,
                
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """
        )

        # Create indexes for common queries
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_domain ON results(domain)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_scanned_at ON results(scanned_at)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_severity ON results(severity)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_score ON results(score)")

        # Domains table - tracks all domains ever scanned
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                scan_count INTEGER DEFAULT 1,
                best_score INTEGER,
                worst_score INTEGER,
                latest_score INTEGER,
                latest_grade TEXT
            )
        """
        )

        # Managed domains - domains the SME has onboarded for continuous monitoring
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS managed_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                added_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                last_scan_at TEXT,
                last_grade TEXT,
                last_score INTEGER,
                previous_grade TEXT,
                previous_score INTEGER,
                notes TEXT DEFAULT ''
            )
        """
        )

        # Settings table - key/value store for app configuration
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )

        # Alerts table - drift detection and grade change notifications
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_at TEXT
            )
        """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_domain_scanned ON results(domain, scanned_at DESC)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC)"
        )

        self.conn.commit()
        logger.info("Database initialized at %s", self.db_path)

    def start_scan(
        self, source_file: Optional[str] = None, notes: Optional[str] = None
    ) -> str:
        """
        Start a new scan session.

        Returns:
            scan_id: Unique identifier for this scan
        """
        # Include microseconds + random suffix to guarantee uniqueness
        import random
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f") + f"_{random.randint(0, 9999):04d}"
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "INSERT INTO scans (scan_id, started_at, source_file, notes) VALUES (?, ?, ?, ?)",
                    (scan_id, datetime.now(timezone.utc).isoformat(), source_file, notes),
                )
                self.conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to start scan: %s", e)
            raise
        logger.info("Started scan %s", scan_id)
        return scan_id

    def save_result(
        self,
        scan_id: str,
        domain: str,
        result: Dict[str, Any],
        evaluation: Dict[str, Any],
    ):
        """
        Save a single domain scan result.

        Args:
            scan_id: The scan session ID
            domain: Domain that was scanned
            result: Raw scan result dictionary
            evaluation: Rule evaluation results
        """
        now = datetime.now(timezone.utc).isoformat()

        # Merge result and evaluation
        combined = {**result, **evaluation, "domain": domain}

        try:
            with self._lock:
                self._save_result_inner(scan_id, domain, result, evaluation, combined, now)
        except sqlite3.Error as e:
            logger.error("Failed to save result for %s: %s", domain, e)
            raise

    def _save_result_inner(
        self, scan_id: str, domain: str, result: Dict, evaluation: Dict,
        combined: Dict, now: str
    ):
        """Inner implementation of save_result (must be called under _lock)."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO results (
                scan_id, domain, scanned_at,
                spf_present, spf_record, spf_lookups, spf_includes, spf_all,
                mx_present, mx_count, mx_hosts,
                dmarc_present, dmarc_policy, dmarc_strength, dmarc_sp, dmarc_aspf, dmarc_adkim, dmarc_pct, dmarc_rua, dmarc_ruf,
                dkim_present, dkim_selectors, dkim_algos,
                mta_sts_present, mta_sts_mode, mta_sts_max_age,
                tls_rpt_present, tls_rpt_rua,
                starttls_grade, starttls_worst,
                severity, score, grade, violations, violation_count, advice, notes,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                scan_id,
                domain,
                now,
                1 if result.get("spf_present") else 0,
                result.get("spf_record", ""),
                result.get("spf_lookups", 0),
                result.get("spf_includes", ""),
                result.get("spf_all", ""),
                1 if result.get("mx_present") else 0,
                result.get("mx_count", 0),
                result.get("mx_hosts", ""),
                1 if result.get("dmarc_present") else 0,
                result.get("dmarc_policy", ""),
                result.get("dmarc_strength", ""),
                result.get("dmarc_sp", ""),
                result.get("dmarc_aspf", ""),
                result.get("dmarc_adkim", ""),
                result.get("dmarc_pct", 100),
                result.get("dmarc_rua", ""),
                result.get("dmarc_ruf", ""),
                1 if result.get("dkim_present") else 0,
                result.get("dkim_selectors", ""),
                result.get("dkim_algos", ""),
                1 if result.get("mta_sts_present") else 0,
                result.get("mta_sts_mode", ""),
                result.get("mta_sts_max_age", 0),
                1 if result.get("tls_rpt_present") else 0,
                result.get("tls_rpt_rua", ""),
                result.get("starttls_grade", ""),
                result.get("starttls_worst", ""),
                evaluation.get("severity", ""),
                evaluation.get("score", 0),
                evaluation.get("grade", ""),
                evaluation.get("violations", ""),
                evaluation.get("violation_count", 0),
                evaluation.get("advice", ""),
                result.get("notes", ""),
                json.dumps(combined),
            ),
        )

        # Update domains tracking table
        cursor.execute("SELECT * FROM domains WHERE domain = ?", (domain,))
        existing = cursor.fetchone()
        score = evaluation.get("score", 0)
        grade = evaluation.get("grade", "")

        if existing:
            best = max(existing["best_score"] or 0, score)
            worst = min(existing["worst_score"] or 100, score)
            cursor.execute(
                """
                UPDATE domains SET
                    last_seen = ?,
                    scan_count = scan_count + 1,
                    best_score = ?,
                    worst_score = ?,
                    latest_score = ?,
                    latest_grade = ?
                WHERE domain = ?
            """,
                (now, best, worst, score, grade, domain),
            )
        else:
            cursor.execute(
                """
                INSERT INTO domains (domain, first_seen, last_seen, scan_count, best_score, worst_score, latest_score, latest_grade)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?)
            """,
                (domain, now, now, score, score, score, grade),
            )

        self.conn.commit()

    def complete_scan(self, scan_id: str, domain_count: int):
        """Mark a scan as completed."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "UPDATE scans SET completed_at = ?, domain_count = ? WHERE scan_id = ?",
                    (datetime.now(timezone.utc).isoformat(), domain_count, scan_id),
                )
                self.conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to complete scan %s: %s", scan_id, e)
            raise
        logger.info("Completed scan %s with %d domains", scan_id, domain_count)

    def get_latest_results(self, limit: int = 100) -> List[Dict]:
        """Get the most recent scan results."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM results
            ORDER BY scanned_at DESC
            LIMIT ?
        """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_domain_history(self, domain: str, limit: int = 20) -> List[Dict]:
        """Get historical scan results for a specific domain."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM results
            WHERE domain = ?
            ORDER BY scanned_at DESC
            LIMIT ?
        """,
            (domain, limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_scan_results(self, scan_id: str) -> List[Dict]:
        """Get all results from a specific scan."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM results
            WHERE scan_id = ?
            ORDER BY domain
        """,
            (scan_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_scans(self, limit: int = 50) -> List[Dict]:
        """Get list of recent scans."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scans
            ORDER BY started_at DESC
            LIMIT ?
        """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict:
        """Get aggregate statistics across all scans."""
        cursor = self.conn.cursor()

        # Total counts
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        total_scans = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(DISTINCT domain) as count FROM results")
        unique_domains = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM results")
        total_results = cursor.fetchone()["count"]

        # Score distribution
        cursor.execute(
            """
            SELECT 
                AVG(score) as avg_score,
                MIN(score) as min_score,
                MAX(score) as max_score
            FROM results
        """
        )
        score_stats = dict(cursor.fetchone())

        # Severity distribution
        cursor.execute(
            """
            SELECT severity, COUNT(*) as count
            FROM results
            GROUP BY severity
        """
        )
        severity_dist = {row["severity"]: row["count"] for row in cursor.fetchall()}

        # Grade distribution
        cursor.execute(
            """
            SELECT grade, COUNT(*) as count
            FROM results
            GROUP BY grade
        """
        )
        grade_dist = {row["grade"]: row["count"] for row in cursor.fetchall()}

        # Common violations
        cursor.execute(
            """
            SELECT violations, COUNT(*) as count
            FROM results
            WHERE violations != ''
            GROUP BY violations
            ORDER BY count DESC
            LIMIT 10
        """
        )
        top_violations = [
            {"violations": row["violations"], "count": row["count"]}
            for row in cursor.fetchall()
        ]

        return {
            "total_scans": total_scans,
            "unique_domains": unique_domains,
            "total_results": total_results,
            "score_stats": score_stats,
            "severity_distribution": severity_dist,
            "grade_distribution": grade_dist,
            "top_violations": top_violations,
        }

    def get_domains_by_grade(self, grade: str) -> List[Dict]:
        """Get all domains with a specific grade from their latest scan."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT domain, latest_score, latest_grade, last_seen, scan_count
            FROM domains
            WHERE latest_grade = ?
            ORDER BY domain
        """,
            (grade,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_improvement_candidates(self, max_score: int = 70) -> List[Dict]:
        """Get domains that need improvement (low scores)."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT domain, latest_score, latest_grade, scan_count
            FROM domains
            WHERE latest_score <= ?
            ORDER BY latest_score ASC
        """,
            (max_score,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    # =========================================================================
    # Managed Domains (SME onboarding)
    # =========================================================================

    def add_managed_domain(self, domain: str, notes: str = "") -> Dict:
        """Add a domain for continuous monitoring."""
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        try:
            cursor.execute(
                """INSERT INTO managed_domains (domain, added_at, notes)
                   VALUES (?, ?, ?)""",
                (domain.lower().strip(), now, notes),
            )
            self.conn.commit()
            return {"ok": True, "domain": domain, "added_at": now}
        except sqlite3.IntegrityError:
            # Already exists — reactivate if inactive
            cursor.execute(
                """UPDATE managed_domains SET is_active = 1, notes = ?
                   WHERE domain = ?""",
                (notes, domain.lower().strip()),
            )
            self.conn.commit()
            return {"ok": True, "domain": domain, "reactivated": True}

    def remove_managed_domain(self, domain: str) -> bool:
        """Soft-delete a managed domain (deactivate)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE managed_domains SET is_active = 0 WHERE domain = ?",
            (domain.lower().strip(),),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def get_managed_domains(self, active_only: bool = True) -> List[Dict]:
        """Get all managed domains."""
        cursor = self.conn.cursor()
        if active_only:
            cursor.execute(
                "SELECT * FROM managed_domains WHERE is_active = 1 ORDER BY domain"
            )
        else:
            cursor.execute("SELECT * FROM managed_domains ORDER BY domain")
        return [dict(row) for row in cursor.fetchall()]

    def update_managed_domain_scan(
        self, domain: str, grade: str, score: int
    ):
        """Update a managed domain after a scan completes."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                now = datetime.now(timezone.utc).isoformat()
                # Store previous values for drift detection
                cursor.execute(
                    "SELECT last_grade, last_score FROM managed_domains WHERE domain = ?",
                    (domain.lower().strip(),),
                )
                row = cursor.fetchone()
                prev_grade = row["last_grade"] if row else None
                prev_score = row["last_score"] if row else None

                cursor.execute(
                    """UPDATE managed_domains
                       SET last_scan_at = ?, last_grade = ?, last_score = ?,
                           previous_grade = ?, previous_score = ?
                       WHERE domain = ?""",
                    (now, grade, score, prev_grade, prev_score, domain.lower().strip()),
                )
                self.conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to update managed domain %s: %s", domain, e)
            raise
        return {"previous_grade": prev_grade, "previous_score": prev_score}

    # =========================================================================
    # Settings
    # =========================================================================

    def get_setting(self, key: str, default: str = "") -> str:
        """Get a setting value."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        """Set a setting value."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                       ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?""",
                    (key, value, now, value, now),
                )
                self.conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to set setting %s: %s", key, e)
            raise

    def clear_scan_data(self):
        """Clear all scan-related data (scans, results, domains, managed_domains, alerts).

        Preserves settings (Cloudflare credentials, org name, etc.).
        Called on server startup so each launch begins with a clean slate.
        """
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM results")
                cursor.execute("DELETE FROM scans")
                cursor.execute("DELETE FROM domains")
                cursor.execute("DELETE FROM managed_domains")
                cursor.execute("DELETE FROM alerts")
                self.conn.commit()
            logger.info("Cleared all scan data for fresh start")
        except sqlite3.Error as e:
            logger.error("Failed to clear scan data: %s", e)

    def delete_domain_history(self, domain: str) -> int:
        """Delete all scan history for a specific domain.

        Returns the number of result rows deleted.
        """
        d = domain.lower().strip()
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM results WHERE domain = ?", (d,))
                deleted = cursor.rowcount
                cursor.execute("DELETE FROM domains WHERE domain = ?", (d,))
                cursor.execute("DELETE FROM alerts WHERE domain = ?", (d,))
                self.conn.commit()
            logger.info("Deleted %d history records for %s", deleted, d)
            return deleted
        except sqlite3.Error as e:
            logger.error("Failed to delete history for %s: %s", d, e)
            raise

    def get_all_settings(self) -> Dict[str, str]:
        """Get all settings as a dictionary."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, value FROM settings")
        return {row["key"]: row["value"] for row in cursor.fetchall()}

    # =========================================================================
    # Alerts & Drift Detection
    # =========================================================================

    def create_alert(
        self, domain: str, alert_type: str, severity: str,
        message: str, details: str = ""
    ) -> int:
        """Create a new alert."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    """INSERT INTO alerts (domain, alert_type, severity, message, details, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (domain, alert_type, severity, message, details, now),
                )
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to create alert for %s: %s", domain, e)
            raise

    def get_alerts(
        self, unacknowledged_only: bool = True, limit: int = 50
    ) -> List[Dict]:
        """Get alerts, newest first."""
        cursor = self.conn.cursor()
        if unacknowledged_only:
            cursor.execute(
                """SELECT * FROM alerts WHERE acknowledged = 0
                   ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            )
        else:
            cursor.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cursor.fetchall()]

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
                    (now, alert_id),
                )
                self.conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error("Failed to acknowledge alert %d: %s", alert_id, e)
            raise

    def get_alert_count(self) -> int:
        """Get count of unacknowledged alerts."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0")
        return cursor.fetchone()["c"]


# Singleton instance for convenience
_db_instance: Optional[AuroraDatabase] = None
_db_lock = threading.Lock()


def get_database(db_path: Optional[Path] = None) -> AuroraDatabase:
    """Get or create the database instance (thread-safe)."""
    global _db_instance
    if _db_instance is None:
        with _db_lock:
            # Double-checked locking
            if _db_instance is None:
                _db_instance = AuroraDatabase(db_path)
    return _db_instance
