"""SQLite storage for scans, settings, alerts, and history."""

import sqlite3
import json
import logging
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional, Any
import random

from app.runtime_paths import get_state_dir

logger = logging.getLogger("northflux.database")


def _with_connection_lock(method):
    """Serialise a method that directly uses the shared SQLite connection."""

    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return locked

# Default database path relative to project root. ``STATE_DIR`` remains public
# for compatibility; _default_db_path() resolves the environment on each call
# so tests and embedded deployments can select storage before first DB use.
STATE_DIR = get_state_dir()
DEFAULT_DB_PATH = STATE_DIR / "northflux.db"
LEGACY_DB_PATH = STATE_DIR / "auroraedge.db"


def _default_db_path() -> Path:
    """Use the new database name while preserving existing local installations."""
    state_dir = get_state_dir()
    default_db_path = state_dir / "northflux.db"
    legacy_db_path = state_dir / "auroraedge.db"
    if default_db_path.exists() or not legacy_db_path.exists():
        return default_db_path
    logger.info(
        "Using legacy database at %s; migrate it to %s when convenient",
        legacy_db_path,
        default_db_path,
    )
    return legacy_db_path


class NorthFluxDatabase:
    """SQLite database for NorthFlux Security scan results."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialise the database connection."""
        self.db_path = db_path or _default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit &#8212; close connection."""
        self.close()
        return False

    def _init_db(self):
        """Create database tables if they don't exist."""
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.row_factory = sqlite3.Row
        # A single SQLite connection is shared by the FastAPI worker threads.
        # SQLite permits that only when application code serialises every use
        # of the connection; concurrent cursors on one connection can otherwise
        # produce false empty reads or ``InterfaceError`` failures.
        self._lock = threading.RLock()
        self._data_generation = 0

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

        # Additive migration: retain every existing row and mark old scans as
        # complete because earlier releases did not record this distinction.
        for table, column in (("results", "scan_incomplete"), ("managed_domains", "last_scan_incomplete")):
            columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
            if column not in columns:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")

        self.conn.commit()
        logger.info("Database initialised at %s", self.db_path)

    def start_scan(
        self, source_file: Optional[str] = None, notes: Optional[str] = None
    ) -> str:
        """
        Start a new scan session.

        Returns:
            scan_id: Unique identifier for this scan
        """
        # Include microseconds + random suffix to guarantee uniqueness
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

        with self._lock:
            try:
                self._save_result_inner(scan_id, domain, result, evaluation, combined, now)
            except Exception:
                # The result row and domain summary are one operation. A later
                # unrelated commit must never persist half a failed save.
                self.conn.rollback()
                logger.exception("Failed to save result for %s", domain)
                raise

    def _save_result_inner(
        self, scan_id: str, domain: str, result: Dict, evaluation: Dict,
        combined: Dict, now: str, *, commit: bool = True
    ):
        """Inner implementation of save_result (must be called under _lock)."""
        incomplete = bool(result.get("scan_incomplete"))
        score = None if incomplete else evaluation.get("score", 0)
        grade = None if incomplete else evaluation.get("grade", "")
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
                raw_json, scan_incomplete
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "ERROR" if incomplete else evaluation.get("severity", ""),
                score,
                grade,
                evaluation.get("violations", ""),
                evaluation.get("violation_count", 0),
                evaluation.get("advice", ""),
                result.get("notes", ""),
                json.dumps(combined),
                int(incomplete),
            ),
        )

        # Update domains tracking table
        cursor.execute("SELECT * FROM domains WHERE domain = ?", (domain,))
        existing = cursor.fetchone()
        if existing:
            best_values = [value for value in (existing["best_score"], score) if value is not None]
            worst_values = [value for value in (existing["worst_score"], score) if value is not None]
            best = max(best_values) if best_values else None
            worst = min(worst_values) if worst_values else None
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

        if commit:
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

    @_with_connection_lock
    def get_data_generation(self) -> int:
        """Return the generation used to invalidate in-flight scan persistence."""
        return self._data_generation

    def write_scan_results(
        self,
        entries: List[tuple[str, Dict[str, Any], Dict[str, Any]]],
        *,
        notes: str,
        expected_generation: Optional[int] = None,
        save_history: bool = True,
        manage_domains: bool = False,
        update_managed: bool = False,
        managed_notes: str = "",
    ) -> bool:
        """Persist evaluated results as one locked database operation.

        Destructive clear, history-delete, and managed-domain removal requests
        increment ``_data_generation``. Results from a scan that started before
        one of those actions are discarded instead of silently recreating data
        after the operator was told deletion had finished.
        """
        with self._lock:
            if (
                expected_generation is not None
                and expected_generation != self._data_generation
            ):
                return False

            cursor = self.conn.cursor()
            try:
                scan_id = None
                if save_history and entries:
                    scan_id = (
                        datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
                        + f"_{random.randint(0, 9999):04d}"
                    )
                    started_at = datetime.now(timezone.utc).isoformat()
                    cursor.execute(
                        "INSERT INTO scans (scan_id, started_at, notes) VALUES (?, ?, ?)",
                        (scan_id, started_at, notes),
                    )
                    for domain, result, evaluation in entries:
                        combined = {**result, **evaluation, "domain": domain}
                        self._save_result_inner(
                            scan_id,
                            domain,
                            result,
                            evaluation,
                            combined,
                            datetime.now(timezone.utc).isoformat(),
                            commit=False,
                        )
                    cursor.execute(
                        "UPDATE scans SET completed_at = ?, domain_count = ? WHERE scan_id = ?",
                        (datetime.now(timezone.utc).isoformat(), len(entries), scan_id),
                    )

                if manage_domains:
                    added_at = datetime.now(timezone.utc).isoformat()
                    for domain, _result, _evaluation in entries:
                        cursor.execute(
                            """INSERT INTO managed_domains (domain, added_at, notes)
                               VALUES (?, ?, ?)
                               ON CONFLICT(domain) DO UPDATE SET
                                   is_active = 1,
                                   notes = excluded.notes""",
                            (domain.lower().strip(), added_at, managed_notes),
                        )

                if manage_domains or update_managed:
                    for domain, result, evaluation in entries:
                        self._update_managed_domain_scan_inner(
                            cursor,
                            domain,
                            evaluation.get("grade", "F"),
                            evaluation.get("score", 0),
                            scan_incomplete=bool(result.get("scan_incomplete")),
                        )

                self.conn.commit()
                return True
            except Exception as error:
                # Keep the batch atomic even when data preparation fails before
                # SQLite executes a statement (for example, JSON serialisation
                # of an unexpected scanner value).  Leaving that transaction
                # open would allow a later, unrelated commit to persist a
                # partial scan row.
                self.conn.rollback()
                logger.error("Failed to persist scan results: %s", error)
                raise

    @contextmanager
    def snapshot(self):
        """Hold a consistent read snapshot across several database methods."""
        with self._lock:
            yield self

    @_with_connection_lock
    def ping(self) -> bool:
        """Check that the shared connection can execute a trivial query."""
        self.conn.execute("SELECT 1").fetchone()
        return True

    def get_latest_results(self, limit: int = 100) -> List[Dict]:
        """Get the most recent scan results."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT * FROM results
                ORDER BY scanned_at DESC, id DESC
                LIMIT ?
            """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_domain_history(self, domain: str, limit: int = 20) -> List[Dict]:
        """Get historical scan results for a specific domain."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT * FROM results
                WHERE domain = ?
                ORDER BY scanned_at DESC, id DESC
                LIMIT ?
            """,
                (domain, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_scan_results(self, scan_id: str) -> List[Dict]:
        """Get all results from a specific scan."""
        with self._lock:
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
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT * FROM scans
                ORDER BY started_at DESC, id DESC
                LIMIT ?
            """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    @_with_connection_lock
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

    @_with_connection_lock
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

    @_with_connection_lock
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

    @_with_connection_lock
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    # =========================================================================
    # Managed Domains (SME onboarding)
    # =========================================================================

    @_with_connection_lock
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
            # Already exists &#8212; reactivate if inactive
            cursor.execute(
                """UPDATE managed_domains SET is_active = 1, notes = ?
                   WHERE domain = ?""",
                (notes, domain.lower().strip()),
            )
            self.conn.commit()
            return {"ok": True, "domain": domain, "reactivated": True}

    def add_managed_domain_if_generation(
        self,
        domain: str,
        notes: str,
        expected_generation: int,
    ) -> bool:
        """Add/reactivate a domain unless scan data was cleared meanwhile."""
        with self._lock:
            if expected_generation != self._data_generation:
                return False
            cursor = self.conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """INSERT INTO managed_domains (domain, added_at, notes)
                   VALUES (?, ?, ?)
                   ON CONFLICT(domain) DO UPDATE SET
                       is_active = 1,
                       notes = excluded.notes""",
                (domain.lower().strip(), now, notes),
            )
            self.conn.commit()
            return True

    @_with_connection_lock
    def remove_managed_domain(self, domain: str) -> bool:
        """Soft-delete a managed domain (deactivate)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE managed_domains SET is_active = 0 WHERE domain = ?",
            (domain.lower().strip(),),
        )
        self.conn.commit()
        removed = cursor.rowcount > 0
        if removed:
            # A monitoring/onboarding scan that started before this removal
            # must not reactivate or update the domain after the operator has
            # been told it was removed.
            self._data_generation += 1
        return removed

    @_with_connection_lock
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
                previous = self._update_managed_domain_scan_inner(
                    cursor, domain, grade, score
                )
                self.conn.commit()
        except sqlite3.Error as e:
            logger.error("Failed to update managed domain %s: %s", domain, e)
            raise
        return previous

    def _update_managed_domain_scan_inner(
        self,
        cursor: sqlite3.Cursor,
        domain: str,
        grade: str,
        score: int,
        *,
        scan_incomplete: bool = False,
    ) -> Dict[str, Any]:
        """Update managed-domain metadata inside the caller's lock/transaction."""
        clean_domain = domain.lower().strip()
        cursor.execute(
            "SELECT last_grade, last_score FROM managed_domains WHERE domain = ?",
            (clean_domain,),
        )
        row = cursor.fetchone()
        previous_grade = row["last_grade"] if row else None
        previous_score = row["last_score"] if row else None
        cursor.execute(
            """UPDATE managed_domains
               SET last_scan_at = ?, last_grade = ?, last_score = ?,
                   previous_grade = ?, previous_score = ?, last_scan_incomplete = ?
               WHERE domain = ?""",
            (
                datetime.now(timezone.utc).isoformat(),
                None if scan_incomplete else grade,
                None if scan_incomplete else score,
                previous_grade,
                previous_score,
                int(scan_incomplete),
                clean_domain,
            ),
        )
        return {
            "previous_grade": previous_grade,
            "previous_score": previous_score,
        }

    # =========================================================================
    # Settings
    # =========================================================================

    @_with_connection_lock
    def get_setting(self, key: str, default: str = "") -> str:
        """Get a setting value."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        """Set one setting using the same atomic path as a settings form."""
        self.set_settings({key: value})

    def set_settings(self, values: Dict[str, str]):
        """Save a validated settings form together or roll back every change."""
        with self._lock:
            try:
                now = datetime.now(timezone.utc).isoformat()
                self.conn.executemany(
                    """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                       ON CONFLICT(key) DO UPDATE SET
                           value = excluded.value, updated_at = excluded.updated_at""",
                    [(key, value, now) for key, value in values.items()],
                )
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                logger.exception("Failed to save settings")
                raise

    def delete_setting(self, key: str) -> bool:
        """Delete one setting, returning whether a row was removed."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM settings WHERE key = ?", (key,))
                removed = cursor.rowcount > 0
                self.conn.commit()
                return removed
        except sqlite3.Error as e:
            logger.error("Failed to delete setting %s: %s", key, e)
            raise

    def clear_scan_data(self):
        """Clear all scan-related data (scans, results, domains, managed_domains, alerts).

        Preserves application settings. Production credentials should be
        supplied through the runtime environment rather than this database.
        """
        with self._lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM results")
                cursor.execute("DELETE FROM scans")
                cursor.execute("DELETE FROM domains")
                cursor.execute("DELETE FROM managed_domains")
                cursor.execute("DELETE FROM alerts")
                self.conn.commit()
                self._data_generation += 1
            except Exception as error:
                self.conn.rollback()
                logger.error("Failed to clear scan data: %s", error)
                raise
        logger.info("Cleared all scan data for fresh start")

    def delete_domain_history(self, domain: str) -> int:
        """Delete all scan history for a specific domain.

        Returns the number of result rows deleted.
        """
        d = domain.lower().strip()
        with self._lock:
            try:
                cursor = self.conn.cursor()
                affected_scans = [row[0] for row in cursor.execute(
                    "SELECT DISTINCT scan_id FROM results WHERE domain = ?", (d,)
                )]
                cursor.execute("DELETE FROM results WHERE domain = ?", (d,))
                deleted = cursor.rowcount
                cursor.execute("DELETE FROM domains WHERE domain = ?", (d,))
                cursor.execute("DELETE FROM alerts WHERE domain = ?", (d,))
                cursor.execute(
                    """UPDATE managed_domains
                       SET last_scan_at = NULL, last_grade = NULL, last_score = NULL,
                           previous_grade = NULL, previous_score = NULL, last_scan_incomplete = 0
                       WHERE domain = ?""",
                    (d,),
                )
                # Only prune completed sessions affected by this deletion;
                # unrelated (or still running CLI) sessions must survive.
                for scan_id in affected_scans:
                    cursor.execute(
                        """UPDATE scans SET domain_count =
                           (SELECT COUNT(*) FROM results WHERE scan_id = ?)
                           WHERE scan_id = ?""", (scan_id, scan_id)
                    )
                    cursor.execute(
                        """DELETE FROM scans WHERE scan_id = ?
                           AND completed_at IS NOT NULL AND domain_count = 0""",
                        (scan_id,),
                    )
                self.conn.commit()
                # Treat domain-history deletion like the global clear for
                # concurrency purposes.  Otherwise an earlier in-flight scan
                # can silently recreate the history moments after deletion.
                self._data_generation += 1
            except Exception as error:
                self.conn.rollback()
                logger.error("Failed to delete history for %s: %s", d, error)
                raise
        logger.info("Deleted %d history records for %s", deleted, d)
        return deleted

    @_with_connection_lock
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
        message: str, details: str = "", expected_generation: Optional[int] = None
    ) -> int:
        """Create a new alert."""
        try:
            with self._lock:
                if (
                    expected_generation is not None
                    and expected_generation != self._data_generation
                ):
                    return 0
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

    @_with_connection_lock
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

    @_with_connection_lock
    def get_alert_count(self) -> int:
        """Get count of unacknowledged alerts."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0")
        return cursor.fetchone()["c"]


# Compatibility alias for integrations written before the product rename.
AuroraDatabase = NorthFluxDatabase


# Singleton instance for convenience
_db_instance: Optional[NorthFluxDatabase] = None
_db_lock = threading.Lock()


def get_database(db_path: Optional[Path] = None) -> NorthFluxDatabase:
    """Get or create the database instance (thread-safe)."""
    global _db_instance
    if _db_instance is None:
        with _db_lock:
            # Double-checked locking
            if _db_instance is None:
                _db_instance = NorthFluxDatabase(db_path)
    return _db_instance
