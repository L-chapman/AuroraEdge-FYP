"""
AuroraEdge Logging Configuration
Centralized logging setup for all application modules.

Features:
- Console and file logging
- Rotating log files (max 5MB, 3 backups)
- Separate logs for scanner, dashboard, and audit
- JSON structured logging option
- Color-coded console output
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# Paths
ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Log files
MAIN_LOG = LOG_DIR / "auroraedge.log"
SCANNER_LOG = LOG_DIR / "scanner.log"
DASHBOARD_LOG = LOG_DIR / "dashboard.log"
AUDIT_LOG = LOG_DIR / "audit.log"
ERROR_LOG = LOG_DIR / "errors.log"

# Log levels from environment
LOG_LEVEL = os.environ.get("AURORAEDGE_LOG_LEVEL", "INFO").upper()


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with color-coded output for console.
    Works on Windows with colorama or in terminals supporting ANSI.
    """

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        record.name = f"\033[34m{record.name}{self.RESET}"  # Blue
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """
    Structured JSON formatter for log aggregation and analysis.
    """

    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "domain"):
            log_entry["domain"] = record.domain

        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms

        return json.dumps(log_entry)


def create_rotating_handler(
    log_file: Path,
    formatter: logging.Formatter,
    max_bytes: int = 5_000_000,
    backup_count: int = 3,
) -> RotatingFileHandler:
    """
    Create a rotating file handler.

    Args:
        log_file: Path to log file
        formatter: Log formatter to use
        max_bytes: Max file size before rotation (default 5MB)
        backup_count: Number of backup files to keep

    Returns:
        Configured RotatingFileHandler
    """
    handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(formatter)
    return handler


def setup_logging(level: str = None, json_format: bool = False) -> None:
    """
    Configure application-wide logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_format: Use JSON structured logging for files

    Usage:
        from src.app.logging_config import setup_logging
        setup_logging(level="DEBUG")
    """
    level = level or LOG_LEVEL
    numeric_level = getattr(logging, level, logging.INFO)

    # Standard formatter for files
    file_formatter = logging.Formatter(
        "%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Optional JSON formatter
    if json_format:
        file_formatter = JSONFormatter()

    # Console formatter with colors
    console_formatter = ColoredFormatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s", datefmt="%H:%M:%S"
    )

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear any existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Main log file (all logs)
    main_handler = create_rotating_handler(MAIN_LOG, file_formatter)
    main_handler.setLevel(numeric_level)
    root_logger.addHandler(main_handler)

    # Error log file (ERROR and above only)
    error_handler = create_rotating_handler(ERROR_LOG, file_formatter)
    error_handler.setLevel(logging.ERROR)
    root_logger.addHandler(error_handler)

    # Module-specific loggers
    configure_module_loggers(file_formatter, numeric_level)

    # Log startup message
    root_logger.info(f"Logging initialized at {level} level")
    root_logger.debug(f"Log directory: {LOG_DIR}")


def configure_module_loggers(formatter: logging.Formatter, level: int) -> None:
    """Configure loggers for specific modules."""

    # Scanner logger
    scanner_logger = logging.getLogger("auroraedge.scanner")
    scanner_handler = create_rotating_handler(SCANNER_LOG, formatter)
    scanner_handler.setLevel(level)
    scanner_logger.addHandler(scanner_handler)

    # Dashboard logger
    dashboard_logger = logging.getLogger("auroraedge.dashboard")
    dashboard_handler = create_rotating_handler(DASHBOARD_LOG, formatter)
    dashboard_handler.setLevel(level)
    dashboard_logger.addHandler(dashboard_handler)

    # Audit logger (always INFO level for important events)
    audit_logger = logging.getLogger("auroraedge.audit")
    audit_handler = create_rotating_handler(AUDIT_LOG, formatter)
    audit_handler.setLevel(logging.INFO)
    audit_logger.addHandler(audit_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger for a module.

    Args:
        name: Module name (will be prefixed with 'auroraedge.')

    Returns:
        Configured Logger instance

    Usage:
        logger = get_logger("scanner")
        logger.info("Scanning domain", extra={"domain": "example.com"})
    """
    if not name.startswith("auroraedge."):
        name = f"auroraedge.{name}"
    return logging.getLogger(name)


class ScanLogger:
    """
    Context manager for logging scan operations with timing.

    Usage:
        with ScanLogger("example.com") as log:
            # perform scan
            log.info("SPF record found")
        # Automatically logs completion with duration
    """

    def __init__(self, domain: str):
        self.domain = domain
        self.logger = get_logger("scanner")
        self.start_time = None

    def __enter__(self):
        self.start_time = datetime.now(timezone.utc)
        self.logger.info(f"Starting scan for {self.domain}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now(timezone.utc) - self.start_time).total_seconds() * 1000
        if exc_type:
            self.logger.error(
                f"Scan failed for {self.domain}",
                extra={"domain": self.domain, "duration_ms": duration},
                exc_info=True,
            )
        else:
            self.logger.info(
                f"Scan completed for {self.domain} in {duration:.0f}ms",
                extra={"domain": self.domain, "duration_ms": duration},
            )
        return False  # Don't suppress exceptions

    def info(self, msg: str) -> None:
        self.logger.info(msg, extra={"domain": self.domain})

    def warning(self, msg: str) -> None:
        self.logger.warning(msg, extra={"domain": self.domain})

    def error(self, msg: str) -> None:
        self.logger.error(msg, extra={"domain": self.domain})


def log_scan_event(domain: str, event: str, level: str = "INFO", **kwargs) -> None:
    """
    Quick function to log scan events.

    Args:
        domain: Domain being scanned
        event: Event description
        level: Log level
        **kwargs: Additional context
    """
    logger = get_logger("scanner")
    log_func = getattr(logger, level.lower(), logger.info)

    msg = f"[{domain}] {event}"
    if kwargs:
        context = " | ".join(f"{k}={v}" for k, v in kwargs.items())
        msg = f"{msg} | {context}"

    log_func(msg, extra={"domain": domain, **kwargs})


def log_audit_event(action: str, user: str = "system", **kwargs) -> None:
    """
    Log an audit event (for security and compliance).

    Args:
        action: Action performed
        user: User or system performing action
        **kwargs: Additional context
    """
    logger = get_logger("audit")

    msg = f"AUDIT | {action} | user={user}"
    if kwargs:
        context = " | ".join(f"{k}={v}" for k, v in kwargs.items())
        msg = f"{msg} | {context}"

    logger.info(msg)


# Auto-initialize logging when imported
if not logging.getLogger().handlers:
    setup_logging()
