"""Centralised, environment-overridable runtime storage paths."""

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def resolve_runtime_dir(env_name: str, default_name: str) -> Path:
    """Resolve a configured runtime directory without changing the process cwd.

    Relative overrides remain project-relative so service and local launches have
    identical behaviour. Empty values intentionally fall back to the documented
    project directory.
    """

    configured = (os.environ.get(env_name) or "").strip()
    path = Path(configured).expanduser() if configured else PROJECT_ROOT / default_name
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def get_state_dir() -> Path:
    return resolve_runtime_dir("NORTHFLUX_STATE_DIR", "state")


def get_reports_dir() -> Path:
    return resolve_runtime_dir("NORTHFLUX_REPORTS_DIR", "reports")


def get_logs_dir() -> Path:
    return resolve_runtime_dir("NORTHFLUX_LOGS_DIR", "logs")


STATE_DIR = get_state_dir()
REPORTS_DIR = get_reports_dir()
INDEXED_REPORTS_DIR = REPORTS_DIR / "indexed"
LOGS_DIR = get_logs_dir()
