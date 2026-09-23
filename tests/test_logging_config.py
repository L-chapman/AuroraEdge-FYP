"""Logging configuration tests use only temporary files and restore host loggers."""

import importlib.util
import json
import logging
from pathlib import Path

import pytest

import app.runtime_paths as runtime_paths


@pytest.fixture
def log_config(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "LOGS_DIR", tmp_path / "logs")
    loggers = [logging.getLogger(name) for name in ("", "northflux.scanner", "northflux.dashboard", "northflux.audit")]
    previous = [(logger, list(logger.handlers), logger.level) for logger in loggers]
    spec = importlib.util.spec_from_file_location("northflux_logging_test", Path(__file__).parents[1] / "src/app/logging_config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        for logger, handlers, level in previous:
            for handler in list(logger.handlers):
                if handler not in handlers:
                    logger.removeHandler(handler)
                    handler.close()
            logger.handlers[:] = handlers
            logger.setLevel(level)


def test_console_colour_does_not_mutate_record_or_corrupt_json(log_config):
    record = logging.LogRecord("northflux.scanner", logging.INFO, __file__, 1, "Completed", (), None)
    coloured = log_config.ColoredFormatter("%(name)s %(levelname)s %(message)s").format(record)
    assert "\x1b[" in coloured
    assert record.name == "northflux.scanner"
    assert record.levelname == "INFO"
    plain = json.loads(log_config.JSONFormatter().format(record))
    assert plain["logger"] == "northflux.scanner"
    assert plain["level"] == "INFO"


def test_reconfiguration_does_not_duplicate_module_logs(log_config):
    log_config.setup_logging()
    old = list(logging.getLogger("northflux.scanner").handlers)
    log_config.setup_logging()
    log_config.get_logger("scanner").warning("one scan warning")
    assert log_config.SCANNER_LOG.read_text(encoding="utf-8").count("one scan warning") == 1
    assert all(handler.stream is None for handler in old)


def test_audit_records_survive_warning_console_threshold(log_config):
    log_config.setup_logging(level="WARNING", json_format=True)
    log_config.log_audit_event("test-action")
    entries = [json.loads(line) for line in log_config.AUDIT_LOG.read_text(encoding="utf-8").splitlines()]
    assert any("test-action" in entry["message"] for entry in entries)
    assert all(entry["level"] == "INFO" for entry in entries)


def test_setup_preserves_external_handlers_and_accepts_lowercase_level(log_config):
    root = logging.getLogger()
    external = logging.NullHandler()
    root.addHandler(external)
    try:
        log_config.setup_logging(level="warning")
        assert external in root.handlers
        assert root.level == logging.WARNING
    finally:
        root.removeHandler(external)
