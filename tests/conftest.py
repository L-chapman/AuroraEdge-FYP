import sys
import os
import tempfile
import logging
from pathlib import Path

import pytest

# Ensure `src` is on sys.path so tests can import the `app` package
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def pytest_configure(config):
    """Never let a test import select the operator's storage or credentials."""
    config._northflux_runtime = tempfile.TemporaryDirectory(prefix="northflux-tests-")
    root = Path(config._northflux_runtime.name)
    values = {
        "NORTHFLUX_STATE_DIR": str(root / "state"),
        "NORTHFLUX_REPORTS_DIR": str(root / "reports"),
        "NORTHFLUX_LOGS_DIR": str(root / "logs"),
        "NORTHFLUX_ENV": "development",
        "NORTHFLUX_DEMO_MODE": "false",
        "NORTHFLUX_SERVE_REACT": "false",
        "NORTHFLUX_PUBLIC_ORIGIN": "",
        "DASH_TOKEN": "",
        **{key: "" for key in (
            "CF_API_TOKEN", "CF_API_KEY", "CF_EMAIL", "CF_ZONE_ID", "CF_ACCOUNT_ID",
        )},
    }
    config._northflux_previous_env = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    for name in ("state", "reports", "logs"):
        (root / name).mkdir()


@pytest.fixture(autouse=True)
def isolated_authentication_state(monkeypatch):
    """Replace the one application-owned store, never aliases to its records."""
    from app.auth_state import AuthenticationState
    import app.dashboard as dashboard

    monkeypatch.setattr(dashboard.app.state, "authentication", AuthenticationState())


@pytest.fixture(autouse=True)
def isolated_default_database(tmp_path, monkeypatch):
    """Unmocked API/CLI calls use a fresh disposable database per test."""
    import app.database as database

    monkeypatch.setenv("NORTHFLUX_STATE_DIR", str(tmp_path / "default-state"))
    monkeypatch.setattr(database, "_db_instance", None)
    yield
    if database._db_instance is not None:
        database._db_instance.close()


@pytest.fixture(autouse=True)
def no_live_provider_requests(monkeypatch):
    """Tests must supply their own HTTP mocks, never inherited live accounts."""
    import requests

    def blocked(*args, **kwargs):
        raise AssertionError("Live HTTP requests are disabled in tests; use a mock")

    monkeypatch.setattr(requests.sessions.Session, "request", blocked)


@pytest.fixture(autouse=True)
def no_external_sockets(monkeypatch):
    """Keep resolver/SMTP/HTTPS mistakes inside this process, not the network."""
    import ipaddress
    import socket
    import dns.resolver

    def blocked_dns(*args, **kwargs):
        raise AssertionError("Live DNS is disabled in tests; supply a resolver mock")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", blocked_dns)
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto

    def check_address(sock, address):
        if sock.family not in {socket.AF_INET, socket.AF_INET6}:
            return
        try:
            is_loopback = ipaddress.ip_address(address[0]).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise AssertionError("External sockets are disabled in tests; supply a network mock")

    def connect(sock, address):
        check_address(sock, address)
        return original_connect(sock, address)

    def connect_ex(sock, address):
        check_address(sock, address)
        return original_connect_ex(sock, address)

    def sendto(sock, data, *args):
        check_address(sock, args[-1])
        return original_sendto(sock, data, *args)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", sendto)


def pytest_unconfigure(config):
    runtime = getattr(config, "_northflux_runtime", None)
    if runtime is not None:
        root = Path(runtime.name).resolve()
        loggers = [logging.getLogger(), *logging.Logger.manager.loggerDict.values()]
        for logger in loggers:
            if not isinstance(logger, logging.Logger):
                continue
            for handler in logger.handlers[:]:
                filename = getattr(handler, "baseFilename", None)
                if filename and Path(filename).resolve().is_relative_to(root):
                    logger.removeHandler(handler)
                    handler.close()
        runtime.cleanup()
        for key, value in config._northflux_previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
