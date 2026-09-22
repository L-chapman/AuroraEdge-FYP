"""Cross-platform launcher safety; CI also runs the real clean-checkout flow."""

import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
from unittest.mock import Mock

import pytest


spec = importlib.util.spec_from_file_location("northflux_start", Path(__file__).parents[1] / "start.py")
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


class Response(io.BytesIO):
    def __init__(self, content, content_type):
        super().__init__(content)
        self.headers = {"Content-Type": content_type}


@pytest.mark.parametrize("value,expected", [("v22.12.0", (22, 12, 0)), ("24.0.1", (24, 0, 1))])
def test_node_version(value, expected):
    assert launch.node_version(value) == expected


@pytest.mark.parametrize("value", ["v22", "not installed", "v24.0.0-rc1"])
def test_node_version_rejects_invalid_or_prerelease(value):
    with pytest.raises(launch.LaunchError, match="Node.js"):
        launch.node_version(value)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "NorthFlux checkout with spaces"
    for relative in ("requirements.txt", "src/app/dashboard.py", "frontend/package-lock.json",
                     "frontend/package.json", "frontend/node_modules/vite/package.json"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    return root


def test_prerequisites_reject_old_python_before_installing(project, monkeypatch):
    monkeypatch.setattr(launch.sys, "version_info", (3, 9, 20))
    with pytest.raises(launch.LaunchError, match="Python 3.10"):
        launch.prerequisites(project)


@pytest.mark.parametrize("version", ["v20.19.0", "v22.11.0"])
def test_prerequisites_reject_old_node(project, monkeypatch, version):
    monkeypatch.setattr(launch.shutil, "which", lambda value: value)
    monkeypatch.setattr(launch, "run", lambda *args, **kwargs: version)
    with pytest.raises(launch.LaunchError, match="Node.js 22.12"):
        launch.prerequisites(project)


def test_prerequisites_explain_missing_node(project, monkeypatch):
    monkeypatch.setattr(launch.shutil, "which", lambda value: None)
    with pytest.raises(launch.LaunchError, match="with npm"):
        launch.prerequisites(project)


def test_prerequisites_reject_incomplete_checkout(tmp_path):
    with pytest.raises(launch.LaunchError, match="complete project"):
        launch.prerequisites(tmp_path)


def test_broken_venv_is_preserved(project):
    marker = project / ".venv/keep-me.txt"
    marker.parent.mkdir()
    marker.write_text("important user content", encoding="utf-8")
    with pytest.raises(launch.LaunchError, match="Rename it"):
        launch.ensure_venv(project)
    assert marker.read_text(encoding="utf-8") == "important user content"


def test_venv_creation_uses_explicit_argument_list(project, monkeypatch):
    calls = []
    def fake_run(command, cwd, **kwargs):
        calls.append((command, cwd))
        python = launch.venv_python(project)
        python.parent.mkdir(parents=True, exist_ok=True)
        python.touch()
        return ""
    monkeypatch.setattr(launch, "run", fake_run)
    assert launch.ensure_venv(project) == launch.venv_python(project)
    assert calls[0] == ([launch.sys.executable, "-m", "venv", str(project / ".venv")], project)


def test_windows_npm_does_not_use_shell(project, monkeypatch):
    npm_cli = project / "node_modules/npm/bin/npm-cli.js"
    npm_cli.parent.mkdir(parents=True)
    npm_cli.touch()
    monkeypatch.setattr(launch, "WINDOWS", True)
    assert launch.npm_command("node.exe", str(project / "npm.cmd")) == ["node.exe", str(npm_cli)]


def test_missing_windows_npm_cli_has_actionable_error(project, monkeypatch):
    monkeypatch.setattr(launch, "WINDOWS", True)
    with pytest.raises(launch.LaunchError, match="Repair your Node.js"):
        launch.npm_command("node.exe", str(project / "npm.cmd"))


def test_posix_npm_uses_executable_without_shell(monkeypatch):
    monkeypatch.setattr(launch, "WINDOWS", False)
    assert launch.npm_command("node", "/a path/npm") == ["/a path/npm"]


def test_run_uses_arguments_and_does_not_leak_captured_output(project, monkeypatch):
    runner = Mock(side_effect=subprocess.CalledProcessError(1, "node", stderr="private-token"))
    monkeypatch.setattr(launch.subprocess, "run", runner)
    with pytest.raises(launch.LaunchError) as error:
        launch.run(["node", "--version"], project, capture=True)
    assert "private-token" not in str(error.value)
    assert runner.call_args.args[0] == ["node", "--version"]
    assert not runner.call_args.kwargs.get("shell")


def test_setup_cache_skips_unchanged_dependencies_but_rebuilds(project, monkeypatch):
    python = launch.venv_python(project)
    python.parent.mkdir(parents=True)
    python.touch()
    calls = []
    def fake_run(command, cwd, **kwargs):
        calls.append(command)
        return "v24.0.0" if command[-1] == "--version" else ""
    monkeypatch.setattr(launch, "run", fake_run)
    monkeypatch.setattr(launch, "npm_command", lambda *args: ["npm"])
    launch.prepare(project, "node", "npm")
    assert ["npm", "ci"] in calls
    assert any("install" in command for command in calls)
    calls.clear()
    launch.prepare(project, "node", "npm")
    assert ["npm", "ci"] not in calls
    assert not any("install" in command for command in calls)
    assert ["npm", "run", "build"] in calls
    (project / "requirements.txt").write_text("changed-content", encoding="utf-8")
    calls.clear()
    launch.prepare(project, "node", "npm")
    assert any("install" in command for command in calls)


def test_failed_build_does_not_cache_success(project, monkeypatch):
    python = launch.venv_python(project)
    python.parent.mkdir(parents=True)
    python.touch()
    def fake_run(command, cwd, **kwargs):
        if "build" in command:
            raise launch.LaunchError("build failed")
        return "v24.0.0"
    monkeypatch.setattr(launch, "run", fake_run)
    monkeypatch.setattr(launch, "npm_command", lambda *args: ["npm"])
    with pytest.raises(launch.LaunchError, match="build failed"):
        launch.prepare(project, "node", "npm")
    assert not (project / ".venv/.northflux-setup.json").exists()


def test_changed_installed_python_version_invalidates_setup_cache(project, monkeypatch):
    python = launch.venv_python(project)
    python.parent.mkdir(parents=True)
    python.touch()
    calls = []
    inventory = ["original-pinned-environment"]

    def fake_run(command, cwd, **kwargs):
        calls.append(command)
        if command[-1] == launch.ENVIRONMENT_PROBE:
            return inventory[0]
        return "v24.0.0" if command[-1] == "--version" else ""

    monkeypatch.setattr(launch, "run", fake_run)
    monkeypatch.setattr(launch, "npm_command", lambda *args: ["npm"])
    launch.prepare(project, "node", "npm")
    calls.clear()
    # Imports and pip check can still pass after replacing a directly pinned
    # package with a different, internally compatible version.
    inventory[0] = "manually-changed-package-version"
    launch.prepare(project, "node", "npm")
    assert any("install" in command for command in calls)


def test_inconsistent_new_python_install_is_not_cached(project, monkeypatch):
    python = launch.venv_python(project)
    python.parent.mkdir(parents=True)
    python.touch()

    def fake_run(command, cwd, **kwargs):
        if command[-2:] == ["pip", "check"]:
            raise launch.LaunchError("inconsistent dependencies")
        return "v24.0.0" if command[-1] == "--version" else ""

    monkeypatch.setattr(launch, "run", fake_run)
    with pytest.raises(launch.LaunchError, match="inconsistent dependencies"):
        launch.prepare(project, "node", "npm")
    assert not (project / ".venv/.northflux-setup.json").exists()


def test_incomplete_cached_frontend_install_is_repaired(project, monkeypatch):
    python = launch.venv_python(project)
    python.parent.mkdir(parents=True)
    python.touch()
    calls = []

    def fake_run(command, cwd, **kwargs):
        calls.append(command)
        if command[1:2] == ["ls"]:
            raise launch.LaunchError("missing TypeScript despite existing Vite")
        return "v24.0.0" if command[-1] == "--version" else ""

    monkeypatch.setattr(launch, "run", fake_run)
    monkeypatch.setattr(launch, "npm_command", lambda *args: ["npm"])
    launch.prepare(project, "node", "npm")
    calls.clear()
    launch.prepare(project, "node", "npm")
    assert ["npm", "ls", "--depth=0", "--json"] in calls
    assert ["npm", "ci"] in calls


def test_local_environment_preserves_auth_and_does_not_read_dotenv(project, monkeypatch):
    monkeypatch.setenv("DASH_TOKEN", "user-supplied-token")
    (project / ".env").write_text("DASH_TOKEN=must-not-load", encoding="utf-8")
    environment = launch.local_environment(project)
    assert environment["DASH_TOKEN"] == "user-supplied-token"
    assert environment["NORTHFLUX_SERVE_REACT"] == "true"
    assert environment["PYTHONPATH"] == str(project / "src")


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_invalid_ports_are_rejected(port):
    with pytest.raises(launch.LaunchError, match="between 1 and 65535"):
        launch.check_port(port)


def test_busy_port_has_actionable_error():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with pytest.raises(launch.LaunchError, match="unavailable"):
            launch.check_port(listener.getsockname()[1])


def test_production_mode_not_silently_downgraded(monkeypatch, capsys):
    monkeypatch.setenv("NORTHFLUX_ENV", "production")
    assert launch.main(["--no-browser"]) == 1
    assert "HTTPS required" in capsys.readouterr().err


def test_setup_only_never_starts_server(project, monkeypatch):
    monkeypatch.setattr(launch, "PROJECT_ROOT", project)
    monkeypatch.setattr(launch, "prerequisites", lambda root: ("node", "npm"))
    monkeypatch.setattr(launch, "prepare", lambda *args: launch.venv_python(project))
    server = Mock()
    monkeypatch.setattr(launch, "serve", server)
    assert launch.main(["--setup-only"]) == 0
    server.assert_not_called()


def test_smoke_test_is_isolated_and_stops_server(project, monkeypatch):
    monkeypatch.setattr(launch, "WINDOWS", False)
    monkeypatch.setenv("CF_API_TOKEN", "user-secret")
    monkeypatch.setenv("NORTHFLUX_STATE_DIR", str(project / "real-state"))
    process = Mock()
    process.poll.return_value = None
    spawn = Mock(return_value=process)
    monkeypatch.setattr(launch.subprocess, "Popen", spawn)
    monkeypatch.setattr(launch, "wait_ready", lambda *args: True)
    responses = [io.BytesIO(json.dumps({"ok": True}).encode()),
                 io.BytesIO(b'<div id="root"></div><script src="/assets/index.js"></script>'
                            b'<link href="/assets/index.css" rel="stylesheet">'),
                 Response(b"console.log('NorthFlux')", "text/javascript; charset=utf-8"),
                 Response(b"body { color: white }", "text/css")]
    opener = Mock()
    opener.open.side_effect = responses
    monkeypatch.setattr(launch.urllib.request, "build_opener", lambda *args: opener)
    assert launch.serve(project, launch.venv_python(project), 8081, no_browser=True, smoke=True) == 0
    env = spawn.call_args.kwargs["env"]
    assert env["CF_API_TOKEN"] == ""
    assert env["NORTHFLUX_STATE_DIR"] != str(project / "real-state")
    assert not Path(env["NORTHFLUX_STATE_DIR"]).parent.exists()
    assert spawn.call_args.args[0][-4:] == ["--host", "127.0.0.1", "--port", "8081"]
    process.terminate.assert_called_once()


def test_asset_check_rejects_spa_fallback_for_missing_javascript():
    opener = Mock()
    opener.open.return_value = Response(b"<!doctype html>", "text/html")
    with pytest.raises(launch.LaunchError, match="asset is missing"):
        launch.verify_react_assets(opener, "http://127.0.0.1:8080",
            '<div id="root"></div><script src="/assets/app.js"></script><link href="/assets/app.css">')


@pytest.mark.parametrize("html", ["legacy dashboard", '<div id="root"></div>',
                                 '<div id="root"></div><script src="/assets/app.js"></script>'])
def test_asset_check_requires_built_react_with_script_and_stylesheet(html):
    with pytest.raises(launch.LaunchError, match="compiled React"):
        launch.verify_react_assets(Mock(), "http://127.0.0.1:8080", html)


def test_server_is_stopped_when_readiness_fails(project, monkeypatch):
    monkeypatch.setattr(launch, "WINDOWS", False)
    process = Mock()
    process.poll.return_value = None
    monkeypatch.setattr(launch.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(launch, "wait_ready", lambda *args: False)
    with pytest.raises(launch.LaunchError, match="did not become ready"):
        launch.serve(project, launch.venv_python(project), 8081, no_browser=True, smoke=True)
    process.terminate.assert_called_once()


def test_windows_shutdown_signals_the_whole_environment_group(monkeypatch):
    monkeypatch.setattr(launch, "WINDOWS", True)
    monkeypatch.setattr(launch.signal, "CTRL_BREAK_EVENT", 1, raising=False)
    process = Mock()
    process.poll.return_value = None
    launch.stop_server(process)
    process.send_signal.assert_called_once_with(1)
    process.terminate.assert_not_called()
