"""Prepare and run the local dashboard using only Python's standard library.

This local HTTP launcher is deliberately restricted to 127.0.0.1. Internet-facing
installations need the HTTPS deployment described in docs/DEPLOYMENT.md instead.
Existing environments are never deleted, repaired by removal, or copied elsewhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser


PROJECT_ROOT = Path(__file__).resolve().parent
WINDOWS = os.name == "nt"
MIN_PYTHON = (3, 10)
MIN_NODE = (22, 12, 0)
PROBE_IMPORTS = "import uvicorn, fastapi, dns, rich, requests, matplotlib, numpy, reportlab"


class LaunchError(Exception):
    """An expected setup problem with a useful next step for the operator."""


def run(command: list[str], cwd: Path, *, capture: bool = False) -> str:
    """Use argument lists so spaces in paths are not interpreted as commands."""
    try:
        result = subprocess.run(
            command, cwd=cwd, check=True, text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        # Captured output can contain credentials from package registry settings.
        name = Path(command[0]).name
        raise LaunchError(
            f"{name} could not finish {' '.join(command[1:3])}. "
            "Check the output above, your internet connection, and folder permissions."
        ) from exc
    return result.stdout.strip() if capture else ""


def node_version(raw: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", raw.strip())
    if not match:
        raise LaunchError("Could not read the Node.js version. Install Node.js 22.12 or newer.")
    return tuple(int(part) for part in match.groups())


def prerequisites(root: Path) -> tuple[str, str]:
    if sys.version_info[:2] < MIN_PYTHON:
        raise LaunchError("Python 3.10 or newer is required. Install it and try again.")
    for relative in ("requirements.txt", "src/app/dashboard.py", "frontend/package-lock.json"):
        if not (root / relative).is_file():
            raise LaunchError(f"Missing {relative}. Download or clone the complete project again.")
    node = shutil.which("node")
    npm = shutil.which("npm.cmd" if WINDOWS else "npm")
    if not node or not npm:
        raise LaunchError("Install Node.js 22.12 or newer with npm from https://nodejs.org/.")
    if node_version(run([node, "--version"], root, capture=True)) < MIN_NODE:
        raise LaunchError("Node.js 22.12 or newer is required. Install a supported Node.js release.")
    try:
        with tempfile.TemporaryFile(dir=root):
            pass
    except OSError as exc:
        raise LaunchError(
            "This project folder is not writable. Move your own copy to a writable local "
            "folder, then try again. NorthFlux will not move or replace your files."
        ) from exc
    return node, npm


def npm_command(node: str, npm: str) -> list[str]:
    if not WINDOWS:
        return [npm]
    # Avoid shell expansion of &, ! and spaces by running npm's JS entry point.
    npm_cli = Path(npm).parent / "node_modules/npm/bin/npm-cli.js"
    if not npm_cli.is_file():
        raise LaunchError(
            "The npm CLI could not be located beside npm.cmd. Repair your Node.js "
            "installation, or run the manual setup in docs/DEPLOYMENT.md."
        )
    return [node, str(npm_cli)]


def venv_python(root: Path) -> Path:
    return root / ".venv" / ("Scripts/python.exe" if WINDOWS else "bin/python")


def ensure_venv(root: Path) -> Path:
    environment = root / ".venv"
    if environment.is_symlink():
        raise LaunchError(".venv is a link. Use a project-local virtual environment instead.")
    if not environment.exists():
        print("[1/3] Creating a project-local Python environment...", flush=True)
        try:
            run([sys.executable, "-m", "venv", str(environment)], root)
        except LaunchError as exc:
            raise LaunchError(
                "Python could not create .venv. On Linux, install your Python version's "
                "venv package (often python3-venv). Check that this folder is writable. "
                "If a partial .venv remains, rename it before retrying."
            ) from exc
    python = venv_python(root)
    if not python.is_file():
        raise LaunchError(
            "The existing .venv is incomplete or belongs to another operating system. "
            "Rename it to keep a backup, then run this launcher again. No files were deleted."
        )
    try:
        run([str(python), "-c", "import sys; assert sys.version_info >= (3, 10)"], root,
            capture=True)
    except LaunchError as exc:
        raise LaunchError(
            "The existing .venv cannot run a supported Python. Rename it to keep a backup, "
            "then launch again with Python 3.10 or newer. No files were deleted."
        ) from exc
    return python


def fingerprint(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def prepare(root: Path, node: str, npm: str) -> Path:
    python = ensure_venv(root)
    cache_file = root / ".venv/.northflux-setup.json"
    try:
        previous = json.loads(cache_file.read_text(encoding="utf-8"))
        if not isinstance(previous, dict):
            previous = {}
    except (OSError, ValueError):
        previous = {}
    current = {
        "python": fingerprint([root / "requirements.txt"]),
        "frontend": fingerprint([root / "frontend/package.json", root / "frontend/package-lock.json"]),
        "node": run([node, "--version"], root, capture=True),
    }
    python_ready = previous.get("python") == current["python"]
    if python_ready:
        try:
            run([str(python), "-c", PROBE_IMPORTS], root, capture=True)
            run([str(python), "-m", "pip", "check"], root, capture=True)
        except LaunchError:
            python_ready = False
    if not python_ready:
        print("[1/3] Installing Python dependencies (first run needs internet)...", flush=True)
        run([str(python), "-m", "pip", "install", "-r", str(root / "requirements.txt")], root)
    print("[2/3] Preparing the React dashboard...", flush=True)
    command = npm_command(node, npm)
    if (previous.get("frontend") != current["frontend"]
            or previous.get("node") != current["node"]
            or not (root / "frontend/node_modules/vite/package.json").is_file()):
        run([*command, "ci"], root / "frontend")
    # Rebuild after every pull, including when dependencies have not changed.
    run([*command, "run", "build"], root / "frontend")
    cache_file.write_text(json.dumps(current), encoding="utf-8")
    return python


def local_environment(root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(root / "src")
    environment["NORTHFLUX_SERVE_REACT"] = "true"
    environment["NORTHFLUX_FRONTEND_DIST"] = str(root / "frontend/dist")
    return environment


def check_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise LaunchError("Choose a port between 1 and 65535, for example --port 8081.")
    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise LaunchError(f"Port {port} is unavailable. Try --port {port + 1 if port < 65535 else 8080}.") from exc


def wait_ready(process: subprocess.Popen, url: str, timeout: float = 45) -> bool:
    deadline = time.monotonic() + timeout
    # Loopback health checks must not go through a system HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while process.poll() is None and time.monotonic() < deadline:
        try:
            with opener.open(url + "/ready", timeout=1) as response:
                if response.status == 200:
                    return True
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    return False


def stop_server(process: subprocess.Popen) -> None:
    if process.poll() is None:
        if WINDOWS:
            # The Windows venv launcher may have a child interpreter. A group
            # signal reaches both and lets Uvicorn close SQLite and log handles.
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT)
            except OSError:
                process.terminate()
        else:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def verify_react_assets(opener, url: str, html: str) -> None:
    assets = re.findall(r'(?:src|href)="(/assets/[^"\s]+\.(?:js|css))"', html)
    if ('<div id="root"></div>' not in html
            or not any(path.endswith(".js") for path in assets)
            or not any(path.endswith(".css") for path in assets)):
        raise LaunchError("The compiled React dashboard was not served.")
    for asset in assets:
        with opener.open(url + asset, timeout=5) as response:
            content_type = response.headers.get("Content-Type", "").split(";")[0]
            expected = {"text/css"} if asset.endswith(".css") else {"text/javascript", "application/javascript"}
            if content_type not in expected or not response.read(1):
                raise LaunchError("A compiled dashboard asset is missing or has the wrong content type.")


def serve(root: Path, python: Path, port: int, *, no_browser: bool, smoke: bool) -> int:
    environment = local_environment(root)
    url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="northflux-startup-check-") as temporary:
        if smoke:
            # Never load real monitoring state or DNS credentials during a check.
            environment.update({
                "NORTHFLUX_ENV": "development", "NORTHFLUX_DEMO_MODE": "false",
                "DASH_TOKEN": "northflux-local-startup-check-not-a-production-secret",
                "NORTHFLUX_PUBLIC_ORIGIN": url,
                "CF_API_TOKEN": "", "CF_ZONE_ID": "", "CF_ACCOUNT_ID": "",
                "CF_API_KEY": "", "CF_EMAIL": "",
            })
            for kind in ("STATE", "REPORTS", "LOGS"):
                environment[f"NORTHFLUX_{kind}_DIR"] = str(Path(temporary) / kind.lower())
        print(f"[3/3] Starting NorthFlux Security: {url}", flush=True)
        process = subprocess.Popen(
            [str(python), "-m", "uvicorn", "app.dashboard:app", "--host", "127.0.0.1",
             "--port", str(port)], cwd=root, env=environment,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0,
        )
        try:
            if not wait_ready(process, url):
                raise LaunchError("The dashboard did not become ready. Check the server output above.")
            if smoke:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(url + "/health", timeout=5) as response:
                    if json.load(response).get("ok") is not True:
                        raise LaunchError("The health check did not report a healthy application.")
                with opener.open(url, timeout=5) as response:
                    html = response.read().decode("utf-8")
                verify_react_assets(opener, url, html)
                print("Startup check passed: health, readiness, React page, JavaScript, and stylesheet.", flush=True)
                return 0
            print("Local use only. Press Ctrl+C to stop. See docs/DEPLOYMENT.md for HTTPS hosting.", flush=True)
            if not environment.get("DASH_TOKEN", "").strip():
                print("No sign-in token is set; access is limited to this computer's loopback interface.", flush=True)
            if not no_browser:
                threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
            return process.wait()
        except KeyboardInterrupt:
            print("\nStopping NorthFlux Security...", flush=True)
            return 0
        finally:
            stop_server(process)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and run NorthFlux locally on Windows or Linux.")
    parser.add_argument("--port", type=int, default=os.environ.get("NORTHFLUX_PORT", "8080"))
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--setup-only", action="store_true", help="install and build without starting a server")
    mode.add_argument("--smoke-test", action="store_true", help="check startup with temporary data, then stop")
    args = parser.parse_args(argv)
    try:
        if (not args.setup_only and not args.smoke_test
                and os.environ.get("NORTHFLUX_ENV", "").strip().lower() == "production"):
            raise LaunchError(
                "This launcher serves local HTTP, but NORTHFLUX_ENV is production (HTTPS required). "
                "Use docs/DEPLOYMENT.md for production, or unset NORTHFLUX_ENV for local use."
            )
        if not args.setup_only:
            check_port(args.port)
        node, npm = prerequisites(PROJECT_ROOT)
        python = prepare(PROJECT_ROOT, node, npm)
        if args.setup_only:
            print("Setup complete. Run this launcher again to open NorthFlux Security.", flush=True)
            return 0
        return serve(PROJECT_ROOT, python, args.port, no_browser=args.no_browser, smoke=args.smoke_test)
    except LaunchError as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"\n[ERROR] Setup or startup failed ({type(exc).__name__}). Check folder permissions "
              "and the output above; see docs/DEPLOYMENT.md.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nSetup cancelled. Run this launcher again when ready.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
