@echo off
setlocal enabledelayedexpansion
title AuroraEdge Security
echo.
echo ===================================================================
echo        AuroraEdge Security
echo        Final Year Project - Leon Chapman
echo ===================================================================
echo.

REM ── Navigate to wherever this .bat file lives ──────────────────────
cd /d "%~dp0"

REM ── Locate a working Python (>= 3.10) ─────────────────────────────
set "PY="
where python >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set "PY_VER=%%v"
    set "PY=python"
)
if not defined PY (
    where py >nul 2>&1
    if not errorlevel 1 (
        for /f "tokens=2 delims= " %%v in ('py --version 2^>^&1') do set "PY_VER=%%v"
        set "PY=py"
    )
)
if not defined PY (
    echo.
    echo [ERROR] Python not found on this machine!
    echo.
    echo   Please install Python 3.10 or newer:
    echo     https://www.python.org/downloads/
    echo.
    echo   During install, tick "Add Python to PATH", then re-run this file.
    echo.
    pause
    exit /b 1
)
echo [OK] Found %PY% %PY_VER%
echo [1/4] Python ready.
echo [*] Please wait while AuroraEdge prepares the local environment.
echo     First launch can take a minute or two while dependencies are checked.

REM ── Create / repair virtual environment ────────────────────────────
echo [2/4] Setting up environment...
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment - first run, may take a moment...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo         Make sure the 'venv' module is installed. It ships with Python.
        pause
        exit /b 1
    )
)

REM ── Activate venv ──────────────────────────────────────────────────
call .venv\Scripts\activate.bat
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Existing virtual environment is not usable on this machine.
    echo [*] Rebuilding .venv using the local Python installation...
    rmdir /s /q .venv 2>nul
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to rebuild virtual environment.
        echo         Delete .venv manually and try again.
        pause
        exit /b 1
    )
    call .venv\Scripts\activate.bat
    python --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Rebuilt virtual environment still cannot run Python.
        echo         Delete .venv manually and recreate it with: %PY% -m venv .venv
        pause
        exit /b 1
    )
)

REM ── Install / update dependencies (skip if requirements unchanged) ──
for %%F in (requirements.txt) do set "REQ_STAMP=%%~tF-%%~zF"
set "REQ_CACHE=.venv\req_stamp.txt"
set "SKIP_INSTALL=0"
if exist "%REQ_CACHE%" (
    set /p CACHED_STAMP=<"%REQ_CACHE%"
    if "!CACHED_STAMP!"=="!REQ_STAMP!" set "SKIP_INSTALL=1"
)
if "!SKIP_INSTALL!"=="1" (
    echo [3/4] Dependencies already up to date.
) else (
    echo [3/4] Installing dependencies...
    echo     This window may look quiet for a short time. That is normal.
    python -m pip install --quiet --upgrade pip 2>nul
    python -m pip install --quiet -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Dependency install failed.
        echo         Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo !REQ_STAMP!>"%REQ_CACHE%"
)

REM ── Environment variables ──────────────────────────────────────────
set "PYTHONPATH=%cd%\src"

REM ── Create data directories ────────────────────────────────────────
if not exist "reports" mkdir reports
if not exist "state"   mkdir state
if not exist "logs"    mkdir logs

REM ── Pick port (8080 first, fall back to 8081-8085) ─────────────────
set "PORT=8080"
for %%P in (8080 8081 8082 8083 8084 8085) do (
    netstat -aon 2>nul | findstr ":%%P " | findstr "LISTEN" >nul 2>&1
    if errorlevel 1 (
        set "PORT=%%P"
        goto :port_ok
    )
)
:port_ok

echo.
echo ===================================================================
echo  Setup Complete!
echo ===================================================================
echo.
echo [4/4] Starting Web Dashboard on port %PORT% ...
echo.
echo     Dashboard : http://127.0.0.1:%PORT%
echo     Test Hub  : http://127.0.0.1:%PORT%/test
echo     Settings  : http://127.0.0.1:%PORT%/settings
echo     Generator : http://127.0.0.1:%PORT%/generator
echo.
echo [*] The browser will open automatically in a few seconds.
echo     If it does not open, visit: http://127.0.0.1:%PORT%/test
echo.
echo     Press Ctrl+C in this window to stop the server.
echo.

REM ── Open browser when the app is actually ready ────────────────────
start "" powershell -WindowStyle Hidden -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$url = 'http://127.0.0.1:%PORT%/health'; $open = 'http://127.0.0.1:%PORT%/test'; for ($i = 0; $i -lt 45; $i++) { try { $null = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2; Start-Process $open; break } catch { Start-Sleep -Seconds 1 } }"

REM ── Launch server (blocks until Ctrl+C) ────────────────────────────
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port %PORT%
echo.
echo Goodbye!
pause
