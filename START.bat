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

REM ── Create / repair virtual environment ────────────────────────────
echo [*] Setting up environment...
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creating virtual environment (first run - may take a moment^)...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo         Make sure the 'venv' module is installed (it ships with Python).
        pause
        exit /b 1
    )
)

REM ── Activate venv ──────────────────────────────────────────────────
call .venv\Scripts\activate.bat

REM ── Install / update dependencies ──────────────────────────────────
echo [*] Installing dependencies...
python -m pip install --quiet --upgrade pip 2>nul
python -m pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo.
    echo [ERROR] Dependency install failed.
    echo         Check your internet connection and try again.
    pause
    exit /b 1
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
echo [*] Starting Web Dashboard on port %PORT% ...
echo.
echo     Dashboard : http://127.0.0.1:%PORT%
echo     Test Hub  : http://127.0.0.1:%PORT%/test
echo     Settings  : http://127.0.0.1:%PORT%/settings
echo     Generator : http://127.0.0.1:%PORT%/generator
echo.
echo     Press Ctrl+C in this window to stop the server.
echo.

REM ── Open browser after a short delay so server can bind ────────────
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:%PORT%"

REM ── Launch server (blocks until Ctrl+C) ────────────────────────────
python -m uvicorn app.dashboard:app --host 127.0.0.1 --port %PORT%
echo.
echo Goodbye!
pause
