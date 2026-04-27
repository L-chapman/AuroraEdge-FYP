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

REM ── Cloudflare credentials bootstrap (single-file flow) ────────────
set "CF_SECRET_FILE=%cd%\state\cf_secrets.local.cmd"
if exist "%CF_SECRET_FILE%" (
    call "%CF_SECRET_FILE%" >nul 2>&1
)

if not defined CF_API_TOKEN (
    if not exist "state" mkdir state
    echo.
    echo [*] Cloudflare credentials are optional for scans, but required for Auto-Fix demo.
    set /p "CF_API_TOKEN=Enter CF_API_TOKEN (leave blank to skip): "
    if defined CF_API_TOKEN (
        set /p "CF_ZONE_ID=Enter CF_ZONE_ID: "
        set /p "CF_ACCOUNT_ID=Enter CF_ACCOUNT_ID (optional, press Enter to skip): "
        if defined CF_API_TOKEN if defined CF_ZONE_ID (
            >"%CF_SECRET_FILE%" (
                echo @echo off
                echo set "CF_API_TOKEN=%CF_API_TOKEN%"
                echo set "CF_ZONE_ID=%CF_ZONE_ID%"
                echo set "CF_ACCOUNT_ID=%CF_ACCOUNT_ID%"
            )
            echo [OK] Saved Cloudflare credentials for future launches.
        ) else (
            echo [!] Incomplete Cloudflare credentials. Auto-Fix will stay disabled.
        )
    )
)
if defined CF_API_TOKEN if defined CF_ZONE_ID (
    echo [OK] Cloudflare credentials loaded for Auto-Fix.
) else (
    echo [!] Cloudflare credentials not loaded. Scanning works, Auto-Fix is disabled.
)

REM ── Create / repair virtual environment ────────────────────────────
echo [2/4] Setting up environment...
set "VENV_DIR=%cd%\.venv"
set "VENV_ACTIVATE=%VENV_DIR%\Scripts\activate.bat"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
set "VENV_LABEL=.venv"
if not exist "%VENV_ACTIVATE%" (
    echo [*] Creating virtual environment - first run, may take a moment...
    %PY% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [WARN] Could not create .venv in this folder ^(common on synced drives^).
        echo [*] Falling back to local user environment under LOCALAPPDATA...
        set "VENV_DIR=%LOCALAPPDATA%\AuroraEdge\venv_submission"
        set "VENV_ACTIVATE=!VENV_DIR!\Scripts\activate.bat"
        set "VENV_PY=!VENV_DIR!\Scripts\python.exe"
        set "VENV_LABEL=!VENV_DIR!"
        if not exist "!VENV_ACTIVATE!" (
            %PY% -m venv "!VENV_DIR!"
            if errorlevel 1 (
                echo [ERROR] Failed to create virtual environment.
                echo         Make sure the 'venv' module is installed. It ships with Python.
                pause
                exit /b 1
            )
        )
    )
)

REM ── Activate venv ──────────────────────────────────────────────────
if not exist "%VENV_PY%" (
    echo [ERROR] Virtual environment python missing at: %VENV_PY%
    pause
    exit /b 1
)
"%VENV_PY%" --version >nul 2>&1
if errorlevel 1 (
    echo [!] Existing virtual environment is not usable on this machine.
    echo [*] Rebuilding %VENV_LABEL% using the local Python installation...
    rmdir /s /q "%VENV_DIR%" 2>nul
    %PY% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to rebuild virtual environment.
        echo         Delete %VENV_LABEL% manually and try again.
        pause
        exit /b 1
    )
    "%VENV_PY%" --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Rebuilt virtual environment still cannot run Python.
        echo         Delete %VENV_LABEL% manually and recreate it with: %PY% -m venv "%VENV_DIR%"
        pause
        exit /b 1
    )
)
echo [*] Using virtual environment: %VENV_LABEL%

REM ── Install / update dependencies (skip if requirements unchanged) ──
for %%F in (requirements.txt) do set "REQ_STAMP=%%~tF-%%~zF"
set "REQ_CACHE=%VENV_DIR%\req_stamp.txt"
set "SKIP_INSTALL=0"
if exist "%REQ_CACHE%" (
    set /p CACHED_STAMP=<"%REQ_CACHE%"
    if "!CACHED_STAMP!"=="!REQ_STAMP!" set "SKIP_INSTALL=1"
)
if "!SKIP_INSTALL!"=="1" (
    "%VENV_PY%" -c "import uvicorn, fastapi" >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Environment cache exists but required packages are missing.
        echo [*] Reinstalling dependencies...
        set "SKIP_INSTALL=0"
    )
)
if "!SKIP_INSTALL!"=="1" (
    echo [3/4] Dependencies already up to date.
) else (
    echo [3/4] Installing dependencies...
    echo     This window may look quiet for a short time. That is normal.
    "%VENV_PY%" -m pip install --quiet --upgrade pip 2>nul
    "%VENV_PY%" -m pip install --quiet -r requirements.txt
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
"%VENV_PY%" -m uvicorn app.dashboard:app --host 127.0.0.1 --port %PORT%
echo.
echo Goodbye!
pause
