@echo off
setlocal enabledelayedexpansion
title NorthFlux Security
echo.
echo ===================================================================
echo        NorthFlux Security
echo        Email security assessment and remediation
echo ===================================================================
echo.

REM ── Navigate to wherever this .bat file lives ──────────────────────
cd /d "%~dp0"

REM ── Ensure we are running from a writable location ──────────────────
set "RUN_DIR=%cd%"
set "WRITE_TEST=%RUN_DIR%\.__northflux_write_test.tmp"
copy nul "%WRITE_TEST%" >nul 2>&1
if errorlevel 1 (
    echo [WARN] This location is not writable: %RUN_DIR%
    echo [*] Copying project to local writable path and relaunching...
    set "LOCAL_RUN_DIR=%LOCALAPPDATA%\NorthFlux Security\app"
    if not exist "%LOCAL_RUN_DIR%" mkdir "%LOCAL_RUN_DIR%" >nul 2>&1
    robocopy "%RUN_DIR%" "%LOCAL_RUN_DIR%" /E /NFL /NDL /NJH /NJS /NP >nul
    if errorlevel 8 (
        echo [ERROR] Failed to copy project to: %LOCAL_RUN_DIR%
        echo         Copy the folder manually to your Desktop/Documents, then re-run START.bat.
        pause
        exit /b 1
    )
    echo [OK] Relaunching from: %LOCAL_RUN_DIR%
    start "" "%LOCAL_RUN_DIR%\START.bat"
    exit /b 0
)
del "%WRITE_TEST%" >nul 2>&1

REM ── Locate a working Python (>= 3.10) ─────────────────────────────
set "PY="
set "PY_VER="
call :probe_python python
if not defined PY call :probe_python py
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
echo [1/5] Python ready.
echo [*] Please wait while NorthFlux Security prepares the local environment.
echo     First launch can take a minute or two while dependencies are checked.

REM ── Cloudflare credentials ─────────────────────────────────────────
REM Credentials may be supplied through environment variables or the
REM authenticated Settings page. START.bat never writes secrets to disk.
if defined CF_API_TOKEN if defined CF_ZONE_ID (
    echo [OK] Cloudflare credentials detected in the current environment.
) else (
    echo [INFO] Cloudflare credentials are not set. Scanning remains available.
)

REM ── Create / repair virtual environment ────────────────────────────
echo [2/5] Setting up environment...
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
        set "VENV_DIR=%LOCALAPPDATA%\NorthFlux Security\venv"
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
    echo [3/5] Python dependencies already up to date.
) else (
    echo [3/5] Installing Python dependencies...
    echo     Live install output is shown below so you can see progress.
    echo [*] Upgrading pip...
    "%VENV_PY%" -m pip install --upgrade pip
    if errorlevel 1 (
        echo.
        echo [ERROR] Pip upgrade failed.
        echo         Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo [*] Installing required packages from requirements.txt...
    "%VENV_PY%" -m pip install --progress-bar on -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Dependency install failed.
        echo         Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo !REQ_STAMP!>"%REQ_CACHE%"
)

REM -- Build the React dashboard ------------------------------------------------
echo [4/5] Preparing React dashboard...
where node >nul 2>&1
if errorlevel 1 goto :node_missing
where npm >nul 2>&1
if errorlevel 1 goto :node_missing
node -e "const [major,minor]=process.versions.node.split('.').map(Number);process.exit(major>22||(major===22&&minor>=12)?0:1)"
if errorlevel 1 (
    echo [ERROR] NorthFlux requires Node.js 22.12 or newer to build the React dashboard.
    echo         Install the current Node.js LTS release from https://nodejs.org/
    pause
    exit /b 1
)
if not exist "frontend\package-lock.json" (
    echo [ERROR] Frontend dependency lockfile is missing.
    pause
    exit /b 1
)
for %%F in ("frontend\package-lock.json") do set "NPM_STAMP=%%~tF-%%~zF"
set "NPM_CACHE=%VENV_DIR%\npm_stamp.txt"
set "SKIP_NPM_INSTALL=0"
if exist "%NPM_CACHE%" if exist "frontend\node_modules" (
    set /p CACHED_NPM_STAMP=<"%NPM_CACHE%"
    if "!CACHED_NPM_STAMP!"=="!NPM_STAMP!" set "SKIP_NPM_INSTALL=1"
)
pushd frontend
if "!SKIP_NPM_INSTALL!"=="0" (
    echo [*] Installing locked frontend dependencies...
    call npm ci
    if errorlevel 1 (
        popd
        echo [ERROR] Frontend dependency install failed.
        pause
        exit /b 1
    )
)
echo [*] Building the production React application...
call npm run build
if errorlevel 1 (
    popd
    echo [ERROR] React dashboard build failed.
    pause
    exit /b 1
)
popd
if "!SKIP_NPM_INSTALL!"=="0" echo !NPM_STAMP!>"%NPM_CACHE%"

REM ── Environment variables ──────────────────────────────────────────
set "PYTHONPATH=%cd%\src"
set "NORTHFLUX_SERVE_REACT=true"

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
echo [5/5] Starting Web Dashboard on port %PORT% ...
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

goto :eof

:node_missing
echo [ERROR] Node.js and npm were not found.
echo         Install Node.js 22.12 or newer from https://nodejs.org/ and re-run START.bat.
pause
exit /b 1

:probe_python
set "PY_CANDIDATE=%~1"
set "PY_PROBE_OUT="

for /f "delims=" %%v in ('%PY_CANDIDATE% --version 2^>^&1') do (
    if not defined PY_PROBE_OUT set "PY_PROBE_OUT=%%v"
)
if not defined PY_PROBE_OUT goto :eof

echo %PY_PROBE_OUT% | findstr /r /c:"^Python [0-9][0-9]*\.[0-9][0-9]*" >nul 2>&1
if errorlevel 1 goto :eof

%PY_CANDIDATE% -c "import venv" >nul 2>&1
if errorlevel 1 goto :eof

set "PY=%PY_CANDIDATE%"
for /f "tokens=2 delims= " %%v in ("%PY_PROBE_OUT%") do set "PY_VER=%%v"
goto :eof
