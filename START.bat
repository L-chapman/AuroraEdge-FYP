@echo off
setlocal DisableDelayedExpansion
title NorthFlux Security
if defined NORTHFLUX_PYTHON goto :configured_python
where py >nul 2>&1
if not errorlevel 1 goto :python_launcher
where python >nul 2>&1
if not errorlevel 1 goto :python_command
echo [ERROR] Install Python 3.10 or newer from https://www.python.org/downloads/
echo         Enable "Add Python to PATH", then open this file again.
if "%~1"=="" pause
exit /b 1

:configured_python
"%NORTHFLUX_PYTHON%" "%~dp0start.py" %*
goto :finish

:python_launcher
py -3 "%~dp0start.py" %*
goto :finish

:python_command
python "%~dp0start.py" %*
goto :finish

:finish
set "NORTHFLUX_EXIT=%errorlevel%"
if not "%NORTHFLUX_EXIT%"=="0" if "%~1"=="" pause
exit /b %NORTHFLUX_EXIT%
