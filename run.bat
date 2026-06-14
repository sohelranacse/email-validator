@echo off
setlocal enabledelayedexpansion
title Email Validator - Auto Setup

echo.
echo ==================================================
echo   Best Real Email Validator
echo   (Auto-installs dependencies on first run)
echo ==================================================
echo.

:: Find a working Python command (python or the Windows py launcher)
set "PYTHON_CMD="
where python >nul 2>nul && set "PYTHON_CMD=python"
if not defined PYTHON_CMD (
    where py >nul 2>nul && set "PYTHON_CMD=py -3"
)

if not defined PYTHON_CMD (
    echo [ERROR] Python was not found on this PC.
    echo.
    echo Please install Python 3.9 or newer from:
    echo https://www.python.org/downloads/
    echo.
    echo IMPORTANT: During installation, CHECK the box:
    echo     "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

echo [OK] Python detected.
%PYTHON_CMD% --version
echo.

:: Create a virtual environment on first run (keeps your system Python clean)
if not exist ".venv\Scripts\python.exe" (
    echo [SETUP] Creating virtual environment in .venv ...
    %PYTHON_CMD% -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo Try running this as Administrator, or install Python with "Add to PATH".
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
    echo.
)

:: Always ensure dependencies are installed / up to date (safe & fast if already present)
echo [SETUP] Installing / updating required packages...
echo This only happens the first time or when requirements.txt changes.
echo.

".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
".venv\Scripts\python.exe" -m pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install dependencies.
    echo You can try manually:
    echo     .venv\Scripts\python -m pip install -r requirements.txt
    pause
    exit /b 1
)

echo.
echo [OK] All dependencies are ready.
echo.

:: Open browser (non-blocking)
echo Starting server and opening browser...
start "" http://127.0.0.1:5051

:: Run using the venv's Python (guaranteed to have the packages)
".venv\Scripts\python.exe" app.py

echo.
echo Server stopped.
pause