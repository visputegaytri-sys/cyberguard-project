@echo off
title CyberGuard - Cyber Security Threat Detection System
cd /d "%~dp0"

echo ==========================================
echo        CYBERGUARD - STARTING...
echo ==========================================
echo.

python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Python/pip is not installed or could not be found.
    echo Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

start "" http://127.0.0.1:5000
python app.py
pause
