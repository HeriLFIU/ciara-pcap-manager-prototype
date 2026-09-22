@echo off
setlocal
cd /d "%~dp0"
title CIARA PCAP Analyzer

where uv >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 'uv' was not found in your PATH.
    echo Please install uv or ensure it is added to your PATH.
    pause
    exit /b 1
)

uv run python scripts/launch_app.py
