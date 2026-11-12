@echo off
rem Double-click to stop everything started by start_noc
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop_noc.ps1"
pause
