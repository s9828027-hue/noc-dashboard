@echo off
rem Double-click to start the NOC dashboard (see start_noc.ps1 for options)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_noc.ps1" %*
if errorlevel 1 pause
