@echo off
REM install.bat -- thin wrapper around install.ps1
REM Run: install.bat [--no-build] [--no-tools] [--no-tunnel] [--check]
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
exit /b %ERRORLEVEL%