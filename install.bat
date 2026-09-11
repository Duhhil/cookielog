@echo off
REM ==============================================================================
REM install.bat -- cookielog dependency installer
REM EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
REM
REM Installs everything needed to run cookielog:
REM   1. Python pip packages (cryptography, websocket-client)
REM   2. MSVC Build Tools 2022 (C++ workload) -- via winget
REM   3. CLI tools: Clink, fzf, bat, ripgrep -- via winget
REM   4. cmd_init.cmd (Linux-style aliases) to %USERPROFILE%\bin\
REM   5. Autorun registry key for cmd_init.cmd
REM   6. Builds the payload (loader.exe + ckdll.dll)
REM
REM Usage:
REM   install.bat              :: install everything
REM   install.bat --no-build   :: skip MSVC + build step (Python + CLI tools only)
REM   install.bat --no-tools   :: skip CLI tools (fzf, bat, ripgrep, clink)
REM   install.bat --check      :: check what's installed, don't install anything
REM
REM Run from the cookielog directory.
REM ==============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ==============================================================================
echo   cookielog -- dependency installer
echo   EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
echo ==============================================================================
echo.

set "DO_BUILD=1"
set "DO_TOOLS=1"
set "CHECK_ONLY=0"

:parse
if "%1"=="" goto start
if /i "%1"=="--no-build" set "DO_BUILD=0"
if /i "%1"=="--no-tools" set "DO_TOOLS=0"
if /i "%1"=="--check" (set "CHECK_ONLY=1" & set "DO_BUILD=0" & set "DO_TOOLS=0")
shift
if not "%1"=="" goto parse

:start

REM --- check Python ---
where /q python 2>nul
if %errorlevel%==1 goto no_python
echo [+] Python found in PATH
goto check_winget

:no_python
echo [-] Python not found in PATH
echo     Install Python 3.8+ from https://python.org and re-run this script.
if "%CHECK_ONLY%"=="0" (
    echo [*] Attempting to install Python via winget...
    winget install Python.Python.3.14 --accept-source-agreements --accept-package-agreements
    if errorlevel 1 goto python_fail
    echo [+] Python installed. Re-run this script.
    exit /b 0
)
:python_fail
exit /b 1

:check_winget
where /q winget 2>nul
if %errorlevel%==1 goto no_winget
echo [+] winget found
goto step1

:no_winget
echo [-] winget not found
echo     winget is included in Windows App Installer (Microsoft Store app).
exit /b 1

REM ==============================================================================
:step1
echo.
echo [1/6] Python pip packages...
echo ==============================================================================
if "%CHECK_ONLY%"=="1" (
    pip list 2>nul | findstr /i "cryptography websocket-client"
    goto step2
)

pip install -r requirements.txt 2>nul
if %errorlevel%==1 (
    echo [-] pip install failed, trying: python -m pip install -r requirements.txt
    python -m pip install -r requirements.txt
    if %errorlevel%==1 echo [-] pip install still failed. Check your Python installation.
) else (
    echo [+] pip packages installed
)

REM ==============================================================================
:step2
echo.
echo [2/6] MSVC Build Tools 2022 (C++ workload)...
echo ==============================================================================
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "!VCVARS!" (
    echo [+] MSVC already installed
    goto step3
)
if "%CHECK_ONLY%"=="1" (
    echo [-] MSVC NOT installed
    goto step3
)
if "%DO_BUILD%"=="0" (
    echo [*] Skipping MSVC (--no-build)
    goto step3
)
echo [*] Installing MSVC Build Tools via winget...
echo     This is a large download (~2 GB). It may take several minutes.
winget install Microsoft.VisualStudio.2022.BuildTools --accept-source-agreements --accept-package-agreements --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
if %errorlevel%==1 (
    echo [-] MSVC install failed or was cancelled.
    echo     Install manually from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo     Select "Desktop development with C++" workload.
    echo     Python tools work without MSVC. You only need it to compile the payload.
) else (
    echo [+] MSVC Build Tools installed
)

REM ==============================================================================
:step3
echo.
echo [3/6] CLI tools (Clink, fzf, bat, ripgrep)...
echo ==============================================================================
if "%CHECK_ONLY%"=="1" goto check_tools
if "%DO_TOOLS%"=="0" (
    echo [*] Skipping CLI tools (--no-tools)
    goto step4
)

REM Clink
where /q clink 2>nul
if not %errorlevel%==1 goto clink_ok
echo [*] Installing Clink...
winget install chrisant996.Clink --accept-source-agreements --accept-package-agreements
if %errorlevel%==1 (echo [-] Clink install failed) else (echo [+] Clink installed)
goto fzf_check
:clink_ok
echo [+] Clink already installed

:fzf_check
REM fzf
where /q fzf 2>nul
if not %errorlevel%==1 goto fzf_ok
echo [*] Installing fzf...
winget install junegunn.fzf --accept-source-agreements --accept-package-agreements
if %errorlevel%==1 (echo [-] fzf install failed) else (echo [+] fzf installed)
goto bat_check
:fzf_ok
echo [+] fzf already installed

:bat_check
REM bat
where /q bat 2>nul
if not %errorlevel%==1 goto bat_ok
echo [*] Installing bat...
winget install sharkdp.bat --accept-source-agreements --accept-package-agreements
if %errorlevel%==1 (echo [-] bat install failed) else (echo [+] bat installed)
goto rg_check
:bat_ok
echo [+] bat already installed

:rg_check
REM ripgrep
where /q rg 2>nul
if not %errorlevel%==1 goto rg_ok
echo [*] Installing ripgrep...
winget install BurntSushi.ripgrep.GNU --accept-source-agreements --accept-package-agreements
if %errorlevel%==1 (echo [-] ripgrep install failed) else (echo [+] ripgrep installed)
goto step4
:rg_ok
echo [+] ripgrep already installed
goto step4

:check_tools
where /q clink 2>nul
if %errorlevel%==1 (echo   [-] clink: not found) else (echo   [+] clink: found)
where /q fzf 2>nul
if %errorlevel%==1 (echo   [-] fzf: not found) else (echo   [+] fzf: found)
where /q bat 2>nul
if %errorlevel%==1 (echo   [-] bat: not found) else (echo   [+] bat: found)
where /q rg 2>nul
if %errorlevel%==1 (echo   [-] ripgrep: not found) else (echo   [+] ripgrep: found)

REM ==============================================================================
:step4
echo.
echo [4/6] cmd_init.cmd (Linux-style aliases)...
echo ==============================================================================
set "CMDINIT_DST=%USERPROFILE%\bin\cmd_init.cmd"

if "%CHECK_ONLY%"=="1" (
    if exist "!CMDINIT_DST!" (echo   [+] cmd_init.cmd: installed) else (echo   [-] cmd_init.cmd: not installed)
    goto step5
)

if not exist "%USERPROFILE%\bin" mkdir "%USERPROFILE%\bin"
copy /y "cmd_init.cmd" "!CMDINIT_DST!" >nul 2>&1
if %errorlevel%==1 (
    echo [-] Failed to copy cmd_init.cmd
) else (
    echo [+] cmd_init.cmd copied to %%USERPROFILE%%\bin\
)

reg add "HKCU\Software\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "call \"%USERPROFILE%\bin\cmd_init.cmd\"" /f >nul 2>&1
if %errorlevel%==1 (
    echo [-] Failed to set AutoRun registry key
) else (
    echo [+] AutoRun registry key set
)

REM ==============================================================================
:step5
echo.
echo [5/6] Building payload (loader.exe + ckdll.dll)...
echo ==============================================================================
if "%CHECK_ONLY%"=="1" (
    if exist "bin\loader.exe" (echo   [+] bin\loader.exe: found) else (echo   [-] bin\loader.exe: not found)
    if exist "bin\ckdll.dll" (echo   [+] bin\ckdll.dll: found) else (echo   [-] bin\ckdll.dll: not found)
    goto step6
)
if "%DO_BUILD%"=="0" (
    echo [*] Skipping build (--no-build)
    goto step6
)

if not exist "!VCVARS!" (
    echo [-] MSVC not found -- skipping build
    echo     Install MSVC Build Tools and run: build.bat
    goto step6
)

if exist "bin\loader.exe" if exist "bin\ckdll.dll" (
    echo [+] Binaries already compiled
    goto step6
)

echo [*] Running build.bat...
call build.bat
if %errorlevel%==1 (
    echo [-] Build failed
) else (
    echo [+] Build successful: bin\loader.exe + bin\ckdll.dll
)

REM ==============================================================================
:step6
echo.
echo [6/6] Summary
echo ==============================================================================
echo.

echo   Python:     
where python 2>nul
echo.

echo   MSVC:       
if exist "!VCVARS!" (echo     [+] installed) else (echo     [-] not installed)

echo   Clink:      
where /q clink 2>nul
if %errorlevel%==1 (echo     [-] not installed) else (echo     [+] installed)

echo   fzf:        
where /q fzf 2>nul
if %errorlevel%==1 (echo     [-] not installed) else (echo     [+] installed)

echo   bat:        
where /q bat 2>nul
if %errorlevel%==1 (echo     [-] not installed) else (echo     [+] installed)

echo   ripgrep:    
where /q rg 2>nul
if %errorlevel%==1 (echo     [-] not installed) else (echo     [+] installed)

echo   cmd_init:   
if exist "%USERPROFILE%\bin\cmd_init.cmd" (echo     [+] installed) else (echo     [-] not installed)

echo   loader.exe: 
if exist "bin\loader.exe" (echo     [+] compiled) else (echo     [-] not compiled)

echo   ckdll.dll:  
if exist "bin\ckdll.dll" (echo     [+] compiled) else (echo     [-] not compiled)
echo.

if "%CHECK_ONLY%"=="1" (
    echo Done (check only -- nothing was installed).
) else (
    echo Done. If MSVC was just installed, open a NEW terminal and run:
    echo   build.bat
    echo Then start cookielog with:
    echo   auto.bat
    echo.
    pause
)
