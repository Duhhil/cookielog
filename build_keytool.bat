@echo off
setlocal EnableExtensions
REM build_keytool.bat -- builds bin\ckkey.exe with ckdec.exe embedded as RCDATA.
REM Reuses the clang-cl + MSVC headers/libs setup from build_clang.bat.
cd /d "%~dp0"
set "PF86=%ProgramFiles(x86)%"

set "CLANG_BIN=%USERPROFILE%\toolchain\clang+llvm-19.1.7-x86_64-pc-windows-msvc\bin"
if exist "%CLANG_BIN%\clang-cl.exe" goto :clang_ok
for /f "delims=" %%i in ('where clang-cl.exe 2^>nul') do set "CLANG_BIN=%%~dpi"
:clang_ok
if not exist "%CLANG_BIN%\clang-cl.exe" goto :no_clang

set "MSVC_ROOT="
if exist "%PF86%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" for /d %%d in ("%PF86%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*") do set "MSVC_ROOT=%%~fd"
if not defined MSVC_ROOT if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC" for /d %%d in ("%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*") do set "MSVC_ROOT=%%~fd"
if not defined MSVC_ROOT goto :no_msvc

set "SDK_ROOT="
if exist "%PF86%\Windows Kits\10\Include" for /d %%d in ("%PF86%\Windows Kits\10\Include\10.*") do set "SDK_ROOT=%%~fd"
if not defined SDK_ROOT goto :no_sdk
for %%d in ("%SDK_ROOT%") do set "SDK_VER=%%~nxd"

set "INCLUDE=%MSVC_ROOT%\include;%PF86%\Windows Kits\10\Include\%SDK_VER%\ucrt;%PF86%\Windows Kits\10\Include\%SDK_VER%\shared;%PF86%\Windows Kits\10\Include\%SDK_VER%\um;%PF86%\Windows Kits\10\Include\%SDK_VER%\winrt"
set "LIB=%MSVC_ROOT%\lib\x64;%PF86%\Windows Kits\10\Lib\%SDK_VER%\ucrt\x64;%PF86%\Windows Kits\10\Lib\%SDK_VER%\um\x64"

set "RC="
if exist "%USERPROFILE%\toolchain\sdkbt\bin\10.0.26100.0\x64\rc.exe" set "RC=%USERPROFILE%\toolchain\sdkbt\bin\10.0.26100.0\x64\rc.exe"
if not defined RC if exist "%PF86%\Windows Kits\10\bin\%SDK_VER%\x64\rc.exe" set "RC=%PF86%\Windows Kits\10\bin\%SDK_VER%\x64\rc.exe"
if not defined RC goto :no_rc
if not exist bin\ckdec.exe goto :no_helper

"%RC%" /nologo /fo bin\keytool.res keytool.rc || goto :fail
"%CLANG_BIN%\clang-cl.exe" /nologo /O2 /MT /std:c++17 /utf-8 keytool.cpp bin\keytool.res /Fe:bin\ckkey.exe -fuse-ld=lld /link /SUBSYSTEM:CONSOLE user32.lib crypt32.lib advapi32.lib || goto :fail
echo [keytool] bin\ckkey.exe built
exit /b 0

:no_clang
echo [keytool] clang-cl not found
exit /b 1
:no_msvc
echo [keytool] MSVC headers/libs not found
exit /b 1
:no_sdk
echo [keytool] Windows SDK headers not found
exit /b 1
:no_rc
echo [keytool] rc.exe not found
exit /b 1
:no_helper
echo [keytool] bin\ckdec.exe missing -- run build.bat first
exit /b 1
:fail
echo [keytool] build failed
exit /b 1
