@echo off
setlocal EnableExtensions
REM build_clang.bat -- same outputs as build.bat, built with clang-cl + lld-link
REM + llvm-ml instead of cl.exe/ml64.exe. The MSVC headers and libs are reused,
REM so the binaries are still MSVC-ABI and match what build.bat would produce.
REM
REM Use it when the Visual Studio install has the headers/libs but no cl.exe.
REM build.bat calls this automatically when vcvars produces no compiler.

cd /d "%~dp0"
set "PF86=%ProgramFiles(x86)%"

REM ---------------------------------------------------------------- clang
set "CLANG_BIN="
set "TOOLCHAIN=%USERPROFILE%\toolchain\clang+llvm-19.1.7-x86_64-pc-windows-msvc"
if exist "%TOOLCHAIN%\bin\clang-cl.exe" set "CLANG_BIN=%TOOLCHAIN%\bin"
if defined CLANG_BIN goto :clang_ok
for /f "delims=" %%i in ('where clang-cl.exe 2^>nul') do set "CLANG_BIN=%%~dpi"
:clang_ok
if not defined CLANG_BIN goto :no_clang

REM ---------------------------------------------------------------- MSVC headers + libs
REM The compiler binaries are gone, the toolset directory is not: headers, libs
REM and the CRT still ship there and clang-cl uses them directly.
set "MSVC_ROOT="
if exist "%PF86%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" for /d %%d in ("%PF86%\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*") do set "MSVC_ROOT=%%~fd"
if not defined MSVC_ROOT if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC" for /d %%d in ("%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*") do set "MSVC_ROOT=%%~fd"
if not defined MSVC_ROOT goto :no_msvc_libs

set "SDK_ROOT="
if exist "%PF86%\Windows Kits\10\Include" for /d %%d in ("%PF86%\Windows Kits\10\Include\10.*") do set "SDK_ROOT=%%~fd"
if not defined SDK_ROOT goto :no_sdk
for %%d in ("%SDK_ROOT%") do set "SDK_VER=%%~nxd"

set "INCLUDE=%MSVC_ROOT%\include;%PF86%\Windows Kits\10\Include\%SDK_VER%\ucrt;%PF86%\Windows Kits\10\Include\%SDK_VER%\shared;%PF86%\Windows Kits\10\Include\%SDK_VER%\um;%PF86%\Windows Kits\10\Include\%SDK_VER%\winrt"
set "LIB=%MSVC_ROOT%\lib\x64;%PF86%\Windows Kits\10\Lib\%SDK_VER%\ucrt\x64;%PF86%\Windows Kits\10\Lib\%SDK_VER%\um\x64"

REM ---------------------------------------------------------------- rc.exe
REM The SDK's bin tree is stripped on this class of install; the NuGet copy of
REM Microsoft.Windows.SDK.BuildTools supplies rc.exe/mt.exe.
set "RC="
if exist "%USERPROFILE%\toolchain\sdkbt\bin\10.0.26100.0\x64\rc.exe" set "RC=%USERPROFILE%\toolchain\sdkbt\bin\10.0.26100.0\x64\rc.exe"
if not defined RC if exist "%PF86%\Windows Kits\10\bin\%SDK_VER%\x64\rc.exe" set "RC=%PF86%\Windows Kits\10\bin\%SDK_VER%\x64\rc.exe"

if not exist "%CLANG_BIN%\llvm-ml.exe" goto :no_ml
if not defined RC goto :no_rc
if not exist "%MSVC_ROOT%\include\vcruntime.h" goto :no_msvc_libs
if not exist "%PF86%\Windows Kits\10\Lib\%SDK_VER%\um\x64\kernel32.lib" goto :no_sdk

echo [build] clang: %CLANG_BIN%
echo [build] msvc:  %MSVC_ROOT%
echo [build] sdk:   %SDK_VER%
echo [build] rc:    %RC%

if not exist bin mkdir bin
del /q bin\ckdll.exp bin\ckdll.lib 2>nul

echo [build] ckdll.dll ...
"%CLANG_BIN%\llvm-ml.exe" -m64 /nologo /c /Fo"bin\chkstk.obj" src\chkstk.asm
if errorlevel 1 ( echo [build] LLVM-ML FAILED & exit /b 1 )

"%CLANG_BIN%\clang-cl.exe" /nologo /LD /Od /Oi- /GS- /Gs4096 /utf-8 -fuse-ld=lld ^
   src\ckdll.cpp bin\chkstk.obj /Fe:bin\ckdll.dll ^
   /link /DLL /INCREMENTAL:NO /NODEFAULTLIB /ENTRY:payload_entry /DYNAMICBASE:NO ^
         /BASE:0x5F000000 /GUARD:NO /MACHINE:X64 kernel32.lib crypt32.lib bcrypt.lib iphlpapi.lib
if errorlevel 1 ( echo [build] DLL BUILD FAILED & exit /b 1 )

echo [build] ckdec.exe ...
"%CLANG_BIN%\clang-cl.exe" /nologo /O2 /MT /std:c++17 /utf-8 ^
   src\ckdec.cpp /Fe:bin\ckdec.exe -fuse-ld=lld ^
   /link /SUBSYSTEM:CONSOLE ole32.lib oleaut32.lib crypt32.lib
if errorlevel 1 ( echo [build] CKDEC BUILD FAILED & exit /b 1 )

echo [build] payload.h ...
powershell -nop -exec bypass -file src\gen.ps1
if errorlevel 1 ( echo [build] GEN FAILED & exit /b 1 )

echo [build] loader.exe ...
"%RC%" /nologo /fo bin\loader.res src\loader.rc
if errorlevel 1 ( echo [build] RC FAILED & exit /b 1 )

"%CLANG_BIN%\clang-cl.exe" /nologo /O2 /MT /std:c++17 /utf-8 ^
   src\loader.cpp bin\loader.res /Fe:bin\loader.exe -fuse-ld=lld ^
   /link /SUBSYSTEM:WINDOWS /PDBALTPATH:fontcache.pdb user32.lib advapi32.lib
if errorlevel 1 ( echo [build] LOADER BUILD FAILED & exit /b 1 )

echo [build] ALL OK (clang-cl)
for %%f in (bin\ckdll.dll bin\loader.exe bin\ckdec.exe) do echo [build]   %%~nxf  %%~zf bytes
exit /b 0

:no_clang
echo [build] ERROR: clang-cl.exe not found.
echo [build] Unpack LLVM into %TOOLCHAIN% or put clang-cl.exe on PATH.
exit /b 2
:no_msvc_libs
echo [build] ERROR: no VC\Tools\MSVC toolset with headers/libs.
echo [build] clang-cl can replace cl.exe but it still needs the MSVC headers/libs.
exit /b 3
:no_sdk
echo [build] ERROR: no Windows Kits\10\Include\10.* directory.
exit /b 3
:no_ml
echo [build] ERROR: llvm-ml.exe is not next to clang-cl.exe (needed for chkstk.asm).
exit /b 3
:no_rc
echo [build] ERROR: rc.exe not found (needed for loader.res).
exit /b 3
