@echo off
setlocal
cd /d "%~dp0"

REM Default key for the demo sensor. If you provision a new sensor, replace this value.
set APIKEY=241hb5rCSuMS48w4ybpn-B1fIzA34EM-gcXpYoHaC70

powershell -ExecutionPolicy Bypass -File "%~dp0start_services.ps1" -ApiKey "%APIKEY%" -NoBrowser

if errorlevel 1 (
    echo.
    echo Failed to start SENTINEL services.
    pause
    exit /b 1
)

echo.
echo SENTINEL services started.
echo SOC: http://127.0.0.1:8080
echo Dashboard: http://127.0.0.1:5000
pause
