@echo off
setlocal EnableExtensions
title Windows Telemetry Remover 1.0.2
set "ROOT=%~dp0"
set "ENGINE=%ROOT%windows-privacy-tool.ps1"
set "DATABASE=%ROOT%spyware-db.json"

if not exist "%ENGINE%" (
    echo [ERROR] Missing engine:
    echo %ENGINE%
    echo.
    pause
    exit /b 2
)

if not exist "%DATABASE%" (
    echo [ERROR] Missing database:
    echo %DATABASE%
    echo.
    pause
    exit /b 3
)

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" ^
    -NoLogo ^
    -NoProfile ^
    -ExecutionPolicy Bypass ^
    -File "%ENGINE%" ^
    -DatabasePath "%DATABASE%"

set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo Windows Telemetry Remover finished with exit code %EXIT_CODE%.
echo Press any key to close this window.
pause >nul
exit /b %EXIT_CODE%
