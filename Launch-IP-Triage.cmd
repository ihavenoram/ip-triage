@echo off
REM Launches the IP Triage GUI with WinForms-safe STA.
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0IP-Triage.ps1" %*
if errorlevel 1 (
    echo.
    echo IP Triage exited with an error. Review the message above.
    pause
)
