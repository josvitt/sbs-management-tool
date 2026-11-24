@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo This must be run as Administrator.
  echo Right-click uninstall-service.bat and choose "Run as administrator".
  echo.
  pause
  exit /b 1
)

where node >nul 2>nul
if errorlevel 1 ( echo Node.js was not found. & pause & exit /b 1 )

echo Removing the "SBS Management Tool" Windows service...
node service-uninstall.js

echo.
echo Done. Your saved switches and history were left in place in this folder.
echo To run the app interactively instead, use start.bat.
echo.
pause
