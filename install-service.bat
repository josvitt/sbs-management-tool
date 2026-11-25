@echo off
setlocal
cd /d "%~dp0"

REM --- Must run elevated: creating a Windows service needs Administrator. ---
net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo This installer must be run as Administrator.
  echo Right-click install-service.bat and choose "Run as administrator", then try again.
  echo.
  pause
  exit /b 1
)

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js was not found on this machine.
  echo Install it from https://nodejs.org, then run this script again.
  echo.
  pause
  exit /b 1
)

echo.
echo Installing application dependencies (first run only)...
if not exist node_modules (
  call npm install
  if errorlevel 1 ( echo npm install failed - see above. & pause & exit /b 1 )
)

echo.
echo Installing node-windows (the service helper, used only to create the service)...
call npm install node-windows
if errorlevel 1 ( echo Could not install node-windows - see above. & pause & exit /b 1 )

echo.
echo Installing and starting the "SBS Management Tool" Windows service...
node service-install.js
if errorlevel 1 (
  echo.
  echo Something went wrong - see the messages above.
  echo.
  pause
  exit /b 1
)

echo.
echo ------------------------------------------------------------------
echo The service is running.
echo.
echo   1. Open the dashboard:  http://localhost:3000  (or run open-ui.bat)
echo   2. Add your switches and credentials in the browser.
echo.
echo The service runs in the background (no window), starts automatically on
echo boot, and keeps collecting from your switches even with no browser open.
echo Enter credentials through the web UI, not by editing files - the service
echo owns the encrypted store and keeps it across reboots.
echo ------------------------------------------------------------------
echo.
pause
