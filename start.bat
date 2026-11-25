@echo off
setlocal

cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js was not found on this machine.
  echo Install it from https://nodejs.org, then run this script again.
  echo.
  pause
  exit /b 1
)

if not exist node_modules (
  echo.
  echo Installing dependencies - first run only, this may take a minute...
  echo.
  call npm install
  if errorlevel 1 (
    echo.
    echo npm install failed - see the messages above.
    echo.
    pause
    exit /b 1
  )
)

echo.
echo Starting SBS Management Tool...
echo.

start "SBS Management Tool Server" cmd /k "node scripts\run.js"

timeout /t 2 /nobreak >nul
start "" "http://localhost:3000"

echo SBS Management Tool is running in the "SBS Management Tool Server" window.
echo Close that window (or press Ctrl+C in it) to stop the server.
echo This window can be closed now.
echo.
pause
