@echo off
REM Open the SBS Management Tool dashboard in the default browser. The service
REM (install-service.bat) runs the server in the background with no window of
REM its own, so this is how you reach the UI. Set PORT to match if you changed it.
if "%PORT%"=="" set PORT=3000
start "" "http://localhost:%PORT%"
