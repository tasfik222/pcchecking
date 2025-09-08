@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   Recent User-Initiated Activity Log
echo ============================================

set "outfile=%TEMP%\user_activity_log.txt"
if exist "%outfile%" del "%outfile%"

:: Check Recent Used Files (from User Profile)
echo [Recent Files Opened by User]>>"%outfile%"
dir "%APPDATA%\Microsoft\Windows\Recent" /a-d /o-d /t:w >>"%outfile%"
echo.>>"%outfile%"

:: Check Prefetch (recently launched EXE files)
echo [Applications Launched (Prefetch)]>>"%outfile%"
dir C:\Windows\Prefetch\*.pf /o-d >>"%outfile%"
echo.>>"%outfile%"

:: Event Viewer Log - Application Executions (EventID 1000)
echo [User Executed Apps - Event Viewer Logs (Last 10)]>>"%outfile%"
wevtutil qe Application /q:"*[System[(EventID=1000)]]" /c:10 /f:text >>"%outfile%" 2>nul
echo.>>"%outfile%"

:: Tasks executed by the user (Task Scheduler History - if enabled)
echo [Tasks Run by User - Task Scheduler]>>"%outfile%"
schtasks /query /fo LIST /v | findstr /i "User:" >>"%outfile%"
echo.>>"%outfile%"

:: Show Results
echo ====== User Activity Summary ======
type "%outfile%"
echo.
echo Full log saved at: %outfile%
pause