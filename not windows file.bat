@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   Detecting Non-Microsoft Running Processes
echo ============================================
echo.

:: Temporary output file
set "outfile=%TEMP%\non_microsoft_processes.txt"
if exist "%outfile%" del "%outfile%"

:: Get the list of all running processes with their paths
for /f "tokens=1,2 delims=," %%A in ('"wmic process get Name,ExecutablePath /format:csv | findstr /i /v "Microsoft Windows""') do (
    set "path=%%B"
    if defined path (
        echo !path!>>"%outfile%"
    )
)

:: Remove duplicates and show result
sort "%outfile%" | findstr /v /i "Windows\\System32" | findstr /v /i "Windows\\SysWOW64" | findstr /v /i "\\Windows\\" > "%TEMP%\filtered_processes.txt"

echo Detected Non-Microsoft (possibly suspicious or third-party) Processes:
echo ---------------------------------------------------------------
type "%TEMP%\filtered_processes.txt"

echo.
echo Done. You can check the full list at: %TEMP%\filtered_processes.txt
pause