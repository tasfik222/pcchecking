@echo off
title 🔍 Ultra-Level Cheat Detector - Tasfik Edition
color 0A
setlocal enabledelayedexpansion

echo ===================================================
echo      🚨 Ultra-Level Background Cheat Detector
echo ===================================================
echo.

:: Temp file path
set "reportFile=%~dp0cheat_report.txt"
if exist "%reportFile%" del "%reportFile%"

echo [+] Scanning running hidden/suspicious processes...
echo.

:: Suspicious process keywords
set "cheatWords=cheat engine artmoney ollydbg x64dbg injector dllinjector speedhack processhacker gameguardian debugger trainer suspend memory editor ce.exe reclass mhs wireshark extreme injector ghub dnspy packet editor sandboxie"

:: Export all processes to a file
tasklist /v /fo csv > "%TEMP%\plist.csv" 2>nul

if not exist "%TEMP%\plist.csv" (
    echo [ERROR] Could not generate process list. Try running as Administrator.
    pause
    exit /b
)

set "foundSuspicious=0"
for /f "skip=1 tokens=1,2,* delims=," %%A in (%TEMP%\plist.csv) do (
    set "proc=%%~A"
    set "desc=%%~C"
    for %%W in (%cheatWords%) do (
        echo !proc! | find /i "%%~W" >nul && (
            echo [!] Suspicious: !proc! - !desc!
            echo [!] Suspicious: !proc! - !desc! >> "%reportFile%"
            set /a foundSuspicious+=1
        )
    )
)

if "!foundSuspicious!"=="0" (
    echo [OK] No suspicious cheat process found!
    echo [OK] No suspicious cheat process found! >> "%reportFile%"
) else (
    echo.
    echo ⚠ Total Suspicious Entries Found: !foundSuspicious!
)

:: Hidden background window check
echo. >> "%reportFile%"
echo ============================== >> "%reportFile%"
echo Hidden Window Processes: >> "%reportFile%"
echo ============================== >> "%reportFile%"
powershell -Command "Get-Process | Where-Object { $_.MainWindowHandle -eq 0 } | Format-Table Name,Id,StartTime -AutoSize" >> "%reportFile%"

:: DLL Hook scan
echo. >> "%reportFile%"
echo ============================== >> "%reportFile%"
echo DLL Hook Check: >> "%reportFile%"
echo ============================== >> "%reportFile%"

for %%D in (user32.dll kernel32.dll win32u.dll ntdll.dll dinput8.dll dxgi.dll) do (
    echo [DLL] Checking %%D >> "%reportFile%"
    tasklist /m %%D >> "%reportFile%" 2>nul
)

echo.
echo ===================================================
echo 🔒 Scan Complete. Output saved to cheat_report.txt
echo ===================================================
echo.
pause