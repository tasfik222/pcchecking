@echo off
cls
echo Running PowerShell script directly from GitHub...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "Invoke-Expression (Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/tasfik222/pcchecking/main/TamperedSignature.ps1').Content"

pause
