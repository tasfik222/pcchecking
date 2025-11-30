@echo off
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/tasfik222/pcchecking/main/Services_besic_check.ps1 | iex"
pause
