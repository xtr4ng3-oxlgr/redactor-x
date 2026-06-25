@echo off
title REDACTOR-X
color 0C
cd /d "%~dp0"
if not exist reports mkdir reports

if exist "REDACTOR-X\REDACTOR-X.exe" (
    start "" "REDACTOR-X\REDACTOR-X.exe"
    exit /b
)

echo No se encontro REDACTOR-X\REDACTOR-X.exe
pause
