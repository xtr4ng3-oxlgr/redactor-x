@echo off
title REDACTOR-X - Probar sin compilar
color 0C
cd /d "%~dp0\.."

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 run_redactorx_gui.py
    pause
    exit /b
)

where python >nul 2>nul
if %errorlevel%==0 (
    python run_redactorx_gui.py
    pause
    exit /b
)

echo No se encontro Python.
pause
