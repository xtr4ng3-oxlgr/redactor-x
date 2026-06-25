@echo off
title REDACTOR-X
color 0C
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 run_redactorx_gui.py
    exit /b
)

where python >nul 2>nul
if %errorlevel%==0 (
    python run_redactorx_gui.py
    exit /b
)

echo No se encontro Python.
pause
