@echo off
title REDACTOR-X - Compilar EXE portable
color 0C
cd /d "%~dp0\.."

echo ============================================================ > BUILD_LOG.txt
echo REDACTOR-X - BUILD LOG >> BUILD_LOG.txt
echo xtr4ng3 >> BUILD_LOG.txt
echo Fecha: %date% %time% >> BUILD_LOG.txt
echo ============================================================ >> BUILD_LOG.txt

set PYTHON_CMD=

where py >nul 2>nul
if %errorlevel%==0 set PYTHON_CMD=py -3

if "%PYTHON_CMD%"=="" (
    where python >nul 2>nul
    if %errorlevel%==0 set PYTHON_CMD=python
)

if "%PYTHON_CMD%"=="" (
    echo No se encontro Python.
    pause
    exit /b
)

%PYTHON_CMD% -m pip install --upgrade pip >> BUILD_LOG.txt 2>&1
%PYTHON_CMD% -m pip install pyinstaller >> BUILD_LOG.txt 2>&1

rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
rmdir /s /q CLIENTE_PORTABLE 2>nul
del /q REDACTOR-X.spec 2>nul

%PYTHON_CMD% -m PyInstaller ^
  --onedir ^
  --windowed ^
  --clean ^
  --noconfirm ^
  --name REDACTOR-X ^
  --hidden-import tkinter ^
  --hidden-import tkinter.ttk ^
  --hidden-import tkinter.messagebox ^
  --hidden-import tkinter.filedialog ^
  run_redactorx_gui.py >> BUILD_LOG.txt 2>&1

if %errorlevel% neq 0 (
    echo Fallo compilacion. Revisar BUILD_LOG.txt
    pause
    exit /b
)

mkdir CLIENTE_PORTABLE
mkdir CLIENTE_PORTABLE\reports
xcopy /E /I /Y "dist\REDACTOR-X" "CLIENTE_PORTABLE\REDACTOR-X" >> BUILD_LOG.txt 2>&1
copy /Y "README.md" "CLIENTE_PORTABLE\README.txt" >> BUILD_LOG.txt 2>&1
copy /Y "build_windows\ABRIR_REDACTOR_X.bat" "CLIENTE_PORTABLE\ABRIR_REDACTOR_X.bat" >> BUILD_LOG.txt 2>&1

echo Build listo.
echo Abrir CLIENTE_PORTABLE\ABRIR_REDACTOR_X.bat
pause
