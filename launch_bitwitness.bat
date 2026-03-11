@echo off
:: ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
::  BitWitness — Quick Launcher
::  Double-click this file to launch the GUI app
::  No terminal window will remain open
:: ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

cd /d "%~dp0"

:: Try venv pythonw first (no console), fall back to system python
if exist "venv\Scripts\pythonw.exe" (
    start "" "venv\Scripts\pythonw.exe" "gui_app.py"
) else if exist "venv\Scripts\python.exe" (
    start "" "venv\Scripts\python.exe" "gui_app.py"
) else (
    echo [ERROR] Virtual environment not found!
    echo Please run: python -m venv venv
    echo Then:       venv\Scripts\pip install -r requirements.txt
    pause
)
