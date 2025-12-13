@echo off
title Advanced Network Anomaly Detection System
color 0A

echo ================================================================
echo ADVANCED NETWORK ANOMALY DETECTION SYSTEM
echo AI-Powered Cybersecurity Research Platform
echo Author: Aryan Pravin Sahu ^| IIT Ropar
echo ================================================================
echo.

echo Starting system...
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found!
    echo Please run setup.py first to install the system.
    echo.
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if activation was successful
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment!
    pause
    exit /b 1
)

echo Virtual environment activated successfully.
echo.

REM Start the web application
echo Starting web dashboard...
echo Dashboard will be available at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the system
echo ================================================================
echo.

python src\web\app.py

REM If we get here, the system has stopped
echo.
echo System stopped.
pause