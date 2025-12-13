@echo off
echo ========================================
echo Network Monitoring System - Admin Mode
echo ========================================
echo.
echo This will run the network monitoring system with administrator privileges
echo required for real network packet capture.
echo.
echo If you don't need real packet capture, you can use the regular run_system.bat
echo which will use simulation mode for demonstration purposes.
echo.
pause

echo Starting system with administrator privileges...
powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %CD% && python src/web/app.py && pause' -Verb RunAs"