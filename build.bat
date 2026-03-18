@echo off
chcp 65001 >nul

echo ========================================
echo   NetMonitor - EXE Build
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo Please install from https://www.python.org
    pause
    exit /b 1
)

echo [1/4] Installing dependencies...
python -m pip install psutil requests pyinstaller pillow
if errorlevel 1 (
    echo [ERROR] pip install failed.
    pause
    exit /b 1
)

echo [2/4] Generating icon...
python make_icon.py
if errorlevel 1 (
    echo [ERROR] Icon generation failed.
    pause
    exit /b 1
)

echo [3/4] Building EXE...
python -m PyInstaller --onefile --windowed --name NetMonitor --icon netmonitor.ico --add-data "netmonitor.ico;." net_monitor.py
if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo.
echo [4/4] Done!
echo ========================================
echo   dist\NetMonitor.exe is ready.
echo ========================================
echo.
pause
