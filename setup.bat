@echo off
REM ============================================================================
REM Elbanna Recon v1.0 - Windows Setup Script
REM Author: Yousef Osama - Cybersecurity Engineering, Egyptian Chinese University
REM Last Updated: September 8, 2025
REM ============================================================================

title Elbanna Recon v1.0 - Setup

echo.
echo ========================================================================
echo                    ELBANNA RECON v1.0 - SETUP
echo ========================================================================
echo Author: Yousef Osama - Cybersecurity Engineering, ECU
echo Setting up your cybersecurity reconnaissance toolkit...
echo.

REM Check if Python is installed
echo [1/6] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH!
    echo.
    echo Please install Python 3.8+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python 3.8+ is required!
    echo Current version:
    python --version
    echo.
    echo Please upgrade Python from https://python.org
    echo.
    pause
    exit /b 1
)

python --version
echo ✅ Python version check passed!
echo.

REM Check if pip is available
echo [2/6] Checking pip installation...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not available!
    echo.
    echo Please reinstall Python with pip support.
    echo.
    pause
    exit /b 1
)

python -m pip --version
echo ✅ pip check passed!
echo.

REM Create virtual environment
echo [3/6] Creating virtual environment...
if exist "venv" (
    echo Virtual environment already exists. Removing old version...
    rmdir /s /q venv
)

python -m venv venv
if %errorlevel% neq 0 (
    echo ERROR: Failed to create virtual environment!
    echo.
    pause
    exit /b 1
)

echo ✅ Virtual environment created successfully!
echo.

REM Activate virtual environment and upgrade pip
echo [4/6] Activating virtual environment and upgrading pip...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment!
    echo.
    pause
    exit /b 1
)

python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo WARNING: Failed to upgrade pip, continuing anyway...
)

echo ✅ Virtual environment activated and pip upgraded!
echo.

REM Install requirements
echo [5/6] Installing Python dependencies...
echo This may take a few minutes...
echo.

if not exist "requirements.txt" (
    echo ERROR: requirements.txt not found!
    echo Please ensure you're running this script from the project directory.
    echo.
    pause
    exit /b 1
)

python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install some dependencies!
    echo This might be due to:
    echo - Network connectivity issues
    echo - Missing system dependencies
    echo - Incompatible package versions
    echo.
    echo You can try:
    echo 1. Check your internet connection
    echo 2. Run this script as Administrator
    echo 3. Install packages individually
    echo.
    pause
    exit /b 1
)

echo ✅ All dependencies installed successfully!
echo.

REM Create necessary directories
echo [6/6] Creating project directories...

if not exist "logs" mkdir logs
if not exist "reports" mkdir reports
if not exist "wordlists" mkdir wordlists

echo ✅ Project directories created!
echo.

REM Final setup verification
echo ========================================================================
echo                           SETUP COMPLETE!
echo ========================================================================
echo.
echo Your Elbanna Recon v1.0 environment is ready!
echo.
echo NEXT STEPS:
echo.
echo 1. To activate the environment:
echo    venv\Scripts\activate
echo.
echo 2. To run the tool:
echo    python elbanna_recon.py
echo.
echo 3. To deactivate when done:
echo    deactivate
echo.
echo IMPORTANT NOTES:
echo - Always activate the virtual environment before running the tool
echo - For packet sniffing, run PowerShell as Administrator
echo - Read the README.md for detailed usage instructions
echo - Use responsibly and only for authorized testing!
echo.
echo TROUBLESHOOTING:
echo - If you get import errors, ensure the virtual environment is activated
echo - For permission issues, try running as Administrator
echo - Check logs/ directory for detailed error information
echo.
echo ========================================================================
echo Author: Yousef Osama - Cybersecurity Engineering, ECU
echo GitHub: [Your GitHub repository URL]
echo ========================================================================
echo.

pause

REM Optional: Ask if user wants to run the tool now
echo.
set /p choice="Would you like to run Elbanna Recon now? (y/n): "
if /i "%choice%"=="y" (
    echo.
    echo Starting Elbanna Recon v1.0...
    echo.
    python elbanna_recon.py
)

echo.
echo Setup script completed. Thank you for using Elbanna Recon v1.0!
pause
