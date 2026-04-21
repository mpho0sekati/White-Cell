@echo off
REM Batch file to easily run White Cell application
REM Created to simplify the launch process

echo.
echo ========================================
echo    White Cell Cybersecurity Platform
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH.
    echo Please install Python and ensure it's added to your PATH.
    pause
    exit /b 1
)

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing/updating dependencies...
pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

REM Verify rich library is installed
echo Verifying rich library installation...
python -c "import rich; print('Rich library version: ' + rich.__version__)"
if errorlevel 1 (
    echo Error: Rich library not found or not properly installed.
    echo Installing rich library separately...
    pip install rich>=15.0.0
    if errorlevel 1 (
        echo Error: Failed to install rich library.
        pause
        exit /b 1
    )
)

REM Run the application
echo.
echo Starting White Cell application...
echo Type 'help' for available commands
echo Type 'exit' to quit the application
echo.
python main.py

REM Deactivate virtual environment when done
deactivate

echo.
echo White Cell application closed.
pause
