@echo off
REM Batch file to setup and run White Cell application with C# component
REM Created to simplify the complete launch process

echo.
echo ========================================
echo    White Cell Setup and Run
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

REM Install dependencies if not already installed
echo Checking dependencies...
pip list --quiet | findstr -i "rich prompt-toolkit python-dotenv groq" >nul
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo Error: Failed to install dependencies.
        pause
        exit /b 1
    )
)

REM Check if .NET SDK is available for compiling C# component
echo.
echo Checking for .NET SDK...
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo Warning: .NET SDK not found. C# component (WhiteCellShield) will not be compiled.
    echo You can still use White Cell but without the C# background defender.
    echo Visit https://dotnet.microsoft.com/download to install .NET SDK if needed.
    echo.
    timeout /t 5
) else (
    REM Compile the C# component if not already compiled
    if not exist "WhiteCellShield\bin\Release\net8.0\win-x64\WhiteCellShield.exe" (
        echo Compiling C# component (WhiteCellShield)...
        cd WhiteCellShield
        dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
        if errorlevel 1 (
            echo Warning: Failed to compile C# component. Continuing without it.
        ) else (
            echo C# component compiled successfully.
        )
        cd ..
    ) else (
        echo C# component already compiled.
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