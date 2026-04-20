@echo off
REM Batch script to compile WhiteCellShield.exe

REM Change to the script's directory
cd /d "%~dp0"

echo Current directory: %CD%

REM Check if .NET 8 SDK is available
where dotnet >nul 2>nul
if %errorlevel% neq 0 (
    echo .NET SDK is not found. Please install .NET 8 SDK.
    pause
    exit /b 1
)

echo Checking .NET SDK version...
dotnet --version
if %errorlevel% neq 0 (
    echo Error: Failed to get .NET SDK version
    pause
    exit /b 1
)

echo Restoring packages...
dotnet restore
if %errorlevel% neq 0 (
    echo Error: Failed to restore packages
    pause
    exit /b 1
)

echo Building the project...
dotnet build -c Release
if %errorlevel% neq 0 (
    echo Error: Failed to build the project
    pause
    exit /b 1
)

echo Publishing as a single file executable...
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
if %errorlevel% neq 0 (
    echo Error: Failed to publish the application
    pause
    exit /b 1
)

echo Compilation completed successfully!
echo Executable is located at: bin\Release\net8.0\win-x64\publish\WhiteCellShield.exe
pause