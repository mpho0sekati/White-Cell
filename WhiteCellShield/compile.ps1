# PowerShell script to compile WhiteCellShield.exe

# Change to the correct directory
Set-Location -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Path)"

Write-Host "Current directory: $(Get-Location)" -ForegroundColor Green

# Check if .NET 8 SDK is available
try {
    $dotnetVersion = dotnet --version
    Write-Host "Using .NET SDK version: $dotnetVersion" -ForegroundColor Green
    
    # Restore packages
    Write-Host "Restoring packages..." -ForegroundColor Yellow
    dotnet restore
    
    # Build the project
    Write-Host "Building the project..." -ForegroundColor Yellow
    dotnet build -c Release
    
    # Publish as a single file executable
    Write-Host "Publishing as a single file executable..." -ForegroundColor Yellow
    dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
    
    Write-Host "Compilation completed successfully!" -ForegroundColor Green
    Write-Host "Executable is located at: bin\Release\net8.0\win-x64\publish\WhiteCellShield.exe" -ForegroundColor Cyan
}
catch {
    Write-Host "Error occurred during compilation: $_" -ForegroundColor Red
    exit 1
}