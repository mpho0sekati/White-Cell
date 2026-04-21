# PowerShell script to easily run White Cell application
# Created to simplify the launch process

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   White Cell Cybersecurity Platform" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
try {
    $python_version = python --version 2>&1
    Write-Host "Python detected: $python_version" -ForegroundColor Green
} catch {
    Write-Host "Error: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install Python and ensure it's added to your PATH." -ForegroundColor Red
    Pause
    exit 1
}

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to create virtual environment." -ForegroundColor Red
        Pause
        exit 1
    }
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Install dependencies
Write-Host "Installing/updating dependencies..." -ForegroundColor Yellow
pip install --upgrade pip
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to install dependencies." -ForegroundColor Red
    Pause
    exit 1
}

# Verify rich library is installed
Write-Host "Verifying rich library installation..." -ForegroundColor Yellow
$result = python -c "import rich; print('Rich library version: ' + rich.__version__)" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Rich library not found or not properly installed." -ForegroundColor Yellow
    Write-Host "Installing rich library separately..." -ForegroundColor Yellow
    pip install rich>=15.0.0
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to install rich library." -ForegroundColor Red
        Pause
        exit 1
    }
} else {
    Write-Host $result -ForegroundColor Green
}

# Run the application
Write-Host ""
Write-Host "Starting White Cell application..." -ForegroundColor Green
Write-Host "Type 'help' for available commands" -ForegroundColor Green
Write-Host "Type 'exit' to quit the application" -ForegroundColor Green
Write-Host ""

python main.py

# Note: Deactivation happens automatically when the script ends
Write-Host ""
Write-Host "White Cell application closed." -ForegroundColor Cyan
Pause
