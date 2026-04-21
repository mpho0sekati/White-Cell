# White Cell - Quick Run Instructions

## Easy Launch Options

### Option 1: Windows Batch File (For Command Prompt users)
Double-click on `run_whitecell.bat` or run it from Command Prompt:
```cmd
run_whitecell.bat
```

### Option 2: PowerShell Script (For PowerShell users)
Right-click on `run_whitecell.ps1` and select "Run with PowerShell", or run:
```powershell
.\run_whitecell.ps1
```

## Manual Setup (Alternative Method)

If the above options don't work, you can set up manually:

1. Open Command Prompt or PowerShell
2. Navigate to this directory:
   ```cmd
   cd "c:\Users\Ekasi Lab\Downloads\White-Cell-main"
   ```
3. Create a virtual environment:
   ```cmd
   python -m venv venv
   ```
4. Activate the virtual environment:
   - For Command Prompt: `venv\Scripts\activate`
   - For PowerShell: `venv\Scripts\Activate.ps1` (may require execution policy adjustment)
5. Install dependencies:
   ```cmd
   pip install -r requirements.txt
   ```
6. Run the application:
   ```cmd
   python main.py
   ```

## Getting Started Once Running

After launching, you can enter these commands to test the application:

- `help` - Show available commands
- `status` - Display current system status
- `triage suspicious powershell downloading payload` - Test threat detection
- `dashboard` - View security dashboard
- `exit` - Quit the application

## Troubleshooting

### If PowerShell Execution Policy Blocks the Script
Run this command in PowerShell as Administrator:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### If Python is Not Found
Ensure Python is installed and added to your PATH environment variable.

### If Dependencies Fail to Install
Try running the installation command separately:
```cmd
pip install rich prompt-toolkit python-dotenv groq
```