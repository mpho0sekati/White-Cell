# WhiteCellShield

A background security agent for the White Cell cybersecurity CLI tool. This application provides identity protection and ransomware defense capabilities while communicating with the main Python application via JSON over standard input/output.

## Features

- **Identity Protection**: Monitors the lsass process and alerts if a non-system process attempts to access its memory (simulating a credential dumping defense).
- **Ransomware Defense**: Uses FileSystemWatcher to monitor the 'Documents' folder. If more than 5 files are renamed or modified within 2 seconds, it automatically suspends the responsible process.
- **JSON Communication**: Communicates with the Python CLI via JSON over Standard Input/Output.
- **Self-Healing**: Responds to heartbeat commands to confirm operational status.

## Compilation

### Prerequisites

- .NET 8 SDK installed on the system

### Build Instructions

1. Navigate to the WhiteCellShield directory:
   ```powershell
   cd "c:\Users\Ekasi Lab\Downloads\White-Cell-main\WhiteCellShield"
   ```

2. Build the application:
   ```cmd
   dotnet build -c Release
   ```

3. Publish as a single executable file:
   ```cmd
   dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
   ```

The executable will be located at: `bin\Release\net8.0\win-x64\publish\WhiteCellShield.exe`

## Commands

The application accepts JSON commands via standard input:

- `{"cmd": "heartbeat"}` - Checks if the shield is active. Response: `{"status": "active"}`
- `{"cmd": "status"}` - Gets current status and uptime. Response: `{"status": "running", "uptime": "timestamp"}`
- `{"cmd": "stop"}` - Gracefully stops the shield. Response: `{"status": "shutdown"}`

## Integration with Python Application

The `test_shield.py` file demonstrates how to integrate with your Python application:

```python
import subprocess
import json

class WhiteCellShieldClient:
    def __init__(self, exe_path):
        self.exe_path = exe_path
        self.process = None
        
    def start(self):
        """Start the WhiteCellShield process"""
        self.process = subprocess.Popen(
            [self.exe_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
    def send_command(self, command_dict):
        """Send a JSON command to the shield"""
        if self.process:
            command_str = json.dumps(command_dict)
            self.process.stdin.write(command_str + '\n')
            self.process.stdin.flush()
            
            # Read response
            response = self.process.stdout.readline().strip()
            return json.loads(response)
    
    def heartbeat(self):
        """Check if shield is active"""
        return self.send_command({"cmd": "heartbeat"})
        
    def stop(self):
        """Stop the shield"""
        if self.process:
            self.send_command({"cmd": "stop"})
            self.process.wait()
```

## Security Features

### Identity Protection

The application continuously monitors for processes attempting to access the lsass (Local Security Authority Subsystem Service) process memory. If a non-system process is detected trying to access lsass, it is flagged as a potential credential dumping attempt and suspended.

### Ransomware Defense

Monitors the user's Documents folder for rapid file modifications or renames. If more than 5 files are altered within a 2-second window, the system identifies this as potential ransomware activity and automatically suspends the responsible process.

## Notes

- Requires Windows OS to run (uses Windows-specific APIs)
- Needs appropriate permissions to access process memory and suspend other processes
- Runs as a background service that communicates asynchronously with the main application