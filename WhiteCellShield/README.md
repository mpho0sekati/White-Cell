# WhiteCellShield

A background security agent for the White Cell cybersecurity CLI tool. This application provides identity protection and ransomware defense capabilities while communicating with the main Python application via JSON over standard input/output.

## Features

- **Credential Dumping Heuristics**: Uses Windows-native process inspection to flag likely dump tooling or sensitive module combinations often associated with LSASS-focused credential access.
- **Ransomware Defense**: Uses `FileSystemWatcher` to monitor protected user-document extensions in the Documents folder. If rapid protected-file activity crosses the threshold, it attempts to suspend the likely culprit.
- **Least Surprise Guardrails**: Avoids suspending trusted baseline processes and runs in observe-only mode when not elevated.
- **JSON Communication**: Communicates with the Python CLI via JSON over Standard Input/Output.
- **Operational Telemetry**: Exposes richer shield status, including elevation state, monitors enabled, alert counters, and protected path.

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
- `{"cmd": "status"}` - Gets current shield telemetry. Example response fields:
  - `status`
  - `startedAt`
  - `isElevated`
  - `lsassMonitorEnabled`
  - `documentsMonitorEnabled`
  - `recentActivityCount`
  - `alertsRaised`
  - `lastAlertType`
  - `lastAlertProcess`
  - `documentsPath`
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

### Credential Access Heuristics

The shield continuously inspects running processes for names and module combinations commonly associated with credential dumping or sensitive credential-access tooling. Suspicious processes trigger structured alerts and are only suspended when the shield is running with elevated rights.

### Ransomware Defense

Monitors the user's Documents folder for rapid changes to protected file types such as Office files, archives, images, databases, and backups. When suspicious change volume crosses the threshold, the shield raises a ransomware alert and attempts containment.

## Notes

- Requires Windows OS to run (uses Windows-specific APIs)
- Elevation is recommended for containment actions against other processes
- Runs as a background service that communicates asynchronously with the main application
