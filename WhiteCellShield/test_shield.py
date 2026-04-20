import subprocess
import json
import sys
import os
from pathlib import Path

class WhiteCellShieldClient:
    def __init__(self, exe_path):
        self.exe_path = exe_path
        self.process = None
        
    def start(self):
        """Start the WhiteCellShield process"""
        try:
            self.process = subprocess.Popen(
                [self.exe_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            print(f"WhiteCellShield started with PID: {self.process.pid}")
        except Exception as e:
            print(f"Error starting WhiteCellShield: {e}")
            sys.exit(1)
    
    def send_command(self, command_dict):
        """Send a JSON command to the shield and return response"""
        if self.process:
            try:
                command_str = json.dumps(command_dict)
                self.process.stdin.write(command_str + '\n')
                self.process.stdin.flush()
                
                # Read response
                response = self.process.stdout.readline().strip()
                return json.loads(response)
            except Exception as e:
                print(f"Error sending command: {e}")
                return None
    
    def heartbeat(self):
        """Check if shield is active"""
        return self.send_command({"cmd": "heartbeat"})
    
    def get_status(self):
        """Get shield status"""
        return self.send_command({"cmd": "status"})
    
    def stop(self):
        """Stop the shield"""
        if self.process:
            self.send_command({"cmd": "stop"})
            self.process.wait()
            print("WhiteCellShield stopped")

def main():
    # Path to the compiled executable
    exe_path = "./bin/Release/net8.0/win-x64/publish/WhiteCellShield.exe"
    
    # Check if the executable exists
    if not os.path.exists(exe_path):
        print(f"Executable not found at: {exe_path}")
        print("Make sure you've published the application using:")
        print("dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true")
        return
    
    # Create and start the shield client
    shield_client = WhiteCellShieldClient(exe_path)
    shield_client.start()
    
    # Test heartbeat command
    print("\nTesting heartbeat command...")
    response = shield_client.heartbeat()
    print(f"Heartbeat response: {response}")
    
    # Test status command
    print("\nTesting status command...")
    response = shield_client.get_status()
    print(f"Status response: {response}")
    
    # Wait a moment to see if any alerts come through
    print("\nShield is running. Press Ctrl+C to stop...")
    try:
        # Keep the process running
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping shield...")
        shield_client.stop()

if __name__ == "__main__":
    main()