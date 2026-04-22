"""
White Cell Engine: Core processing module

This module contains the core logic for handling user input,
detecting cybersecurity threats, and generating responses.
It supports a Command Mode for crisis situations, threat detection,
risk scoring, and logging.

Author: White Cell Project
"""

import json
import subprocess
import threading
from pathlib import Path
from typing import Optional

from whitecell.immune import ImmuneSystem
from whitecell.state import global_state

# Logging configuration
LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_FILE = LOGS_DIR / "threats.json"
immune_system = ImmuneSystem()


class AgentOrchestrator:
    """
    Orchestrates the C# defender (WhiteCellShield.exe) and Go scanner (scanner.exe).
    Uses subprocess to start executables and listens for alerts from the C# agent.
    """
    
    def __init__(self):
        self.defender_process = None
        self.scanner_process = None
        self.alert_thread = None
        self.running = False
    
    def start_defender(self):
        """Start the WhiteCellShield.exe defender process."""
        try:
            exe_path = Path(__file__).parent.parent / "WhiteCellShield" / "bin" / "Release" / "net8.0" / "win-x64" / "WhiteCellShield.exe"
            if not exe_path.exists():
                print(f"Defender executable not found: {exe_path}")
                return False
                
            self.defender_process = subprocess.Popen(
                [str(exe_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            print(f"WhiteCell Defender started with PID: {self.defender_process.pid}")
            return True
        except Exception as e:
            print(f"Error starting defender: {e}")
            return False
    
    def start_scanner(self):
        """Start the scanner.exe process."""
        try:
            exe_path = Path(__file__).parent.parent / "scanner.exe"
            if not exe_path.exists():
                print(f"Scanner executable not found: {exe_path}")
                return False
                
            self.scanner_process = subprocess.Popen(
                [str(exe_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            print(f"Go Scanner started with PID: {self.scanner_process.pid}")
            return True
        except Exception as e:
            print(f"Error starting scanner: {e}")
            return False
    
    def listen_for_alerts(self):
        """Non-blocking method to listen for alerts from the C# agent using a thread."""
        if self.defender_process is None:
            print("Defender process is not running")
            return
        
        def _listen():
            while self.running:
                try:
                    output = self.defender_process.stdout.readline()
                    if output:
                        # Try to parse as JSON, if it's an alert
                        try:
                            alert_data = json.loads(output.strip())
                            if 'alert' in alert_data or 'message' in alert_data:
                                # Print alert with Rich formatting
                                from rich.console import Console
                                console = Console()
                                alert_msg = alert_data.get('alert', alert_data.get('message', 'Unknown alert'))
                                console.print(f"[bold red][CRITICAL][/bold red] {alert_msg}")
                        except json.JSONDecodeError:
                            # If not JSON, print as plain text
                            if 'detected' in output.lower() or 'alert' in output.lower() or 'critical' in output.lower():
                                from rich.console import Console
                                console = Console()
                                console.print(f"[bold red][CRITICAL][/bold red] {output.strip()}")
                except Exception as e:
                    print(f"Error reading defender output: {e}")
                    break
        
        self.running = True
        self.alert_thread = threading.Thread(target=_listen, daemon=True)
        self.alert_thread.start()
    
    def stop_all(self):
        """Stop all processes."""
        self.running = False
        if self.defender_process:
            self.defender_process.terminate()
            self.defender_process = None
        if self.scanner_process:
            self.scanner_process.terminate()
            self.scanner_process = None
        print("All orchestrated processes stopped")


def initialize_logging() -> None:
    """Initialize the logging directory and file."""
    LOGS_DIR.mkdir(exist_ok=True)
    if not LOGS_FILE.exists():
        LOGS_FILE.write_text(json.dumps([], indent=2))


def log_threat_entry(log_entry: dict) -> None:
    """
    Persist a threat log entry to the threats.json file.

    Args:
        log_entry: Canonical log entry generated by the immune stack
    """
    try:
        logs = json.loads(LOGS_FILE.read_text()) if LOGS_FILE.exists() else []
    except (json.JSONDecodeError, FileNotFoundError):
        logs = []

    logs.append(log_entry)
    
    try:
        LOGS_FILE.write_text(json.dumps(logs, indent=2))
    except IOError as e:
        print(f"[Warning] Failed to write logs: {e}")


def log_threat(threat_info: dict, risk_info: dict, user_input: str) -> None:
    """
    Backwards-compatible wrapper for threat logging.
    """
    from whitecell.immune.monocytes import MonocyteCleanup

    entry = MonocyteCleanup().build_log_entry(threat_info, risk_info, user_input)
    log_threat_entry(entry)


def handle_input(user_input: str, state_dict: Optional[dict] = None) -> str:
    """
    Process user input and detect cybersecurity threats.
    Activates Command Mode if a threat is found and applies risk scoring.

    Args:
        user_input: The user's input string
        state_dict: (Deprecated) Legacy dictionary state. Use global_state instead.

    Returns:
        A response string to display to the user
    """
    # Initialize logging on first call
    if not LOGS_FILE.exists():
        initialize_logging()

    outcome = immune_system.handle_input(user_input, global_state)
    if outcome.detected and outcome.log_entry:
        log_threat_entry(outcome.log_entry)
    return outcome.response_text


def parse_command(user_input: str) -> tuple[str, list[str]]:
    """
    Parse user input into a command and arguments.

    Args:
        user_input: The raw user input string

    Returns:
        A tuple of (command, arguments)
    """
    parts = user_input.strip().split()
    if not parts:
        return ("", [])

    command = parts[0].lower()
    arguments = parts[1:]

    return command, arguments


def get_session_logs() -> list[dict]:
    """
    Retrieve all threat logs from the session.

    Returns:
        List of threat log entries
    """
    try:
        if LOGS_FILE.exists():
            return json.loads(LOGS_FILE.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    return []
