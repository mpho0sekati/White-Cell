"""
White Cell Engine: Core processing module

This module contains the core logic for handling user input,
detecting cybersecurity threats, and generating responses.
It supports a Command Mode for crisis situations, threat detection,
risk scoring, and logging.

Author: White Cell Project
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from whitecell.detection import detect_threat, get_threat_context
from whitecell.risk import calculate_risk
from whitecell.command_mode import display_command_mode_activation, display_suggested_actions
from whitecell.state import global_state

# Logging configuration
LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_FILE = LOGS_DIR / "threats.json"


def initialize_logging() -> None:
    """Initialize the logging directory and file."""
    LOGS_DIR.mkdir(exist_ok=True)
    if not LOGS_FILE.exists():
        LOGS_FILE.write_text(json.dumps([], indent=2))


def log_threat(threat_info: dict, risk_info: dict, user_input: str) -> None:
    """
    Log a detected threat to the threats.json file.

    Args:
        threat_info: Dictionary with threat detection details
        risk_info: Dictionary with risk scoring details
        user_input: The original user input that triggered the threat
    """
    try:
        logs = json.loads(LOGS_FILE.read_text()) if LOGS_FILE.exists() else []
    except (json.JSONDecodeError, FileNotFoundError):
        logs = []

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "threat_type": threat_info.get("threat_type", "unknown"),
        "keywords_matched": threat_info.get("keywords_matched", ""),
        "user_input": user_input,
        "risk_score": risk_info.get("risk_score", 0),
        "risk_level": risk_info.get("risk_level", "unknown"),
        "estimated_financial_loss": risk_info.get("estimated_financial_loss", 0),
        "popia_exposure": risk_info.get("popia_exposure", False),
    }

    logs.append(log_entry)
    
    try:
        LOGS_FILE.write_text(json.dumps(logs, indent=2))
    except IOError as e:
        print(f"[Warning] Failed to write logs: {e}")


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

    # Detect threat using deterministic detection
    threat_info = detect_threat(user_input)

    if threat_info:
        # Get additional threat context
        context = get_threat_context(threat_info["threat_type"])
        threat_info.update(context)

        # Calculate risk score
        risk_info = calculate_risk(threat_info)

        # Activate Command Mode
        global_state.activate_command_mode(
            {
                "threat_type": threat_info.get("threat_type"),
                "severity": threat_info.get("severity"),
                "risk_score": risk_info.get("risk_score"),
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Log the threat
        log_threat(threat_info, risk_info, user_input)

        # Build response with threat detection and risk summary
        response = display_command_mode_activation(threat_info, risk_info)
        response += "\n\n" + display_suggested_actions(risk_info.get("risk_level", "low"))

        return response

    # No threat detected - safe input
    return f"[cyan]You said:[/cyan] {user_input}"


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
