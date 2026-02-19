"""
White Cell Engine: Core processing module

This module contains the core logic for handling user input,
detecting cybersecurity threats, and generating responses.
It supports a Command Mode for crisis situations, threat detection,
risk scoring, and structured logging.

Author: White Cell Project
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from whitecell.command_mode import display_command_mode_activation, display_suggested_actions
from whitecell.detection import detect_threat, get_threat_context
from whitecell.risk import calculate_risk
from whitecell.state import global_state

# Logging configuration
LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_FILE = LOGS_DIR / "threats.jsonl"
LEGACY_LOGS_FILE = LOGS_DIR / "threats.json"
LOG_SCHEMA_VERSION = "1.0"
LOG_ROTATION_MAX_BYTES = 1_000_000
LOG_RETENTION_FILES = 5


def _get_rotated_log_files() -> list[Path]:
    """Return rotated log files sorted by newest first."""

    return sorted(LOGS_DIR.glob("threats-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)


def _rotate_logs_if_needed() -> None:
    """Rotate logs when current file exceeds configured size and apply retention."""

    if not LOGS_FILE.exists() or LOGS_FILE.stat().st_size < LOG_ROTATION_MAX_BYTES:
        return

    rotated_name = f"threats-{datetime.now().strftime('%Y%m%d%H%M%S')}.jsonl"
    LOGS_FILE.rename(LOGS_DIR / rotated_name)
    LOGS_FILE.touch()

    rotated = _get_rotated_log_files()
    for stale in rotated[LOG_RETENTION_FILES:]:
        stale.unlink(missing_ok=True)


def initialize_logging() -> None:
    """Initialize logging directory and JSONL file, migrating legacy JSON if present."""

    LOGS_DIR.mkdir(exist_ok=True)

    if not LOGS_FILE.exists():
        LOGS_FILE.touch()

    # Opportunistic migration for legacy array logs
    if LEGACY_LOGS_FILE.exists() and LEGACY_LOGS_FILE.stat().st_size > 0:
        try:
            legacy_logs = json.loads(LEGACY_LOGS_FILE.read_text())
            if isinstance(legacy_logs, list):
                with LOGS_FILE.open("a", encoding="utf-8") as stream:
                    for entry in legacy_logs:
                        if isinstance(entry, dict):
                            migrated = {
                                "schema_version": LOG_SCHEMA_VERSION,
                                "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                                "event_type": "threat_detected",
                                **entry,
                            }
                            stream.write(json.dumps(migrated) + "\n")
                LEGACY_LOGS_FILE.unlink(missing_ok=True)
        except (json.JSONDecodeError, OSError):
            # Keep legacy file untouched if invalid or inaccessible.
            pass


def log_threat(threat_info: dict, risk_info: dict, user_input: str) -> None:
    """
    Log a detected threat as structured JSONL.

    Args:
        threat_info: Dictionary with threat detection details
        risk_info: Dictionary with risk scoring details
        user_input: The original user input that triggered the threat
    """
    _rotate_logs_if_needed()

    log_entry = {
        "schema_version": LOG_SCHEMA_VERSION,
        "event_type": "threat_detected",
        "timestamp": datetime.now().isoformat(),
        "threat_type": threat_info.get("threat_type", "unknown"),
        "keywords_matched": threat_info.get("keywords_matched", ""),
        "confidence": threat_info.get("confidence"),
        "user_input": user_input,
        "risk_score": risk_info.get("risk_score", 0),
        "risk_level": risk_info.get("risk_level", "unknown"),
        "estimated_financial_loss": risk_info.get("estimated_financial_loss", 0),
        "popia_exposure": risk_info.get("popia_exposure", False),
    }

    try:
        with LOGS_FILE.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(log_entry) + "\n")
    except OSError as error:
        print(f"[Warning] Failed to write logs: {error}")


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

        # Dispatch helper crew (if any) to triage activity
        for helper in global_state.helper_crew:
            helper_name = helper.get("name", "helper")
            threat_type = threat_info.get("threat_type", "unknown")
            global_state.record_helper_activity(
                helper_name,
                f"triaging {threat_type} incident",
                "engaged",
            )
            global_state.learn_from_helper(
                helper_name,
                f"Observed {threat_type} indicators from user input: {user_input}",
                [f"triage:{threat_type}", f"risk:{risk_info.get('risk_level', 'low')}"]
            )

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
    Retrieve threat logs from JSONL storage (with legacy JSON fallback).

    Returns:
        List of threat log entries
    """
    logs: list[dict] = []

    # Read rotated historical logs first, then current file
    for path in list(reversed(_get_rotated_log_files())) + [LOGS_FILE]:
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if isinstance(entry, dict):
                            logs.append(entry)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue

    if logs:
        return logs

    # Legacy fallback
    try:
        if LEGACY_LOGS_FILE.exists():
            legacy = json.loads(LEGACY_LOGS_FILE.read_text())
            if isinstance(legacy, list):
                return legacy
    except (json.JSONDecodeError, OSError):
        pass

    return []
