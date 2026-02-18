"""
White Cell State Management

This module manages the global session state for the White Cell CLI,
including command mode status, threat tracking, and session logs.

Author: White Cell Project
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SessionState:
    """
    Represents the global session state.

    Attributes:
        command_mode: Boolean flag indicating if the system is in crisis/command mode
        last_threat: Dictionary containing the last detected threat details
        logs: List of all threats and events logged during the session
        session_active: Boolean flag indicating if the session is active
    """
    command_mode: bool = False
    last_threat: dict[str, Any] = field(default_factory=dict)
    logs: list[dict[str, Any]] = field(default_factory=list)
    session_active: bool = True

    def activate_command_mode(self, threat_info: dict[str, Any]) -> None:
        """
        Activate Command Mode and store threat information.

        Args:
            threat_info: Dictionary containing threat details (type, severity, risk_score, etc.)
        """
        self.command_mode = True
        self.last_threat = threat_info
        self.logs.append(threat_info)

    def deactivate_command_mode(self) -> None:
        """Deactivate Command Mode."""
        self.command_mode = False

    def add_log(self, log_entry: dict[str, Any]) -> None:
        """
        Add a log entry to the session logs.

        Args:
            log_entry: Dictionary containing log information
        """
        self.logs.append(log_entry)

    def get_logs(self) -> list[dict[str, Any]]:
        """
        Retrieve all session logs.

        Returns:
            List of log entries
        """
        return self.logs

    def clear_logs(self) -> None:
        """Clear all session logs."""
        self.logs.clear()


# Global session state instance
global_state = SessionState()
