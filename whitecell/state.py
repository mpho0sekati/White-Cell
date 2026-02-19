"""
White Cell State Management

This module manages the global session state for the White Cell CLI,
including command mode status, threat tracking, and session logs.

Author: White Cell Project
"""

from dataclasses import dataclass, field
from datetime import datetime
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
    helper_crew: list[dict[str, Any]] = field(default_factory=list)
    helper_activity: list[dict[str, Any]] = field(default_factory=list)
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


    def spawn_helper(self, name: str, role: str) -> dict[str, Any]:
        """Create and register a helper agent for operational support."""

        helper = {
            "name": name,
            "role": role,
            "status": "idle",
            "created_at": datetime.now().isoformat(),
            "tasks_completed": 0,
        }
        self.helper_crew.append(helper)
        self.record_helper_activity(name, f"spawned with role: {role}", "created")
        return helper

    def record_helper_activity(self, helper_name: str, activity: str, status: str) -> None:
        """Record helper activity and update helper status."""

        self.helper_activity.append(
            {
                "timestamp": datetime.now().isoformat(),
                "helper": helper_name,
                "activity": activity,
                "status": status,
            }
        )

        for helper in self.helper_crew:
            if helper.get("name") == helper_name:
                helper["status"] = status
                if status in {"resolved", "completed"}:
                    helper["tasks_completed"] = helper.get("tasks_completed", 0) + 1
                break

    def get_helper(self, name: str) -> dict[str, Any] | None:
        """Return helper by name."""

        for helper in self.helper_crew:
            if helper.get("name") == name:
                return helper
        return None

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
