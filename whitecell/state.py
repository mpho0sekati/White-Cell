"""
White Cell State Management

This module manages the global session state for the White Cell CLI,
including command mode status, threat tracking, and session logs.

Author: White Cell Project
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from whitecell.brain_storage import BrainStorage, BrainStorageConfig


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
    helper_learning: list[dict[str, Any]] = field(default_factory=list)
    immune_history: list[dict[str, Any]] = field(default_factory=list)
    session_active: bool = True
    brain_agent_name: str = "main-agent"
    brain_storage: BrainStorage | None = None
    brain_last_sync: str | None = None


    def initialize_brain(
        self,
        agent_name: str = "main-agent",
        local_dir: Path | None = None,
        google_drive_enabled: bool = False,
        google_drive_folder_id: str | None = None,
        google_service_account_file: str | None = None,
    ) -> None:
        """Initialize persistent brain storage and load memory."""

        self.brain_agent_name = agent_name
        storage_dir = local_dir or (Path(__file__).parent.parent / "logs" / "brain")
        config = BrainStorageConfig(
            agent_name=agent_name,
            local_dir=storage_dir,
            google_drive_enabled=google_drive_enabled,
            google_drive_folder_id=google_drive_folder_id,
            google_service_account_file=google_service_account_file,
        )
        self.brain_storage = BrainStorage(config)

        persisted = self.brain_storage.load()
        learning_entries = persisted.get("helper_learning", [])
        if isinstance(learning_entries, list):
            self.helper_learning = [entry for entry in learning_entries if isinstance(entry, dict)]

        self._rebuild_helper_techniques_from_memory()

    def _rebuild_helper_techniques_from_memory(self) -> None:
        """Re-apply memory techniques onto helper profiles."""

        for helper in self.helper_crew:
            helper["techniques"] = []

        for memory in self.helper_learning:
            helper_name = memory.get("helper", "helper")
            techniques = memory.get("techniques", [])
            helper = self.get_helper(helper_name)
            if helper is None:
                helper = self.spawn_helper(helper_name, "incident analyst")
            existing = set(helper.get("techniques", []))
            helper["techniques"] = sorted(existing.union(set(techniques)))

    def persist_brain_memory(self) -> None:
        """Write in-memory learning to configured storage."""

        if self.brain_storage is None:
            return
        self.brain_storage.save({"helper_learning": self.helper_learning})

    def sync_brain_to_google_drive(self) -> tuple[bool, str]:
        """Push local brain file to Google Drive if configured."""

        if self.brain_storage is None:
            return False, "Brain storage not initialized"

        self.persist_brain_memory()
        ok, message = self.brain_storage.sync_to_google_drive()
        if ok:
            self.brain_last_sync = datetime.now().isoformat()
        return ok, message

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
            "techniques": [],
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



    def learn_from_helper(self, helper_name: str, conversation: str, techniques: list[str]) -> dict[str, Any]:
        """Store helper conversation and techniques for main-agent memory."""

        helper = self.get_helper(helper_name)
        if helper is None:
            helper = self.spawn_helper(helper_name, "incident analyst")

        normalized_techniques = sorted({tech.strip().lower() for tech in techniques if tech.strip()})
        memory = {
            "timestamp": datetime.now().isoformat(),
            "helper": helper_name,
            "conversation": conversation.strip(),
            "techniques": normalized_techniques,
        }
        self.helper_learning.append(memory)
        self.persist_brain_memory()

        existing = set(helper.get("techniques", []))
        helper["techniques"] = sorted(existing.union(normalized_techniques))
        helper["last_shared_conversation"] = conversation.strip()
        return memory

    def get_helper_memories(self, helper_name: str | None = None) -> list[dict[str, Any]]:
        """Return recorded helper learning entries, optionally filtered by helper name."""

        if not helper_name:
            return self.helper_learning
        return [entry for entry in self.helper_learning if entry.get("helper") == helper_name]

    def get_collective_techniques(self) -> list[str]:
        """Return unique techniques learned from all helper agents."""

        techniques: set[str] = set()
        for entry in self.helper_learning:
            for technique in entry.get("techniques", []):
                techniques.add(technique)
        return sorted(techniques)

    def add_immune_scan(self, scan_result: dict[str, Any]) -> None:
        """Persist a host immune-scan snapshot in session state."""

        self.immune_history.append(scan_result)

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
