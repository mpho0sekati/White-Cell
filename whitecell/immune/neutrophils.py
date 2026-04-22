"""Fast local detection layer."""

from typing import Any

from whitecell.detection import detect_threat, detect_threats, get_threat_context


class NeutrophilDetector:
    """Low-latency detector for immediate incident triage."""

    def detect(self, user_input: str) -> dict[str, Any] | None:
        """Return the top threat match enriched with context."""
        threat_info = detect_threat(user_input)
        if not threat_info:
            return None
        threat_info.update(get_threat_context(threat_info["threat_type"]))
        return threat_info

    def detect_all(self, user_input: str) -> list[dict[str, Any]]:
        """Return all candidate matches for correlation and memory."""
        return detect_threats(user_input)
