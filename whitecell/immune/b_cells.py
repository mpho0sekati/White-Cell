"""Signature generation and adaptive memory layer."""

from typing import Any

from whitecell.immune.memory import ThreatMemory, ThreatMemoryRecord


class BCellSignatureMemory:
    """Store and reuse threat-specific indicators for future encounters."""

    def __init__(self, memory: ThreatMemory | None = None) -> None:
        self.memory = memory or ThreatMemory()

    def remember_incident(self, threat_info: dict[str, Any], risk_info: dict[str, Any]) -> ThreatMemoryRecord:
        """Persist a threat encounter into cached memory."""
        indicators = [str(item) for item in threat_info.get("keywords_matched", [])]
        regex_indicators = [str(item) for item in threat_info.get("regex_matched", [])]
        indicators.extend(regex_indicators)
        return self.memory.remember(
            threat_type=str(threat_info.get("threat_type", "unknown")),
            confidence=float(threat_info.get("confidence", 0.0)),
            risk_score=int(risk_info.get("risk_score", 0)),
            indicators=indicators,
        )

    def recall(self, threat_type: str) -> ThreatMemoryRecord | None:
        """Return cached memory for a known threat."""
        return self.memory.recall(threat_type)
