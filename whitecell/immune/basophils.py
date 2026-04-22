"""Alert amplification and telemetry helpers."""

from typing import Any


class BasophilTelemetry:
    """Build alert context that can be consumed by UI and audit layers."""

    def build_signal(self, threat_info: dict[str, Any], risk_info: dict[str, Any], memory_sightings: int = 1) -> dict[str, Any]:
        """Create a normalized alert signal."""
        risk_score = int(risk_info.get("risk_score", 0))
        if risk_score >= 80:
            severity = "critical"
        elif risk_score >= 60:
            severity = "high"
        elif risk_score >= 35:
            severity = "medium"
        else:
            severity = "low"

        return {
            "threat_type": threat_info.get("threat_type", "unknown"),
            "severity": severity,
            "risk_score": risk_score,
            "risk_level": risk_info.get("risk_level", "unknown"),
            "memory_sightings": memory_sightings,
            "popia_exposure": bool(risk_info.get("popia_exposure", False)),
        }
