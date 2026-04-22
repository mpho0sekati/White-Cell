"""Security orchestration and response decisions."""

from datetime import datetime
from typing import Any

from whitecell.command_mode import display_command_mode_activation, display_mitigation_plan, display_suggested_actions
from whitecell.risk import get_threat_mitigations


class TCellOrchestrator:
    """Coordinate the response once a threat is confirmed."""

    def activate_response(self, session_state: Any, threat_info: dict[str, Any], risk_info: dict[str, Any]) -> None:
        """Activate command mode in the shared session state."""
        session_state.activate_command_mode(
            {
                "threat_type": threat_info.get("threat_type"),
                "severity": threat_info.get("severity"),
                "risk_score": risk_info.get("risk_score"),
                "timestamp": datetime.now().isoformat(),
            }
        )

    def build_response_text(self, threat_info: dict[str, Any], risk_info: dict[str, Any]) -> str:
        """Compose the operator-facing containment guidance."""
        response = display_command_mode_activation(threat_info, risk_info)
        response += "\n\n" + display_suggested_actions(str(risk_info.get("risk_level", "low")))
        mitigations = get_threat_mitigations(str(threat_info.get("threat_type", "unknown")))
        response += "\n" + display_mitigation_plan(str(threat_info.get("threat_type", "unknown")), mitigations)
        return response
