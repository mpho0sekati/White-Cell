"""Coordinator for the White Cell immune architecture."""

from dataclasses import dataclass
from typing import Any

from whitecell.risk import calculate_risk
from whitecell.immune.b_cells import BCellSignatureMemory
from whitecell.immune.basophils import BasophilTelemetry
from whitecell.immune.monocytes import MonocyteCleanup
from whitecell.immune.neutrophils import NeutrophilDetector
from whitecell.immune.t_cells import TCellOrchestrator


@dataclass
class ImmuneOutcome:
    """Result of running a user input through the immune stack."""

    detected: bool
    response_text: str
    threat_info: dict[str, Any] | None = None
    risk_info: dict[str, Any] | None = None
    log_entry: dict[str, Any] | None = None
    signal: dict[str, Any] | None = None
    memory_record: dict[str, Any] | None = None


class ImmuneSystem:
    """End-to-end threat detection, response, memory, and cleanup pipeline."""

    def __init__(
        self,
        neutrophils: NeutrophilDetector | None = None,
        b_cells: BCellSignatureMemory | None = None,
        t_cells: TCellOrchestrator | None = None,
        monocytes: MonocyteCleanup | None = None,
        basophils: BasophilTelemetry | None = None,
    ) -> None:
        self.neutrophils = neutrophils or NeutrophilDetector()
        self.b_cells = b_cells or BCellSignatureMemory()
        self.t_cells = t_cells or TCellOrchestrator()
        self.monocytes = monocytes or MonocyteCleanup()
        self.basophils = basophils or BasophilTelemetry()

    def handle_input(self, user_input: str, session_state: Any) -> ImmuneOutcome:
        """Run an input string through the immune pipeline."""
        threat_info = self.neutrophils.detect(user_input)
        if not threat_info:
            return ImmuneOutcome(
                detected=False,
                response_text=f"[cyan]You said:[/cyan] {user_input}",
            )

        risk_info = calculate_risk(threat_info)
        memory_record = self.b_cells.remember_incident(threat_info, risk_info)
        signal = self.basophils.build_signal(
            threat_info,
            risk_info,
            memory_sightings=memory_record.sightings,
        )
        self.t_cells.activate_response(session_state, threat_info, risk_info)
        response_text = self.t_cells.build_response_text(threat_info, risk_info)
        log_entry = self.monocytes.build_log_entry(threat_info, risk_info, user_input)

        return ImmuneOutcome(
            detected=True,
            response_text=response_text,
            threat_info=threat_info,
            risk_info=risk_info,
            log_entry=log_entry,
            signal=signal,
            memory_record={
                "threat_type": memory_record.threat_type,
                "sightings": memory_record.sightings,
                "last_seen": memory_record.last_seen,
                "confidence": memory_record.confidence,
            },
        )
