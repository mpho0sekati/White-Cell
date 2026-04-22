"""Cleanup, logging, and post-incident record generation."""

from datetime import datetime
from typing import Any


class MonocyteCleanup:
    """Build cleanup/audit records after an incident is detected."""

    def build_log_entry(self, threat_info: dict[str, Any], risk_info: dict[str, Any], user_input: str) -> dict[str, Any]:
        """Create the canonical threat log entry."""
        return {
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat_info.get("threat_type", "unknown"),
            "keywords_matched": threat_info.get("keywords_matched", []),
            "user_input": user_input,
            "risk_score": risk_info.get("risk_score", 0),
            "risk_level": risk_info.get("risk_level", "unknown"),
            "estimated_financial_loss": risk_info.get("estimated_financial_loss", 0),
            "popia_exposure": risk_info.get("popia_exposure", False),
        }
