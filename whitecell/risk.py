"""
White Cell Risk Scoring

This module implements risk scoring for detected threats.
It calculates risk scores (0-100), estimated financial loss, and POPIA exposure.

Author: White Cell Project
"""

from typing import Literal

from whitecell.threat_catalog import get_threat_definition


def calculate_risk(threat_info: dict) -> dict:
    """
    Calculate the risk score for a detected threat.

    Args:
        threat_info: Dictionary containing threat details including:
            - threat_type: Type of threat (e.g., 'ransomware')
            - severity: Severity level (1-10)
            - keywords_matched: Keyword that triggered detection

    Returns:
        Dictionary containing:
            - risk_score: Integer between 0-100
            - risk_level: String ('low', 'medium', 'high')
            - estimated_financial_loss: Estimated financial impact in dollars
            - popia_exposure: Boolean indicating if personal data may be exposed
            - recommendation: String with recommended action
    """
    threat_type = threat_info.get("threat_type", "unknown")
    severity = threat_info.get("severity", 5)
    threat = get_threat_definition(threat_type)

    # Normalize severity to 0-10 range
    severity = max(1, min(10, severity))

    # Calculate base risk score from severity (0-100)
    base_risk_score = severity * 10

    # Adjust risk based on threat type
    adjusted_risk_score = int(base_risk_score * threat.risk_multiplier)
    adjusted_risk_score = max(0, min(100, adjusted_risk_score))

    # Determine risk level
    if adjusted_risk_score <= 33:
        risk_level = "low"
    elif adjusted_risk_score <= 66:
        risk_level = "medium"
    else:
        risk_level = "high"

    # Adjust financial loss by risk score
    adjusted_financial_loss = int(threat.financial_impact * (adjusted_risk_score / 50))

    # Generate recommendation
    recommendations = {
        "low": "Monitor the situation and maintain elevated alertness.",
        "medium": "Increase logging and monitoring. Prepare incident response procedures.",
        "high": "IMMEDIATE ACTION: Isolate affected systems, activate incident response team.",
    }
    recommendation = recommendations.get(risk_level, "Unknown risk level")

    return {
        "risk_score": adjusted_risk_score,
        "risk_level": risk_level,
        "estimated_financial_loss": adjusted_financial_loss,
        "popia_exposure": threat.popia_exposure,
        "recommendation": recommendation,
    }


def get_risk_color(risk_level: Literal["low", "medium", "high"]) -> str:
    """
    Get the Rich color tag for displaying the risk level.

    Args:
        risk_level: One of 'low', 'medium', 'high'

    Returns:
        Rich color tag string
    """
    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
    }
    return color_map.get(risk_level, "white")


def format_risk_summary(risk_info: dict) -> str:
    """
    Format risk information for Rich console display.

    Args:
        risk_info: Dictionary returned from calculate_risk()

    Returns:
        Formatted string for Rich console
    """
    risk_score = risk_info.get("risk_score", 0)
    risk_level = risk_info.get("risk_level", "unknown")
    financial_loss = risk_info.get("estimated_financial_loss", 0)
    popia_exposure = risk_info.get("popia_exposure", False)
    recommendation = risk_info.get("recommendation", "")

    color = get_risk_color(risk_level)

    output = f"""
[bold {color}]Risk Summary:[/bold {color}]
  Risk Score: {risk_score}/100 [{color}]{risk_level.upper()}[/{color}]
  Est. Financial Loss: ${financial_loss:,}
  POPIA Exposure: {"[red]YES[/red]" if popia_exposure else "[green]NO[/green]"}
  Action: {recommendation}
"""
    return output.strip()
