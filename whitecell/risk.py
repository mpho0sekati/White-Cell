"""
White Cell Risk Scoring

This module implements risk scoring for detected threats.
It calculates risk scores (0-100), estimated financial loss, and POPIA exposure.
Provides actionable recommendations based on threat severity.

Author: White Cell Project
"""

from typing import Literal, Dict, Any

from whitecell.threats_config import get_threat_by_type


# Mitigation strategies for each threat type (unchanged)
THREAT_MITIGATIONS = {
    "ransomware": [
        "Conduct immediate backup verification (test recovery)",
        "Isolate affected systems from network",
        "Disable suspicious user accounts",
        "Review recent admin activity logs",
        "Prepare ransomware negotiation team if needed",
        "Contact cyber insurance provider",
    ],
    "malware": [
        "Scan all systems with updated antivirus",
        "Check for rootkits using specialized tools",
        "Review network for command & control callbacks",
        "Quarantine infected systems",
        "Perform memory forensics on affected hosts",
        "Update all security definitions",
    ],
    "data_breach": [
        "Identify scope of data compromise",
        "Notify affected individuals immediately",
        "Engage incident response team",
        "Preserve evidence for investigation",
        "Contact legal and compliance teams",
        "Monitor dark web for leaked data",
    ],
    "phishing": [
        "Send warning email to all users",
        "Block sender across email systems",
        "Check if users clicked/submitted credentials",
        "Force password reset for affected users",
        "Review webmail logs for unauthorized access",
        "Update email filtering rules",
    ],
    "exploit": [
        "Patch affected systems immediately",
        "Review for signs of exploitation",
        "Check intrusion detection logs",
        "Monitor for related CVE exploitations",
        "Test patch deployment process",
        "Review security controls for gaps",
    ],
    "lateral_movement": [
        "Enable advanced session monitoring",
        "Review privileged account usage",
        "Implement/verify network segmentation",
        "Check for suspicious admin activities",
        "Review security group memberships",
        "Deploy additional monitoring on sensitive systems",
    ],
    "denial_of_service": [
        "Activate DDoS mitigation services",
        "Implement rate limiting",
        "Review network bandwidth utilization",
        "Coordinate with ISP for upstream filtering",
        "Analyze attack patterns",
        "Prepare incident communication",
    ],
    "credential_theft": [
        "Force password resets for compromised accounts",
        "Monitor for unauthorized account usage",
        "Review MFA logs for suspicious activity",
        "Check for forwarding rules on compromised accounts",
        "Audit recent permission changes",
        "Enable enhanced credential monitoring",
    ],
    "supply_chain": [
        "Audit all third-party access and permissions",
        "Review supply chain security agreements",
        "Implement additional monitoring on vendor access",
        "Verify integrity of vendor-provided software",
        "Review vendor incident response procedures",
        "Consider alternative suppliers",
    ],
}


def calculate_risk(threat_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate the risk score for a detected threat using centralized metadata.

    Accepts either the legacy single-match dict or a match returned by
    `detection.detect_threats` / `detect_threat`.
    """
    threat_type = threat_info.get("threat_type", "unknown")
    severity = threat_info.get("severity", threat_info.get("severity", 5))

    # Normalize severity to 1-10
    severity = max(1, min(10, int(severity)))

    base_risk_score = severity * 10

    td = get_threat_by_type(threat_type)
    multiplier = td.risk_multiplier if td else 1.0

    adjusted_risk_score = int(base_risk_score * multiplier)
    adjusted_risk_score = max(0, min(100, adjusted_risk_score))

    # Determine risk level
    if adjusted_risk_score <= 33:
        risk_level = "low"
    elif adjusted_risk_score <= 66:
        risk_level = "medium"
    else:
        risk_level = "high"

    # Financial loss - use centralized baseline
    financial_loss = td.financial_impact if td else 2000
    adjusted_financial_loss = int(financial_loss * (adjusted_risk_score / 50))

    # POPIA exposure from central config
    popia_exposure = td.popia_exposure if td else False

    # Recommendations
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
        "popia_exposure": popia_exposure,
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


def get_threat_mitigations(threat_type: str) -> list[str]:
    """
    Get recommended mitigation steps for a threat type.

    Args:
        threat_type: The type of threat

    Returns:
        List of mitigation steps
    """
    return THREAT_MITIGATIONS.get(threat_type, [
        "Contact your cybersecurity team",
        "Document all relevant information",
        "Preserve evidence for investigation",
    ])
