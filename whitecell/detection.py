"""
White Cell Threat Detection

This module implements deterministic threat detection based on keywords.
Detected threats trigger Command Mode activation.

Author: White Cell Project
"""

from typing import Optional
from dataclasses import dataclass


@dataclass
class ThreatSignature:
    """
    Represents a threat signature with keywords and severity level.

    Attributes:
        threat_type: Name of the threat (e.g., 'ransomware')
        keywords: List of keywords that trigger this threat
        default_severity: Default severity level (1-10)
    """
    threat_type: str
    keywords: list[str]
    default_severity: int


# Collection of known threat signatures
THREAT_SIGNATURES = [
    ThreatSignature("ransomware", ["ransomware", "encrypt", "locked"], 9),
    ThreatSignature("malware", ["malware", "virus", "trojan", "worm"], 8),
    ThreatSignature("data_breach", ["breach", "exposed", "compromised"], 8),
    ThreatSignature("phishing", ["phishing", "suspicious link", "verify credentials"], 6),
    ThreatSignature("exploit", ["exploit", "vulnerability", "rce", "sql injection"], 7),
    ThreatSignature("lateral_movement", ["lateral movement", "privilege escalation"], 7),
    ThreatSignature("denial_of_service", ["ddos", "dos attack", "flood"], 7),
]

# Map threat types to risk categories for financial impact
THREAT_FINANCIAL_IMPACT = {
    "ransomware": 5000,
    "malware": 3000,
    "data_breach": 10000,
    "phishing": 1000,
    "exploit": 4000,
    "lateral_movement": 5000,
    "denial_of_service": 2000,
}

# Map threat types to POPIA (Protection of Personal Information Act) exposure
# True if the threat could expose personal data
THREAT_POPIA_EXPOSURE = {
    "ransomware": True,
    "malware": True,
    "data_breach": True,
    "phishing": True,
    "exploit": True,
    "lateral_movement": True,
    "denial_of_service": False,
}


def detect_threat(user_input: str) -> Optional[dict]:
    """
    Detect if the user input contains keywords indicating a cybersecurity threat.

    Args:
        user_input: The user's input string

    Returns:
        A dictionary with threat details (threat_type, keywords_matched, severity)
        or None if no threat is detected
    """
    normalized_input = user_input.lower()

    for signature in THREAT_SIGNATURES:
        for keyword in signature.keywords:
            if keyword.lower() in normalized_input:
                return {
                    "threat_type": signature.threat_type,
                    "keywords_matched": keyword,
                    "severity": signature.default_severity,
                }

    return None


def get_threat_context(threat_type: str) -> dict:
    """
    Get additional context for a detected threat.

    Args:
        threat_type: The type of threat detected

    Returns:
        Dictionary with financial impact and POPIA exposure information
    """
    return {
        "financial_impact": THREAT_FINANCIAL_IMPACT.get(threat_type, 2000),
        "popia_exposure": THREAT_POPIA_EXPOSURE.get(threat_type, False),
    }
