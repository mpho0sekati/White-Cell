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
        description: Detailed description of the threat type
    """
    threat_type: str
    keywords: list[str]
    default_severity: int
    description: str = ""


# Collection of known threat signatures
THREAT_SIGNATURES = [
    ThreatSignature("ransomware", ["ransomware", "encrypt", "locked", "pay", "bitcoin"], 9, 
                   "Malicious software that encrypts files and demands ransom"),
    ThreatSignature("malware", ["malware", "virus", "trojan", "worm", "spyware"], 8,
                   "Malicious software designed to harm or exploit systems"),
    ThreatSignature("data_breach", ["breach", "exposed", "compromised", "leaked", "stolen"], 8,
                   "Unauthorized access or disclosure of sensitive data"),
    ThreatSignature("phishing", ["phishing", "suspicious link", "verify credentials", "click here", "urgent action"], 6,
                   "Social engineering attack attempting to steal credentials"),
    ThreatSignature("exploit", ["exploit", "vulnerability", "rce", "sql injection", "xss", "zero-day"], 7,
                   "Attack targeting software vulnerabilities"),
    ThreatSignature("lateral_movement", ["lateral movement", "privilege escalation", "pivot", "access granted"], 7,
                   "Attacker moving through network after initial breach"),
    ThreatSignature("denial_of_service", ["ddos", "dos attack", "flood", "overload", "offline"], 7,
                   "Attack designed to make systems unavailable"),
    ThreatSignature("credential_theft", ["credentials stolen", "password compromised", "account takeover"], 7,
                   "Unauthorized access to user accounts and credentials"),
    ThreatSignature("supply_chain", ["supply chain", "compromised vendor", "third party"], 8,
                   "Attack through compromised third-party providers"),
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
    "credential_theft": 6000,
    "supply_chain": 8000,
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
    "credential_theft": True,
    "supply_chain": True,
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


def get_threat_description(threat_type: str) -> str:
    """
    Get the description for a threat type.

    Args:
        threat_type: The type of threat

    Returns:
        Threat description string
    """
    for sig in THREAT_SIGNATURES:
        if sig.threat_type == threat_type:
            return sig.description
    return "Unknown threat type"


def get_all_threats() -> list[dict]:
    """
    Get all available threat types with their details.

    Returns:
        List of dictionaries with threat information
    """
    threats = []
    for sig in THREAT_SIGNATURES:
        threats.append({
            "threat_type": sig.threat_type,
            "severity": sig.default_severity,
            "description": sig.description,
            "financial_impact": THREAT_FINANCIAL_IMPACT.get(sig.threat_type, 2000),
            "popia_exposure": THREAT_POPIA_EXPOSURE.get(sig.threat_type, False),
        })
    return threats
