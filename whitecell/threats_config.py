"""
Centralized threat definitions for White Cell.

Contains signatures, keyword weights, regex patterns, base financial impact,
POPIA exposure flags, default severity and risk multipliers.

This file is the single source of truth for threat metadata and should be
consumed by `detection.py` and `risk.py`.
"""
from dataclasses import dataclass
from typing import List, Dict, Pattern, Optional
import re


@dataclass
class ThreatDefinition:
    threat_type: str
    description: str
    default_severity: int
    keyword_weights: Dict[str, float]
    regex_patterns: List[Pattern]
    financial_impact: int
    popia_exposure: bool
    risk_multiplier: float = 1.0


# Helper to compile regex strings
def _compile_patterns(patterns: Optional[List[str]]) -> List[Pattern]:
    if not patterns:
        return []
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# Centralized threat definitions
THREATS: List[ThreatDefinition] = [
    ThreatDefinition(
        threat_type="ransomware",
        description="Malicious software that encrypts files and demands ransom",
        default_severity=9,
        keyword_weights={
            "ransomware": 2.0,
            "encrypt": 1.5,
            "locked": 1.2,
            "pay": 0.8,
            "bitcoin": 0.6,
        },
        regex_patterns=_compile_patterns([r"\b[A-F0-9]{32,}\b"]),
        financial_impact=5000,
        popia_exposure=True,
        risk_multiplier=1.2,
    ),
    ThreatDefinition(
        threat_type="malware",
        description="Malicious software designed to harm or exploit systems",
        default_severity=8,
        keyword_weights={
            "malware": 1.5,
            "virus": 1.2,
            "trojan": 1.2,
            "worm": 1.0,
            "spyware": 1.0,
        },
        regex_patterns=None,
        financial_impact=3000,
        popia_exposure=True,
        risk_multiplier=1.1,
    ),
    ThreatDefinition(
        threat_type="data_breach",
        description="Unauthorized access or disclosure of sensitive data",
        default_severity=8,
        keyword_weights={
            "breach": 1.8,
            "exposed": 1.3,
            "compromised": 1.5,
            "leaked": 1.4,
            "stolen": 1.4,
        },
        regex_patterns=None,
        financial_impact=10000,
        popia_exposure=True,
        risk_multiplier=1.15,
    ),
    ThreatDefinition(
        threat_type="phishing",
        description="Social engineering attack attempting to steal credentials",
        default_severity=6,
        keyword_weights={
            "phishing": 1.5,
            "suspicious link": 1.2,
            "verify credentials": 1.3,
            "click here": 0.8,
            "urgent action": 0.9,
        },
        regex_patterns=None,
        financial_impact=1000,
        popia_exposure=True,
        risk_multiplier=0.8,
    ),
    ThreatDefinition(
        threat_type="exploit",
        description="Attack targeting software vulnerabilities",
        default_severity=7,
        keyword_weights={
            "exploit": 1.4,
            "vulnerability": 1.3,
            "rce": 1.6,
            "sql injection": 1.5,
            "xss": 1.2,
            "zero-day": 1.8,
        },
        regex_patterns=None,
        financial_impact=4000,
        popia_exposure=True,
        risk_multiplier=1.1,
    ),
    ThreatDefinition(
        threat_type="lateral_movement",
        description="Attacker moving through network after initial breach",
        default_severity=7,
        keyword_weights={
            "lateral movement": 1.6,
            "privilege escalation": 1.5,
            "pivot": 1.2,
            "access granted": 1.0,
        },
        regex_patterns=None,
        financial_impact=5000,
        popia_exposure=True,
        risk_multiplier=1.15,
    ),
    ThreatDefinition(
        threat_type="denial_of_service",
        description="Attack designed to make systems unavailable",
        default_severity=7,
        keyword_weights={
            "ddos": 1.8,
            "dos attack": 1.5,
            "flood": 1.0,
            "overload": 1.0,
            "offline": 0.8,
        },
        regex_patterns=None,
        financial_impact=2000,
        popia_exposure=False,
        risk_multiplier=0.9,
    ),
    ThreatDefinition(
        threat_type="credential_theft",
        description="Unauthorized access to user accounts and credentials",
        default_severity=7,
        keyword_weights={
            "credentials stolen": 1.8,
            "password compromised": 1.6,
            "account takeover": 1.6,
        },
        regex_patterns=None,
        financial_impact=6000,
        popia_exposure=True,
        risk_multiplier=1.2,
    ),
    ThreatDefinition(
        threat_type="supply_chain",
        description="Attack through compromised third-party providers",
        default_severity=8,
        keyword_weights={
            "supply chain": 1.6,
            "compromised vendor": 1.4,
            "third party": 1.0,
        },
        regex_patterns=None,
        financial_impact=8000,
        popia_exposure=True,
        risk_multiplier=1.15,
    ),
]


def get_threat_by_type(threat_type: str) -> Optional[ThreatDefinition]:
    for t in THREATS:
        if t.threat_type == threat_type:
            return t
    return None


def get_all_threats() -> List[ThreatDefinition]:
    return THREATS.copy()
