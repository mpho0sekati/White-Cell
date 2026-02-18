"""
White Cell Threat Catalog

Central source of truth for threat definitions and metadata used by
threat detection and risk scoring.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatDefinition:
    """Defines all metadata for a supported threat type."""

    threat_type: str
    keywords: tuple[str, ...]
    regex_signatures: tuple[str, ...]
    default_severity: int
    risk_multiplier: float
    financial_impact: int
    popia_exposure: bool


DEFAULT_THREAT = ThreatDefinition(
    threat_type="unknown",
    keywords=(),
    regex_signatures=(),
    default_severity=5,
    risk_multiplier=1.0,
    financial_impact=2000,
    popia_exposure=False,
)


THREAT_CATALOG: dict[str, ThreatDefinition] = {
    "ransomware": ThreatDefinition(
        threat_type="ransomware",
        keywords=("ransomware", "encrypt", "encrypted", "locked"),
        regex_signatures=(r"\b(ransom\s*note|decrypt\s*key)\b",),
        default_severity=9,
        risk_multiplier=1.2,
        financial_impact=5000,
        popia_exposure=True,
    ),
    "malware": ThreatDefinition(
        threat_type="malware",
        keywords=("malware", "virus", "trojan", "worm", "payload"),
        regex_signatures=(r"\b(backdoor|keylogger|malicious\s+binary)\b",),
        default_severity=8,
        risk_multiplier=1.1,
        financial_impact=3000,
        popia_exposure=True,
    ),
    "data_breach": ThreatDefinition(
        threat_type="data_breach",
        keywords=("breach", "exposed", "compromised", "leak", "leaked"),
        regex_signatures=(r"\b(data\s+exfiltration|records?\s+leaked)\b",),
        default_severity=8,
        risk_multiplier=1.15,
        financial_impact=10000,
        popia_exposure=True,
    ),
    "phishing": ThreatDefinition(
        threat_type="phishing",
        keywords=("phishing", "suspicious link", "verify credentials", "spoofed"),
        regex_signatures=(r"\b(verify\s+your\s+account|reset\s+your\s+password)\b",),
        default_severity=6,
        risk_multiplier=0.8,
        financial_impact=1000,
        popia_exposure=True,
    ),
    "exploit": ThreatDefinition(
        threat_type="exploit",
        keywords=("exploit", "vulnerability", "rce", "sql injection", "xss"),
        regex_signatures=(r"\b(cve-\d{4}-\d{4,7}|remote\s+code\s+execution)\b",),
        default_severity=7,
        risk_multiplier=1.1,
        financial_impact=4000,
        popia_exposure=True,
    ),
    "lateral_movement": ThreatDefinition(
        threat_type="lateral_movement",
        keywords=("lateral movement", "privilege escalation", "pass the hash"),
        regex_signatures=(r"\b(credential\s+dumping|admin\s+takeover)\b",),
        default_severity=7,
        risk_multiplier=1.15,
        financial_impact=5000,
        popia_exposure=True,
    ),
    "denial_of_service": ThreatDefinition(
        threat_type="denial_of_service",
        keywords=("ddos", "dos attack", "flood", "traffic spike"),
        regex_signatures=(r"\b(request\s+flood|service\s+unavailable)\b",),
        default_severity=7,
        risk_multiplier=0.9,
        financial_impact=2000,
        popia_exposure=False,
    ),
}


def get_threat_definition(threat_type: str) -> ThreatDefinition:
    """Return the threat definition for a threat type or a safe default."""

    return THREAT_CATALOG.get(threat_type, DEFAULT_THREAT)
