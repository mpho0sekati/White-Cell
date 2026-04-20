"""
White Cell Threat Detection

This module implements deterministic threat detection based on keywords.
Detected threats trigger Command Mode activation.

Author: White Cell Project
"""

from typing import Optional, List, Dict, Any
import re

from whitecell.threats_config import THREATS, get_threat_by_type, ThreatDefinition


def _token_matches(text: str, keyword: str) -> bool:
    """Return True if keyword matches as a token or phrase within text."""
    # escape keyword for regex and use word boundaries when appropriate
    kw_escaped = re.escape(keyword)
    pattern = rf"\b{kw_escaped}\b"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def detect_threats(user_input: str) -> List[Dict[str, Any]]:
    """
    Detect threats in input and return all matching signatures with confidence scores.

    Returns a list of matches sorted by confidence (desc). Each match contains:
      - threat_type
      - keywords_matched: list[str]
      - regex_matched: list[str]
      - confidence: 0.0-1.0
      - severity: default severity from definition
    """
    normalized = user_input
    matches: List[Dict[str, Any]] = []

    for td in THREATS:
        total_weight = sum(td.keyword_weights.values()) if td.keyword_weights else 0.0
        matched_weight = 0.0
        matched_keywords: List[str] = []
        matched_regex: List[str] = []

        # keyword matching with token boundaries
        for kw, w in td.keyword_weights.items():
            if _token_matches(normalized, kw):
                matched_weight += w
                matched_keywords.append(kw)

        # regex pattern matches
        for pat in (td.regex_patterns or []):
            if pat.search(normalized):
                matched_regex.append(pat.pattern)
                # boost matched weight for regex matches
                matched_weight += 1.5

        if matched_weight > 0 and total_weight > 0:
            confidence = min(1.0, matched_weight / max(total_weight, 1.0))
        elif matched_regex:
            confidence = 0.6 + min(0.4, len(matched_regex) * 0.1)
        else:
            confidence = 0.0

        if confidence > 0:
            matches.append({
                "threat_type": td.threat_type,
                "keywords_matched": matched_keywords,
                "regex_matched": matched_regex,
                "confidence": round(confidence, 3),
                "severity": td.default_severity,
            })

    # sort by confidence desc
    matches.sort(key=lambda x: x["confidence"], reverse=True)
    return matches


def detect_threat(user_input: str) -> Optional[dict]:
    """
    Backwards-compatible helper returning the top match or None.

    Use `detect_threats` to get all matches and confidences.
    """
    matches = detect_threats(user_input)
    if not matches:
        return None
    top = matches[0]
    return {
        "threat_type": top["threat_type"],
        "keywords_matched": top.get("keywords_matched", []),
        "confidence": top.get("confidence", 0.0),
        "severity": top.get("severity", 5),
    }


def get_threat_context(threat_type: str) -> dict:
    td = get_threat_by_type(threat_type)
    if not td:
        return {"financial_impact": 2000, "popia_exposure": False}
    return {"financial_impact": td.financial_impact, "popia_exposure": td.popia_exposure}


def get_threat_description(threat_type: str) -> str:
    td = get_threat_by_type(threat_type)
    return td.description if td else "Unknown threat type"


def get_all_threats() -> list[dict]:
    out = []
    for td in THREATS:
        out.append({
            "threat_type": td.threat_type,
            "severity": td.default_severity,
            "description": td.description,
            "financial_impact": td.financial_impact,
            "popia_exposure": td.popia_exposure,
        })
    return out
