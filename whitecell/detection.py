"""
White Cell Threat Detection

This module implements deterministic threat detection based on weighted evidence,
token boundaries, and optional regex signatures.

Author: White Cell Project
"""

import re
from difflib import SequenceMatcher
from typing import Optional

from whitecell.threat_catalog import THREAT_CATALOG, get_threat_definition

TOKEN_RE = re.compile(r"[a-z0-9_]+")
TYPO_SIMILARITY_THRESHOLD = 0.86


def _tokenize(text: str) -> list[str]:
    """Tokenize input text into lowercase alphanumeric tokens."""

    return TOKEN_RE.findall(text.lower())


def _phrase_match_with_boundaries(text: str, phrase: str) -> bool:
    """Match a keyword/phrase with word boundaries to reduce false positives."""

    escaped = re.escape(phrase.lower())
    pattern = re.compile(rf"\b{escaped}\b")
    return bool(pattern.search(text))


def _fuzzy_token_match(tokens: list[str], keyword: str) -> bool:
    """Detect near-miss typos for single-token keywords."""

    if " " in keyword:
        return False
    for token in tokens:
        if SequenceMatcher(a=token, b=keyword).ratio() >= TYPO_SIMILARITY_THRESHOLD:
            return True
    return False


def detect_threat(user_input: str) -> Optional[dict]:
    """
    Detect threats using weighted keyword and regex evidence.

    Args:
        user_input: The user's input string

    Returns:
        A dictionary with the top matched threat and ranked matches with confidence,
        or None if no threat is detected.
    """
    normalized_input = user_input.lower()
    tokens = _tokenize(user_input)
    ranked_matches = []

    for threat in THREAT_CATALOG.values():
        matched_keywords: list[str] = []
        matched_patterns: list[str] = []
        evidence_score = 0.0

        for keyword in threat.keywords:
            normalized_keyword = keyword.lower()
            if _phrase_match_with_boundaries(normalized_input, normalized_keyword):
                matched_keywords.append(keyword)
                evidence_score += 1.0
            elif _fuzzy_token_match(tokens, normalized_keyword):
                matched_keywords.append(f"{keyword}~")
                evidence_score += 0.5

        for signature in threat.regex_signatures:
            if re.search(signature, normalized_input, flags=re.IGNORECASE):
                matched_patterns.append(signature)
                evidence_score += 1.5

        if evidence_score > 0:
            max_possible_score = (len(threat.keywords) * 1.0) + (len(threat.regex_signatures) * 1.5)
            confidence = min(1.0, evidence_score / max_possible_score)
            ranked_matches.append(
                {
                    "threat_type": threat.threat_type,
                    "severity": threat.default_severity,
                    "confidence": round(confidence, 3),
                    "evidence_score": round(evidence_score, 2),
                    "matched_keywords": matched_keywords,
                    "matched_patterns": matched_patterns,
                }
            )

    if not ranked_matches:
        return None

    ranked_matches.sort(
        key=lambda match: (match["confidence"], match["evidence_score"], match["severity"]),
        reverse=True,
    )

    top_match = ranked_matches[0]
    return {
        "threat_type": top_match["threat_type"],
        "keywords_matched": ", ".join(top_match["matched_keywords"]) if top_match["matched_keywords"] else "regex_signature",
        "severity": top_match["severity"],
        "confidence": top_match["confidence"],
        "matches": ranked_matches,
    }


def get_threat_context(threat_type: str) -> dict:
    """
    Get additional context for a detected threat.

    Args:
        threat_type: The type of threat detected

    Returns:
        Dictionary with financial impact and POPIA exposure information
    """
    threat = get_threat_definition(threat_type)
    return {
        "financial_impact": threat.financial_impact,
        "popia_exposure": threat.popia_exposure,
    }
