"""Shared immune memory structures."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ThreatMemoryRecord:
    """Cached incident memory for previously-seen threats."""

    threat_type: str
    confidence: float
    risk_score: int
    last_seen: str
    sightings: int = 1
    indicators: list[str] = field(default_factory=list)


class ThreatMemory:
    """In-memory incident cache that approximates adaptive immune memory."""

    def __init__(self) -> None:
        self._records: dict[str, ThreatMemoryRecord] = {}

    def remember(
        self,
        threat_type: str,
        confidence: float,
        risk_score: int,
        indicators: list[str] | None = None,
    ) -> ThreatMemoryRecord:
        """Add or update a cached threat memory record."""
        now = datetime.now().isoformat()
        record = self._records.get(threat_type)
        clean_indicators = sorted(set(indicators or []))
        if record is None:
            record = ThreatMemoryRecord(
                threat_type=threat_type,
                confidence=confidence,
                risk_score=risk_score,
                last_seen=now,
                indicators=clean_indicators,
            )
            self._records[threat_type] = record
            return record

        record.confidence = max(record.confidence, confidence)
        record.risk_score = max(record.risk_score, risk_score)
        record.last_seen = now
        record.sightings += 1
        record.indicators = sorted(set(record.indicators + clean_indicators))
        return record

    def recall(self, threat_type: str) -> ThreatMemoryRecord | None:
        """Return a cached record for a threat type, if present."""
        return self._records.get(threat_type)

    def export(self) -> list[dict[str, Any]]:
        """Return serializable memory state."""
        return [
            {
                "threat_type": record.threat_type,
                "confidence": record.confidence,
                "risk_score": record.risk_score,
                "last_seen": record.last_seen,
                "sightings": record.sightings,
                "indicators": list(record.indicators),
            }
            for record in sorted(self._records.values(), key=lambda item: item.threat_type)
        ]
