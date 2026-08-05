from dataclasses import dataclass, field
from typing import Dict, List
from penflow.planning.hypothesis import Hypothesis
from penflow.shared.utils import get_utc_timestamp

@dataclass
class ConfidenceRecord:
    hypothesis_id: str
    old_confidence: float
    new_confidence: float
    reason: str
    timestamp: float = field(default_factory=get_utc_timestamp)

class ConfidenceEngine:
    """
    Manages confidence score evolution over time with full audit history.
    """
    def __init__(self):
        self.history: List[ConfidenceRecord] = []

    def adjust_confidence(self, hypothesis: Hypothesis, delta: float, reason: str) -> float:
        old_val = hypothesis.confidence
        new_val = round(max(0.0, min(1.0, old_val + delta)), 4)
        hypothesis.confidence = new_val
        hypothesis.updated_at = get_utc_timestamp()

        rec = ConfidenceRecord(
            hypothesis_id=hypothesis.id,
            old_confidence=old_val,
            new_confidence=new_val,
            reason=reason
        )
        self.history.append(rec)

        if new_val < 0.1:
            hypothesis.status = "INVALIDATED"
        elif new_val >= 0.9:
            hypothesis.status = "ACTIVE"

        return new_val
