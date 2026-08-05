from typing import List, Dict
from penflow.testing.strategy import TestingHypothesis
from penflow.shared.utils import get_utc_timestamp

class TestingConfidenceEngine:
    """
    Maintains hypothesis confidence scores with explainable log records.
    """
    def adjust_confidence(self, hypothesis: TestingHypothesis, delta: float, reason: str) -> float:
        old_val = hypothesis.confidence
        new_val = round(max(0.0, min(1.0, old_val + delta)), 4)
        hypothesis.confidence = new_val
        return new_val
