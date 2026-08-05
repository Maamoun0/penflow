from penflow.testing.strategy import TestingHypothesis

class TestingPriorityEngine:
    """
    Ranks testing hypotheses based on business value, asset importance, tech, freshness, confidence.
    """
    def calculate_priority(self, hypothesis: TestingHypothesis, business_value: float = 5.0, asset_importance: float = 5.0) -> float:
        base_score = (business_value * 0.5) + (asset_importance * 0.5)
        return round((hypothesis.confidence * 4.0) + (base_score * 0.6), 2)
