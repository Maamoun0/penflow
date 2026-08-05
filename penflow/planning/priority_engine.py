from penflow.planning.hypothesis import Hypothesis

class PriorityEngine:
    """
    Deterministic priority scoring engine.
    Formula: Priority = (Confidence * 4.0) + (Base Priority * 0.6)
    Same observations always produce the exact same priority.
    """
    def calculate_priority(self, hypothesis: Hypothesis, business_value: float = 5.0, asset_importance: float = 5.0) -> float:
        base_score = (business_value * 0.5) + (asset_importance * 0.5)
        calculated_priority = round((hypothesis.confidence * 4.0) + (base_score * 0.6), 2)
        hypothesis.priority = calculated_priority
        return calculated_priority
