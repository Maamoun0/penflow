from typing import List, Optional
from penflow.planning.hypothesis import Hypothesis
from penflow.planning.priority_engine import PriorityEngine

class HypothesisRanker:
    """
    Ranks and sorts hypotheses deterministically using PriorityEngine scores.
    """
    def __init__(self, priority_engine: Optional[PriorityEngine] = None):
        self.priority_engine = priority_engine or PriorityEngine()

    def rank(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        for h in hypotheses:
            self.priority_engine.calculate_priority(h)
        # Sort descending by priority
        return sorted(hypotheses, key=lambda h: h.priority, reverse=True)
