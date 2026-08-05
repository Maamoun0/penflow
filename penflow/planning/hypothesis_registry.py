from typing import Dict, List, Optional
from penflow.planning.hypothesis import Hypothesis

class HypothesisRegistry:
    """
    Registry for storing and managing active and archived hypotheses.
    """
    def __init__(self):
        self._hypotheses: Dict[str, Hypothesis] = {}

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._hypotheses[hypothesis.id] = hypothesis

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        return self._hypotheses.get(hypothesis_id)

    def get_all_hypotheses(self) -> List[Hypothesis]:
        return list(self._hypotheses.values())

    def get_active_hypotheses(self) -> List[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.status in ["DRAFT", "ACTIVE"]]
