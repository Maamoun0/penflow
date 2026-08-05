from typing import List, Dict, Any

class ReasoningEngine:
    """
    Deterministic, explainable reasoning engine building structured explanation chains.
    """
    def build_reasoning_chain(self, observations: List[str], condition_logic: str, conclusion: str) -> str:
        obs_str = " + ".join(observations) if observations else "No observations"
        return f"Reasoning: [{obs_str}] -> ({condition_logic}) => Implies {conclusion}"
