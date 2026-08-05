from typing import List, Dict, Optional
from penflow.testing.strategy import Strategy, TestingHypothesis
from penflow.testing.priority import TestingPriorityEngine

class StrategyBuilder:
    """
    Builds executable testing strategies from knowledge, observations, and hypotheses.
    """
    def __init__(self, priority_engine: Optional[TestingPriorityEngine] = None):
        self.priority_engine = priority_engine or TestingPriorityEngine()

    def build_strategy(self, hypothesis: TestingHypothesis) -> Strategy:
        strat = Strategy(
            title=f"Testing Strategy for {hypothesis.target}",
            ordered_execution_plan=[f"Execute capability {cap}" for cap in hypothesis.required_capabilities],
            required_agents=[],
            expected_evidence=hypothesis.required_evidence,
            validation_rules=["Verify response code", "Check data isolation"],
            stop_conditions=hypothesis.blocking_conditions,
            success_conditions=["Evidence bundle matched"]
        )
        return strat
