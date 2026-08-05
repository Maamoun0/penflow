from dataclasses import dataclass
from typing import Dict, Any
from penflow.planning.hypothesis import Hypothesis

@dataclass
class PlanningDecision:
    hypothesis_id: str
    decision_type: str  # IGNORE, OBSERVE, CONTINUE_RECON, COLLECT_EVIDENCE, CREATE_STRATEGY, ARCHIVE
    explanation: str

class DecisionEngine:
    """
    Evaluates hypotheses and produces explainable planning decisions.
    """
    def decide(self, hypothesis: Hypothesis) -> PlanningDecision:
        if hypothesis.status == "INVALIDATED" or hypothesis.confidence < 0.2:
            return PlanningDecision(
                hypothesis_id=hypothesis.id,
                decision_type="ARCHIVE",
                explanation=f"Hypothesis confidence is too low ({hypothesis.confidence}). Archiving."
            )

        if hypothesis.confidence >= 0.7:
            return PlanningDecision(
                hypothesis_id=hypothesis.id,
                decision_type="CREATE_STRATEGY",
                explanation=f"High confidence ({hypothesis.confidence}). Ready for testing strategy creation."
            )

        if hypothesis.confidence >= 0.4:
            return PlanningDecision(
                hypothesis_id=hypothesis.id,
                decision_type="COLLECT_EVIDENCE",
                explanation=f"Moderate confidence ({hypothesis.confidence}). Additional evidence required."
            )

        return PlanningDecision(
            hypothesis_id=hypothesis.id,
            decision_type="OBSERVE",
            explanation=f"Low confidence ({hypothesis.confidence}). Continuing passive observation."
        )
