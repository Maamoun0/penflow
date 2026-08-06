from typing import List, Optional
from penflow.planning.planning_context import PlanningContext
from penflow.planning.hypothesis_builder import HypothesisBuilder
from penflow.planning.hypothesis_ranker import HypothesisRanker
from penflow.planning.decision_engine import DecisionEngine
from penflow.planning.execution_plan import ExecutionPlan
from penflow.planning.hypothesis import Hypothesis
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.planning.planner")

class Planner:
    """
    The reasoning brain of PenFlow.
    Transforms KnowledgeStore observations into ordered, explainable ExecutionPlan objects.
    NEVER executes security tests or HTTP requests.
    """
    def __init__(
        self,
        hypothesis_builder: Optional[HypothesisBuilder] = None,
        hypothesis_ranker: Optional[HypothesisRanker] = None,
        decision_engine: Optional[DecisionEngine] = None
    ):
        self.builder = hypothesis_builder or HypothesisBuilder()
        self.ranker = hypothesis_ranker or HypothesisRanker()
        self.decision_engine = decision_engine or DecisionEngine()

    def create_plan(self, context: PlanningContext) -> ExecutionPlan:
        logger.info(f"[Planner] Generating planning hypotheses for target '{context.target_domain}'...")
        
        all_observations = context.knowledge_store.observations.get_all()
        generated_hypotheses: List[Hypothesis] = []

        for obs in all_observations:
            obs_summary = f"{obs.observation_type} : {obs.data}"
            hyps = self.builder.build_from_observation(obs_summary)
            generated_hypotheses.extend(hyps)

        # Filter out invalidated / archived decisions
        actionable_hypotheses = []
        for h in generated_hypotheses:
            dec = self.decision_engine.decide(h)
            if dec.decision_type in ["CREATE_STRATEGY", "COLLECT_EVIDENCE", "OBSERVE"]:
                actionable_hypotheses.append(h)

        ranked = self.ranker.rank(actionable_hypotheses)

        # Correlate tech stack hints with writeup knowledge store
        from penflow.planning.writeup_correlator import WriteupCorrelator
        correlator = WriteupCorrelator()
        tech_hints = []
        for obs in all_observations:
            if obs.observation_type == "tech_fingerprint" and isinstance(obs.data, dict):
                tech_hints.extend(obs.data.get("technologies", []))

        boosted_caps = correlator.correlate_tech_stack(tech_hints)

        # Collect required capabilities across all ranked hypotheses
        caps = set(boosted_caps)
        for h in ranked:
            caps.update(h.required_capabilities)

        plan = ExecutionPlan(
            ordered_hypotheses=ranked,
            required_capabilities=list(caps),
            estimated_cost=round(len(ranked) * 0.5, 2),
            estimated_runtime_seconds=len(ranked) * 10.0,
            expected_value=round(sum(h.priority for h in ranked), 2)
        )
        logger.info(f"[Planner] ExecutionPlan created with {len(ranked)} hypotheses and {len(caps)} capabilities (Expected Value={plan.expected_value}).")
        return plan
