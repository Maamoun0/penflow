from typing import Dict, Any, Optional
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.planning_context import PlanningContext
from penflow.planning.planner import Planner
from penflow.planning.execution_plan import ExecutionPlan
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.planning.pipeline")

class PlanningPipeline:
    """
    End-to-End Planning Pipeline orchestrating:
    Observation -> Knowledge Update -> Reasoning -> Hypothesis -> Confidence -> Priority -> Decision -> Execution Plan
    """
    def __init__(self, knowledge_store: KnowledgeStore, planner: Optional[Planner] = None):
        self.knowledge_store = knowledge_store
        self.planner = planner or Planner()

    def run_planning_cycle(self, target_domain: str) -> ExecutionPlan:
        context = PlanningContext(
            knowledge_store=self.knowledge_store,
            target_domain=target_domain
        )
        logger.info(f"[PlanningPipeline] Triggering planning cycle for '{target_domain}'")
        return self.planner.create_plan(context)
