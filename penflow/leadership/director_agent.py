from typing import List, Dict, Any, Optional
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.planning_pipeline import PlanningPipeline
from penflow.planning.execution_plan import ExecutionPlan
from penflow.leadership.economy_agent import EconomyAgent
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.leadership.director")

class ResearchDirectorAgent:
    """
    Research Director Agent: The supreme executive controller of PenFlow.
    Orchestrates scan cycles, supervises swarm execution, triggers dynamic re-planning
    when new observations emerge, and enforces budget constraints via EconomyAgent.
    """
    def __init__(
        self,
        knowledge_store: KnowledgeStore,
        economy_agent: Optional[EconomyAgent] = None,
        planning_pipeline: Optional[PlanningPipeline] = None
    ):
        self.knowledge_store = knowledge_store
        self.economy = economy_agent or EconomyAgent()
        self.pipeline = planning_pipeline or PlanningPipeline(self.knowledge_store)

    def evaluate_target_strategy(self, target_domain: str) -> ExecutionPlan:
        logger.info(f"[ResearchDirectorAgent] Strategic assessment initiated for target domain '{target_domain}'...")
        
        # Enforce budget approval before generating strategy
        self.economy.allocate_tokens(requested_tokens=500, estimated_cost=0.01)
        
        plan = self.pipeline.run_planning_cycle(target_domain)
        logger.info(f"[ResearchDirectorAgent] Strategy approved with Expected Value={plan.expected_value}")
        return plan

    def evaluate_mid_scan_replanning(self, target_domain: str, new_verified_count: int) -> Optional[ExecutionPlan]:
        """
        Dynamically triggers mid-scan re-planning if new high-value vulnerabilities or endpoints are discovered.
        """
        if new_verified_count > 0:
            logger.info(f"[ResearchDirectorAgent] New findings discovered! Triggering dynamic tactical re-planning for '{target_domain}'...")
            return self.pipeline.run_planning_cycle(target_domain)
        return None
