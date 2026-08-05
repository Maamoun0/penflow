from typing import Dict, Any, List
from penflow.agents.base_agent import BaseSwarmAgent
from penflow.utils.logger import get_logger

logger = get_logger("penflow.agents.director")

class ResearchDirectorAgent(BaseSwarmAgent):
    """
    Research Director Agent: Senior Strategic Lead of the Swarm.
    Responsible for high-level decision making, re-planning based on new intel,
    and directing specialized agents without doing raw execution directly.
    """

    @property
    def agent_name(self) -> str:
        return "ResearchDirectorAgent"

    @property
    def role(self) -> str:
        return "Director"

    async def evaluate_next_step(self, target_intel: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate target state and decide the optimal next strategic step.
        Asks key questions: Is GraphQL present? OAuth? API endpoints? Need more recon?
        """
        target = target_intel.get("target", "")
        tech_stack = target_intel.get("tech_stack", [])
        discovered_endpoints = target_intel.get("endpoints", [])
        
        has_graphql = any("graphql" in str(ep).lower() for ep in discovered_endpoints) or "GraphQL" in tech_stack
        has_oauth = any("oauth" in str(ep).lower() for ep in discovered_endpoints) or "OAuth" in tech_stack
        
        decision = {
            "target": target,
            "recommended_action": "RECON_EXPANSION",
            "priority_agents": [],
            "reasoning": ""
        }
        
        if not discovered_endpoints:
            decision["recommended_action"] = "DEEP_CRAWL"
            decision["priority_agents"] = ["ReconAgent", "WebAgent"]
            decision["reasoning"] = "No endpoints discovered yet. Initiate deep web crawling."
        elif has_graphql:
            decision["recommended_action"] = "TEST_GRAPHQL_SECURITY"
            decision["priority_agents"] = ["APIAgent", "AuthzAgent", "IDORAgent"]
            decision["reasoning"] = "GraphQL detected! Focus on schema introspection and BOLA/IDOR queries."
        elif has_oauth:
            decision["recommended_action"] = "TEST_OAUTH_FLOWS"
            decision["priority_agents"] = ["AuthAgent", "AuthzAgent"]
            decision["reasoning"] = "OAuth indicators detected. Evaluate redirect URI & token state validation."
        else:
            decision["recommended_action"] = "CROSS_SESSION_BOLA_TESTING"
            decision["priority_agents"] = ["IDORAgent", "BFLAAgent", "MassAssignAgent"]
            decision["reasoning"] = "Standard REST API structure detected. Initiate cross-session authorization tests."
            
        logger.info(f"[ResearchDirectorAgent] Strategic Decision for {target}: {decision['recommended_action']}")
        await self.publish_event("STRATEGY_DECISION_MADE", decision)
        return decision

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.evaluate_next_step(task_data)
