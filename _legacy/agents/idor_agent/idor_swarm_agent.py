from typing import Dict, Any, List
from penflow.agents.base_agent import BaseSwarmAgent
from penflow.scanner.vuln_detectors.idor_bola import IDORDetector
from penflow.network.http_client import HttpClient
from penflow.network.auth_session_manager import AuthSessionManager
from penflow.utils.logger import get_logger

logger = get_logger("penflow.agents.idor_swarm")

class IDORSwarmAgent(BaseSwarmAgent):
    """
    IDOR / BOLA Swarm Agent: Specialized vulnerability hunter for Broken Object Level Auth.
    Fully integrated into the Swarm communication bus to send candidate findings to CriticAgent.
    """

    def __init__(self, event_bus=None, memory_manager=None):
        super().__init__(event_bus, memory_manager)
        self.detector = IDORDetector()

    @property
    def agent_name(self) -> str:
        return "IDORSwarmAgent"

    @property
    def role(self) -> str:
        return "VulnerabilitySpecialist"

    async def execute_idor_tests(self, endpoint: Dict[str, Any], http_client: HttpClient, auth_manager: AuthSessionManager) -> List[Dict[str, Any]]:
        """
        Execute BOLA/IDOR tests using dual-account cross-session swapping.
        Emits candidate findings over the EventBus for CriticAgent scrutinization.
        """
        config = {"auth_manager": auth_manager}
        candidate_findings = await self.detector.detect(endpoint, http_client, config)
        
        for finding in candidate_findings:
            logger.info(f"[IDORSwarmAgent] Found candidate BOLA vulnerability on {finding.get('url')}")
            await self.publish_event("CANDIDATE_FINDING_DISCOVERED", finding)
            
        return candidate_findings

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        endpoint = task_data.get("endpoint", {})
        http_client = task_data.get("http_client")
        auth_manager = task_data.get("auth_manager")
        
        if endpoint and http_client and auth_manager:
            findings = await self.execute_idor_tests(endpoint, http_client, auth_manager)
            return {"findings_count": len(findings), "findings": findings}
            
        return {"status": "error", "message": "Missing required task parameters"}
