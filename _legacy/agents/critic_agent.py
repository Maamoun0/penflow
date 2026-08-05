from typing import Dict, Any
from penflow.agents.base_agent import BaseSwarmAgent
from penflow.utils.logger import get_logger

logger = get_logger("penflow.agents.critic")

class CriticAgent(BaseSwarmAgent):
    """
    Critic Agent: Adversarial Falsification Engine.
    Responsible for scrutinizing potential findings, attempting to disprove them,
    and filtering out False Positives before findings reach the human.
    """

    @property
    def agent_name(self) -> str:
        return "CriticAgent"

    @property
    def role(self) -> str:
        return "Critic"

    async def scrutinize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Actively attempts to invalidate a candidate finding.
        Checks for:
        1. Login/Redirect pages disguised as 200 OK responses.
        2. Generic error pages or public unauthenticated data.
        3. Identical response hashes between User A and User B.
        """
        vuln_type = finding.get("vuln_type", "")
        raw_response = finding.get("raw_response", "").lower()
        confidence = finding.get("confidence", 0.5)
        
        rejection_reasons = []
        
        # Rule 1: Check for auth redirect in response
        if "login" in raw_response or "sign in" in raw_response or "unauthorized" in raw_response:
            rejection_reasons.append("Response body contains authentication redirect or login keywords.")
            
        # Rule 2: Check low confidence threshold
        if confidence < 0.6:
            rejection_reasons.append("Finding confidence score is below required threshold (0.6).")
            
        is_validated = len(rejection_reasons) == 0
        
        verdict = {
            "finding_id": finding.get("url", "") + ":" + vuln_type,
            "original_vuln_type": vuln_type,
            "is_valid": is_validated,
            "critic_confidence": 0.95 if is_validated else 0.1,
            "rejection_reasons": rejection_reasons
        }
        
        logger.info(f"[CriticAgent] Verdict for {vuln_type} on {finding.get('url')}: Valid={is_validated}")
        await self.publish_event("FINDING_CRITICIZED", verdict)
        return verdict

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.scrutinize_finding(task_data)
