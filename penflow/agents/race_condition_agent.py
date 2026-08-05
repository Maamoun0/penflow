import asyncio
from typing import List, Dict, Any, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.traffic.models import IdentityType, TrafficRequest
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.race_condition")

STATE_CHANGING_PATTERNS = ["redeem", "coupon", "claim", "transfer", "apply", "vote", "withdraw", "checkout"]

class RaceConditionCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for Race Condition and Concurrency TOCTOU (Time-of-Check to Time-of-Use) testing.
    Executes synchronized parallel HTTP bursts against state-mutating endpoints.
    """
    def __init__(self, priority: int = 10, burst_size: int = 5):
        super().__init__(agent_name="RaceConditionCapabilityAgent", priority=priority)
        self.burst_size = burst_size

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="race_condition_check",
                name="Race Condition / TOCTOU Flaw Check",
                description="Sends synchronized concurrent request bursts to test for double-spend and state race conditions",
                priority=self.priority,
                tags=["race_condition", "concurrency", "business_logic"]
            ),
            Capability(
                id="concurrency_burst",
                name="Concurrent Burst Execution",
                description="Simulates parallel asynchronous bursts against single-use tokens and resources",
                priority=self.priority,
                tags=["burst", "logic", "toctou"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[RaceConditionCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}' with burst size {self.burst_size}")

        http_client = context.get_http_client()
        session_mgr = context.session_manager

        user_ident = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_A)
        if not user_ident:
            user_ident = session_mgr.create_identity("concurrency_tester", IdentityType.STANDARD_USER_A, bearer_token="penflow_test_token")

        candidate_url = f"https://{context.asset}/api/v1/coupon/redeem"

        # Send simultaneous burst using asyncio.gather
        burst_tasks = [
            http_client.send_as_identity(
                identity_id=user_ident.id,
                method="POST",
                url=candidate_url,
                json_data={"code": "PROMO2026", "item_id": 1}
            )
            for _ in range(self.burst_size)
        ]

        exchanges = await asyncio.gather(*burst_tasks)

        successful_responses = [
            exch for exch in exchanges
            if exch.response and exch.response.status_code in [200, 201]
        ]

        # If a single-use action succeeded more than once in the parallel burst, potential race condition!
        is_vulnerable = len(successful_responses) > 1
        confidence = 0.90 if is_vulnerable else 0.0
        reasoning = (
            f"Race condition detected! {len(successful_responses)} of {self.burst_size} parallel requests succeeded."
            if is_vulnerable else
            f"Concurrency boundary held: {len(successful_responses)} successful requests out of {self.burst_size} attempts."
        )

        evidence = {
            "target_url": candidate_url,
            "burst_size": self.burst_size,
            "success_count": len(successful_responses),
            "status_codes": [exch.response.status_code if exch.response else 0 for exch in exchanges],
            "reasoning": reasoning,
            "sample_exchange": exchanges[0].to_dict() if exchanges else None
        }

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vulnerable,
            "confidence_score": confidence,
            "evidence": evidence
        }
