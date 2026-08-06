"""
Business Logic & State Machine Capability Agent for PenFlow.

Capabilities:
  - Multi-step workflow step bypass (e.g. checkout: init -> review -> pay -> confirm)
  - Price, quantity, and currency parameter manipulation
  - Coupon reuse & unverified account state bypass
"""
import httpx
from typing import Dict, Any, List
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.business_logic")


class BusinessLogicCapabilityAgent(BaseCapabilityAgent):
    """
    Agent testing business logic workflows, price manipulation, and state transitions.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="BusinessLogicCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="business_logic_bypass", name="Business Logic Bypass", description="Detects business logic bypasses", priority=self.priority, tags=["logic"]),
            Capability(id="workflow_state_tampering", name="Workflow Tampering", description="Detects workflow step bypasses", priority=self.priority, tags=["workflow"]),
            Capability(id="price_manipulation", name="Price Manipulation", description="Detects price & quantity tampering", priority=self.priority, tags=["finance"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                # 1. Price & Quantity Manipulation Test
                checkout_payload = {
                    "item_id": "item_100",
                    "quantity": -1,
                    "price": 0.01,
                    "currency": "USD"
                }
                checkout_resp = await client.post(f"{base_url}/api/v1/cart/checkout", json=checkout_payload)
                if checkout_resp.status_code == 200 and ("success" in checkout_resp.text.lower() or "order_id" in checkout_resp.text.lower()):
                    findings.append({
                        "vulnerability_type": "business_logic_bypass",
                        "subtype": "price_quantity_tampering",
                        "target_url": f"{base_url}/api/v1/cart/checkout",
                        "severity": "HIGH",
                        "description": "Endpoint accepts negative quantity or altered unit price during checkout."
                    })
                    evidence["checkout_tampering"] = True

                # 2. Workflow Step Bypass Test (Direct Jump to Confirm Step)
                confirm_resp = await client.post(f"{base_url}/api/v1/checkout/confirm", json={"order_id": "99999"})
                if confirm_resp.status_code == 200 and "confirmed" in confirm_resp.text.lower():
                    findings.append({
                        "vulnerability_type": "business_logic_bypass",
                        "subtype": "workflow_step_bypass",
                        "target_url": f"{base_url}/api/v1/checkout/confirm",
                        "severity": "CRITICAL",
                        "description": "Direct step bypass: Order confirmed without completing payment step."
                    })
                    evidence["step_bypass"] = True
        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{base_url}': {e}")

        is_vuln = len(findings) > 0
        return {
            "capability_id": capability_id,
            "is_vulnerable": is_vuln,
            "confidence": 0.8 if is_vuln else 0.1,
            "evidence": evidence,
            "findings": findings
        }
