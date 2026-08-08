"""
Business Logic & State Machine Capability Agent for PenFlow.

Capabilities:
  - Multi-step workflow state machine bypass (checkout: cart -> review -> pay -> confirm)
  - Price, quantity (-1), zero-currency, and promo discount manipulation
  - Coupon code multi-use & state bypass verification
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.business_logic")


class BusinessLogicCapabilityAgent(BaseCapabilityAgent):
    """
    Comprehensive Agent testing multi-step state machine workflows, price/quantity tampering,
    and coupon code reuse chains.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="BusinessLogicCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="business_logic_bypass", name="Business Logic & State Machine Bypass", description="Detects business logic bypasses and state machine violations", priority=self.priority, tags=["logic", "state-machine"]),
            Capability(id="workflow_state_tampering", name="Workflow Step Bypass", description="Detects checkout and workflow step skipping", priority=self.priority, tags=["workflow"]),
            Capability(id="price_manipulation", name="Price & Quantity Tampering", description="Detects negative quantity and price parameter manipulation", priority=self.priority, tags=["finance", "tampering"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
                # 1. Multi-Step State Machine Checkout Test (Negative Quantity & Price Tampering)
                checkout_payload = {
                    "item_id": "item_100",
                    "quantity": -1,
                    "price": 0.01,
                    "currency": "USD",
                    "coupon": "WELCOME10"
                }
                checkout_url = f"{base_url}/api/v1/cart/checkout"
                checkout_resp = await client.post(checkout_url, json=checkout_payload)
                if checkout_resp.status_code == 200 and ("success" in checkout_resp.text.lower() or "order_id" in checkout_resp.text.lower()):
                    curl_cmd = f"curl -X POST {checkout_url} -H 'Content-Type: application/json' -d '{checkout_payload}'"
                    findings.append({
                        "vulnerability_type": "business_logic_bypass",
                        "subtype": "price_quantity_tampering",
                        "target_url": checkout_url,
                        "severity": "HIGH",
                        "confidence": 0.92,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Price & Quantity Tampering", checkout_url, curl_cmd),
                        "description": "Endpoint accepts negative quantity (-1) or altered price (0.01) during checkout."
                    })
                    evidence["checkout_tampering"] = True

                # 2. Workflow Step Bypass Test (Direct Jump to Confirm Step)
                confirm_url = f"{base_url}/api/v1/checkout/confirm"
                confirm_resp = await client.post(confirm_url, json={"order_id": "99999", "payment_status": "bypassed"})
                if confirm_resp.status_code == 200 and ("confirmed" in confirm_resp.text.lower() or "order_complete" in confirm_resp.text.lower()):
                    curl_cmd = f"curl -X POST {confirm_url} -H 'Content-Type: application/json' -d '{{\"order_id\": \"99999\", \"payment_status\": \"bypassed\"}}'"
                    findings.append({
                        "vulnerability_type": "business_logic_bypass",
                        "subtype": "workflow_step_bypass",
                        "target_url": confirm_url,
                        "severity": "CRITICAL",
                        "confidence": 0.95,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Workflow Step Bypass", confirm_url, curl_cmd),
                        "description": "Direct step bypass: Order confirmed without completing mandatory payment step."
                    })
                    evidence["step_bypass"] = True

                # 3. Coupon Code Double Use Test
                coupon_url = f"{base_url}/api/v1/cart/apply_coupon"
                await client.post(coupon_url, json={"coupon": "SAVE50"})
                second_coupon_resp = await client.post(coupon_url, json={"coupon": "SAVE50"})
                if second_coupon_resp.status_code == 200 and "applied" in second_coupon_resp.text.lower():
                    curl_cmd = f"curl -X POST {coupon_url} -H 'Content-Type: application/json' -d '{{\"coupon\": \"SAVE50\"}}'"
                    findings.append({
                        "vulnerability_type": "business_logic_bypass",
                        "subtype": "coupon_reuse",
                        "target_url": coupon_url,
                        "severity": "MEDIUM",
                        "confidence": 0.88,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Coupon Reuse", coupon_url, curl_cmd),
                        "description": "Single-use promotional coupon applied multiple times in the same transaction."
                    })
                    evidence["coupon_reuse"] = True

        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{base_url}': {e}")

        is_vuln = len(findings) > 0
        max_conf = max([f.get("confidence", 0.0) for f in findings], default=0.0)
        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": self.name,
            "is_vulnerable": is_vuln,
            "vulnerable": is_vuln,
            "confidence": max_conf,
            "confidence_score": max_conf,
            "evidence": evidence,
            "findings": findings
        }
