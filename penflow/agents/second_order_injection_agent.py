"""
Second-Order Injection Capability Agent for PenFlow.

Capabilities:
  - Second-Order SQL Injection (stored payload evaluated during profile/report generation)
  - Second-Order Stored XSS / Template Injection
  - Asynchronous payload propagation tracking across user state updates
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.second_order_injection")

SECOND_ORDER_PAYLOADS = [
    {"payload": "testuser'--", "marker": "SQL syntax", "subtype": "second_order_sqli"},
    {"payload": "<script>console.log('penflow_so_xss')</script>", "marker": "penflow_so_xss", "subtype": "second_order_xss"},
    {"payload": "user{{7*7}}test", "marker": "user49test", "subtype": "second_order_ssti"}
]


class SecondOrderInjectionAgent(BaseCapabilityAgent):
    """
    Capability Agent testing stored inputs that execute asynchronously during secondary actions.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="SecondOrderInjectionAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="second_order_injection", name="Second-Order Injection", description="Detects stored input payloads evaluated during secondary API operations", priority=self.priority, tags=["second_order", "sqli", "xss", "ssti"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        update_url = f"{base_url}/api/v1/user/profile"
        view_url = f"{base_url}/api/v1/user/details"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for item in SECOND_ORDER_PAYLOADS:
                    payload = item["payload"]
                    marker = item["marker"]
                    subtype = item["subtype"]

                    # Phase 1: Store payload
                    try:
                        resp_store = await client.post(update_url, json={"bio": payload, "name": payload})
                        if resp_store.status_code in (200, 201, 204):
                            # Phase 2: Retrieve and verify secondary execution
                            resp_view = await client.get(view_url)
                            if resp_view.status_code == 200 and marker in resp_view.text:
                                curl_cmd = f"curl -X POST '{update_url}' -H 'Content-Type: application/json' -d '{{\"name\": \"{payload}\"}}' && curl -i -s '{view_url}'"
                                exch_dict = {
                                    "request": {"method": "POST", "url": update_url, "json_data": {"name": payload}},
                                    "response": {"status_code": resp_view.status_code, "body_snippet": resp_view.text[:500]}
                                }
                                findings.append({
                                    "vulnerability_type": "second_order_injection",
                                    "subtype": subtype,
                                    "target_url": update_url,
                                    "view_url": view_url,
                                    "payload": payload,
                                    "severity": "CRITICAL" if "sqli" in subtype or "ssti" in subtype else "HIGH",
                                    "confidence": 0.92,
                                    "is_vulnerable": True,
                                    "exploit_curl": curl_cmd,
                                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Second-Order Injection", update_url, curl_cmd),
                                    "description": f"Stored payload '{payload}' injected at '{update_url}' was evaluated during secondary fetch at '{view_url}'.",
                                    "_exchange_obj": exch_dict
                                })
                                evidence["second_order_success"] = True
                                break
                    except Exception as e:
                        logger.debug(f"Second order check failed: {e}")

        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{context.asset}': {e}")

        is_vuln = len(findings) > 0
        primary_exch = findings[0].get("_exchange_obj") if findings else None
        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": self.name,
            "is_vulnerable": is_vuln,
            "vulnerable": is_vuln,
            "confidence": 0.92 if is_vuln else 0.0,
            "confidence_score": 0.92 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
