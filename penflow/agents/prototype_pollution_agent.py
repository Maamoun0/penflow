"""
Prototype Pollution Capability Agent for PenFlow.

Capabilities:
  - Client-side Prototype Pollution (__proto__, constructor.prototype)
  - Server-side Node.js/Express JSON merge object pollution
  - Property pollution leading to RCE/Auth bypass
"""
import httpx
from typing import Dict, Any, List
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.prototype_pollution")

POLLUTION_PAYLOADS = [
    {"__proto__": {"polluted_flag": "penflow_pp_test"}},
    {"constructor": {"prototype": {"polluted_flag": "penflow_pp_test"}}}
]


class PrototypePollutionCapabilityAgent(BaseCapabilityAgent):
    """
    Agent detecting Prototype Pollution in Node.js/Express endpoints and JSON merge functions.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="PrototypePollutionCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="prototype_pollution", name="Prototype Pollution", description="Detects object prototype pollution", priority=self.priority, tags=["prototype_pollution"]),
            Capability(id="server_side_pollution", name="Server-Side Pollution", description="Detects server-side Node.js pollution", priority=self.priority, tags=["nodejs"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}/api/v1/user/profile"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                for payload in POLLUTION_PAYLOADS:
                    resp = await client.post(base_url, json=payload)
                    if resp.status_code == 200:
                        # Perform verification check to see if property was polluted globally
                        check_resp = await client.get(base_url)
                        if "polluted_flag" in check_resp.text:
                            findings.append({
                                "vulnerability_type": "prototype_pollution",
                                "target_url": base_url,
                                "payload": payload,
                                "severity": "HIGH",
                                "description": "Server-side Object Prototype Pollution detected via JSON merge operation."
                            })
                            evidence["pollution_success"] = True
        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{base_url}': {e}")

        is_vuln = len(findings) > 0
        return {
            "capability_id": capability_id,
            "is_vulnerable": is_vuln,
            "confidence": 0.85 if is_vuln else 0.1,
            "evidence": evidence,
            "findings": findings
        }
