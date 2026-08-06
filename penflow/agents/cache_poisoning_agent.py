"""
Web Cache Poisoning Capability Agent for PenFlow.

Capabilities:
  - Host Header Injection (X-Forwarded-Host, X-Host, X-Forwarded-Server)
  - Unkeyed Query Parameter & Cookie identification
  - Cache Poisoning Denial of Service (CPDoS) via oversized headers
"""
import httpx
from typing import Dict, Any, List
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.cache_poisoning")

CACHE_INJECTION_HEADERS = {
    "X-Forwarded-Host": "evil-poisoned-cache.com",
    "X-Host": "evil-poisoned-cache.com",
    "X-Forwarded-Server": "evil-poisoned-cache.com",
    "X-Original-URL": "/admin"
}


class WebCachePoisoningCapabilityAgent(BaseCapabilityAgent):
    """
    Agent detecting Web Cache Poisoning, Host Header Injection, and CPDoS vulnerabilities.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="WebCachePoisoningCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="cache_poisoning", name="Web Cache Poisoning", description="Detects cache poisoning via unkeyed headers", priority=self.priority, tags=["cache_poisoning"]),
            Capability(id="host_header_injection", name="Host Header Injection", description="Detects host header injection vectors", priority=self.priority, tags=["host_header"]),
            Capability(id="cpdos_analysis", name="Cache Poisoning DoS", description="Detects CPDoS vulnerabilities", priority=self.priority, tags=["cpdos"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                # 1. Host Header Injection check
                for h_name, h_val in CACHE_INJECTION_HEADERS.items():
                    headers = {h_name: h_val}
                    resp = await client.get(base_url, headers=headers)

                    if h_val in resp.text or (resp.headers.get("Location") and h_val in resp.headers["Location"]):
                        finding = {
                            "vulnerability_type": "cache_poisoning",
                            "subtype": "host_header_reflection",
                            "header_tested": h_name,
                            "poison_payload": h_val,
                            "target_url": base_url,
                            "severity": "HIGH",
                            "description": f"Target reflects unkeyed header '{h_name}' in response/redirect body."
                        }
                        findings.append(finding)
                        evidence[h_name] = {"status": resp.status_code, "reflected": True}

                # 2. CPDoS (Cache Poisoning Denial of Service) check via oversized headers
                cpdos_headers = {"X-Oversized-Header": "A" * 8192}
                cpdos_resp = await client.get(base_url, headers=cpdos_headers)
                if cpdos_resp.status_code in (400, 413, 500):
                    findings.append({
                        "vulnerability_type": "cache_poisoning",
                        "subtype": "cpdos_oversized_header",
                        "target_url": base_url,
                        "severity": "MEDIUM",
                        "description": f"Server returned HTTP {cpdos_resp.status_code} on oversized header, vulnerable to CPDoS."
                    })
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
