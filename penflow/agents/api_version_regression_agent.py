"""
API Version Regression Capability Agent for PenFlow.

Capabilities:
  - Legacy API Version Enumeration (/api/v1 vs /api/v2, /api/v3)
  - Broken Object Level Authorization (BOLA/IDOR) in Deprecated Endpoints
  - Security Control & Auth Bypass on Legacy API Versions
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.api_version_regression")


class APIVersionRegressionAgent(BaseCapabilityAgent):
    """
    Capability Agent probing deprecated or unmaintained legacy API versions (/v1, /v2, /v0, /beta)
    for security control downgrades and unauthenticated access.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="APIVersionRegressionAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="api_version_regression", name="API Version Regression", description="Detects authentication or security control bypasses on legacy/deprecated API versions", priority=self.priority, tags=["api", "regression", "versioning", "legacy"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        current_ep = f"{base_url}/api/v3/users/profile"
        legacy_eps = [
            f"{base_url}/api/v1/users/profile",
            f"{base_url}/api/v2/users/profile",
            f"{base_url}/api/v0/users/profile",
            f"{base_url}/api/beta/users/profile",
            f"{base_url}/api/v1/user/100"
        ]

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for leg_url in legacy_eps:
                    try:
                        resp = await client.get(leg_url)
                        if resp.status_code == 200 and ("email" in resp.text.lower() or "id" in resp.text.lower()):
                            curl_cmd = f"curl -i -s -k '{leg_url}'"
                            exch_dict = {
                                "request": {"method": "GET", "url": leg_url},
                                "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                            }

                            findings.append({
                                "vulnerability_type": "api_version_regression",
                                "target_url": leg_url,
                                "severity": "HIGH",
                                "confidence": 0.90,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("API Version Regression", leg_url, curl_cmd),
                                "description": f"Deprecated API version at '{leg_url}' remains active and returns sensitive user data without authentication.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["legacy_api_exposed"] = leg_url
                            break
                    except Exception as e:
                        logger.debug(f"API regression test failed on {leg_url}: {e}")

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
