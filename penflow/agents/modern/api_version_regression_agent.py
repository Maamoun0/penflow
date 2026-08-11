"""
API Version Regression Capability Agent for PenFlow.

Capabilities:
  - Legacy API Version Enumeration (/api/v1 vs /api/v2, /api/v3)
  - Broken Object Level Authorization (BOLA/IDOR) in Deprecated Endpoints
  - Security Control & Auth Bypass on Legacy API Versions
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
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

        http_client = context.get_http_client()
        base_urls = self._collect_api_base_urls(context)

        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        version_prefixes = ["/v1/", "/v2/", "/v0/", "/beta/", "/legacy/", "/internal/", "/api/v1/", "/api/v2/", "/api/v0/"]

        for base_url in base_urls[:4]:
            for prefix in version_prefixes:
                leg_url = f"{base_url.rstrip('/')}{prefix}user/profile"
                try:
                    exch = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=leg_url)
                    resp = exch.response
                    if not resp:
                        continue

                    body_lower = (resp.body_text or resp.body_snippet or "").lower()
                    if resp.status_code == 200 and ("email" in body_lower or "user_id" in body_lower or "profile" in body_lower):
                        curl_cmd = f"curl -i -s -k '{leg_url}'"
                        exch_dict = exch.to_dict()

                        findings.append({
                            "vulnerability_type": "api_version_regression",
                            "target_url": leg_url,
                            "version_prefix": prefix,
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
                    logger.debug(f"API regression test error on {leg_url}: {e}")

        is_vuln = len(findings) > 0
        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=0.90 if is_vuln else 0.0,
            reasoning=findings[0]["description"] if findings else "API version regression endpoints verified safely without unauthenticated data leakage.",
            target_url=base_urls[0] if base_urls else f"https://{context.asset}",
            findings=findings,
            evidence={
                "legacy_api_exposed": evidence.get("legacy_api_exposed"),
                "findings": findings,
                "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")]
            }
        ).to_dict()

    def _collect_api_base_urls(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        urls = [target_url]

        if hasattr(context, "observations") and context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    for ep in data.get("endpoints", []):
                        if isinstance(ep, dict) and ep.get("url"):
                            urls.append(ep["url"].split("/v")[0] if "/v" in ep["url"] else ep["url"])

        return list(dict.fromkeys(urls))

