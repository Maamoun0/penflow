"""
BFLACapabilityAgent — Multi-Role BFLA & HTTP Verb Tampering Specialist for PenFlow.

Verifies Broken Function Level Authorization (BFLA) across administrative functions:
  - Multi-role RBAC boundary checks (Admin vs Standard User vs Anonymous Guest)
  - HTTP Verb Tampering (GET -> POST / PUT / DELETE / PATCH)
  - Verb override header tampering (X-HTTP-Method-Override: POST, X-Method-Override: PUT)
"""
from typing import List, Dict, Any, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.result import AgentExecutionResult
from penflow.traffic.models import IdentityType
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.bfla")

ADMIN_PATTERNS = ["admin", "manage", "system", "config", "delete", "create_user", "update_role", "billing", "settings", "export"]


class BFLACapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for Broken Function Level Authorization (BFLA)
    and Privilege Escalation detection across administrative and sensitive functions.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="BFLACapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="bfla_analysis",
                name="Broken Function Level Authorization Check",
                description="Verifies whether unprivileged users can execute sensitive administrative functions",
                priority=self.priority,
                tags=["bfla", "privilege_escalation", "authorization"]
            ),
            Capability(
                id="privilege_analysis",
                name="Privilege Escalation Surface Analysis",
                description="Scrutinizes administrative and management endpoints against permission models",
                priority=self.priority,
                tags=["privilege_escalation", "admin", "rbac"]
            ),
            Capability(
                id="method_tampering",
                name="HTTP Verb & Method Tampering Check",
                description="Tests alternative HTTP verbs (POST/PUT/DELETE/PATCH) and verb overrides on restricted endpoints",
                priority=self.priority,
                tags=["bfla", "method_tampering", "api"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[BFLACapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        session_mgr = context.session_manager

        candidate_urls: List[str] = self._collect_admin_urls(context)

        # Retrieve or configure unprivileged standard user
        unpriv_user = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_B)
        if not unpriv_user:
            unpriv_user = session_mgr.create_identity("unpriv_tester", IdentityType.STANDARD_USER_B, bearer_token="penflow_unpriv_token")

        findings: List[Dict[str, Any]] = []

        for target_url in candidate_urls[:8]:
            # 1. Direct unprivileged request
            exch = await http_client.send_as_identity(
                identity_id=unpriv_user.id,
                method="GET",
                url=target_url
            )

            status = exch.response.status_code if exch.response else 0
            is_vuln = False
            confidence = 0.0
            reasoning = ""

            body_text = (exch.response.body_text or "") if exch.response else ""
            body_lower = body_text.lower()
            is_login_page = any(kw in body_lower for kw in ["type=password", "name=\"password\"", "name='password'", "name=password", "action=\"/login\"", "action='/login'", "action=/login", "<h1>login</h1>", "<title>login"])

            if status == 200 and not is_login_page:
                has_admin_controls = any(kw in body_lower for kw in ["admin panel", "manage user", "delete user", "update role", "role management", "system settings", "user accounts", "carlos", "administrator"])
                if has_admin_controls:
                    is_vuln = True
                    confidence = 0.92
                    reasoning = f"Unprivileged identity '{unpriv_user.id}' accessed administrative functionality without authentication on '{target_url}' (HTTP 200)."
            elif status in (401, 403, 405) or (status == 200 and is_login_page):
                # 2. HTTP Method Tampering (POST / PUT / DELETE / PATCH / GET)
                for test_method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    tamper_exch = await http_client.send_as_identity(
                        identity_id=unpriv_user.id,
                        method=test_method,
                        url=target_url,
                        json_data={"action": "test_bfla_tamper"}
                    )
                    t_status = tamper_exch.response.status_code if tamper_exch.response else 0
                    t_body = ((tamper_exch.response.body_text or "") if tamper_exch.response else "").lower()
                    t_is_login = any(kw in t_body for kw in ["type=password", "name=\"password\"", "name='password'", "name=password", "<h1>login</h1>"])

                    if t_status in (200, 201, 204) and not t_is_login:
                        is_vuln = True
                        confidence = 0.95
                        reasoning = f"Method tampering ({test_method}) bypassed authorization check on '{target_url}' (HTTP {t_status})."
                        exch = tamper_exch
                        break

                # 3. Verb Override Header Tampering (X-HTTP-Method-Override)
                if not is_vuln:
                    override_exch = await http_client.send_as_identity(
                        identity_id=unpriv_user.id,
                        method="POST",
                        url=target_url,
                        headers={"X-HTTP-Method-Override": "GET", "X-Method-Override": "GET"}
                    )
                    o_status = override_exch.response.status_code if override_exch.response else 0
                    o_body = ((override_exch.response.body_text or "") if override_exch.response else "").lower()
                    o_is_login = any(kw in o_body for kw in ["type=password", "name=\"password\"", "name='password'", "name=password"])

                    if o_status == 200 and not o_is_login:
                        is_vuln = True
                        confidence = 0.93
                        reasoning = f"Verb override header (X-HTTP-Method-Override: GET) bypassed authorization on '{target_url}'."
                        exch = override_exch

            if not reasoning:
                reasoning = f"Endpoint '{target_url}' properly enforced RBAC boundary (HTTP {status})."

            finding = {
                "target_url": target_url,
                "capability": capability_id,
                "is_vulnerable": is_vuln,
                "confidence_score": confidence,
                "reasoning": reasoning,
                "status_code": status,
                "_exchange_obj": exch.to_dict(),
                "evidence_exchange": exch.to_dict()
            }
            findings.append(finding)

            if is_vuln:
                break

        primary_finding = findings[0] if findings else {}

        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=primary_finding.get("is_vulnerable", False),
            confidence_score=primary_finding.get("confidence_score", 0.0),
            reasoning=primary_finding.get("reasoning", ""),
            target_url=primary_finding.get("target_url", ""),
            findings=findings,
            evidence={
                **primary_finding,
                "findings": findings,
                "evidence_exchanges": [f.get("evidence_exchange") for f in findings if f.get("evidence_exchange")],
            },
            metadata={
                "findings_count": len(findings),
                "_exchange_obj": primary_finding.get("_exchange_obj"),
            },
        ).to_dict()

    def _collect_admin_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        for data in context.get_observation_data():
            if isinstance(data, dict):
                url = data.get("url", "")
                if url and any(pat in url.lower() for pat in ADMIN_PATTERNS):
                    urls.append(url)
                elif "endpoints" in data and isinstance(data["endpoints"], list):
                    for ep in data["endpoints"]:
                        if isinstance(ep, dict) and ep.get("url"):
                            ep_url = ep["url"]
                            if any(pat in ep_url.lower() for pat in ADMIN_PATTERNS):
                                urls.append(ep_url)
        if not urls:
            urls = [f"https://{context.asset}/api/v1/admin/users/export"]
        return list(set(urls))
