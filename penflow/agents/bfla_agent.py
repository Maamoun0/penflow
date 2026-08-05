from typing import List, Dict, Any, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.traffic.models import IdentityType
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.bfla")

ADMIN_PATTERNS = ["admin", "manage", "system", "config", "delete", "create_user", "update_role", "billing", "settings"]

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

        # Identify candidate admin endpoints
        candidate_urls: List[str] = []
        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else (obs.data if hasattr(obs, "data") else {})
            if isinstance(data, dict):
                url = data.get("url", "")
                if any(pat in url.lower() for pat in ADMIN_PATTERNS):
                    candidate_urls.append(url)
                elif "endpoints" in data and isinstance(data["endpoints"], list):
                    for ep in data["endpoints"]:
                        ep_url = ep.get("url", "") if isinstance(ep, dict) else ""
                        if any(pat in ep_url.lower() for pat in ADMIN_PATTERNS):
                            candidate_urls.append(ep_url)

        if not candidate_urls:
            candidate_urls = [f"https://{context.asset}/api/v1/admin/users/export"]

        # Use unprivileged standard user or guest
        unpriv_user = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_B)
        if not unpriv_user:
            unpriv_user = session_mgr.create_identity("unpriv_tester", IdentityType.STANDARD_USER_B, bearer_token="penflow_unpriv_token")

        findings: List[Dict[str, Any]] = []

        for target_url in candidate_urls:
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

            if status == 200:
                is_vuln = True
                confidence = 0.92
                reasoning = f"Unprivileged identity '{unpriv_user.id}' received HTTP 200 on administrative endpoint '{target_url}'."
            elif status in [401, 403]:
                # 2. Try HTTP Method Tampering (POST / PUT / DELETE)
                for test_method in ["POST", "PUT", "DELETE"]:
                    tamper_exch = await http_client.send_as_identity(
                        identity_id=unpriv_user.id,
                        method=test_method,
                        url=target_url,
                        json_data={"action": "test"}
                    )
                    t_status = tamper_exch.response.status_code if tamper_exch.response else 0
                    if t_status in [200, 201, 204]:
                        is_vuln = True
                        confidence = 0.95
                        reasoning = f"Method tampering ({test_method}) bypassed authorization check on '{target_url}' (HTTP {t_status})."
                        exch = tamper_exch
                        break

            if not reasoning:
                reasoning = f"Endpoint '{target_url}' properly enforced RBAC boundary (HTTP {status})."

            findings.append({
                "target_url": target_url,
                "capability": capability_id,
                "is_vulnerable": is_vuln,
                "confidence_score": confidence,
                "reasoning": reasoning,
                "status_code": status,
                "evidence_exchange": exch.to_dict()
            })

        primary_finding = findings[0] if findings else {}

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": primary_finding.get("is_vulnerable", False),
            "confidence_score": primary_finding.get("confidence_score", 0.0),
            "findings_count": len(findings),
            "evidence": primary_finding
        }
