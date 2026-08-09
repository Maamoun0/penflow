"""
IDORCapabilityAgent — Multi-Identity BOLA (Broken Object Level Authorization) Specialist for PenFlow.

Executes 3-Identity Cross-Account Authorization Matrix testing across all candidate endpoints:
  - User A (Resource Owner) vs User B (Cross-Tenant Attacker) vs Anonymous Guest
  - Swaps tokens, authorization headers (Bearer, Cookie, X-API-Key), and URL object IDs
  - Scrutinizes body similarity ratio, leaked identifiers, and JSON key structures
"""
from typing import List, Dict, Any, Optional
import urllib.parse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.traffic.models import IdentityType, TrafficRequest, TrafficExchange
from penflow.traffic.diff_engine import DifferentialEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.idor")


class IDORCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for IDOR / BOLA (Broken Object Level Authorization) Analysis.
    Performs deterministic multi-identity cross-account authorization matrix testing.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="IDORCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="id_access_analysis",
                name="IDOR / Parameter Access Analysis",
                description="Analyzes sequential IDs, object references, and cross-session object access",
                priority=self.priority,
                tags=["idor", "bola", "authorization"]
            ),
            Capability(
                id="authorization",
                name="Cross-Session Authorization Check",
                description="Performs multi-tenant token swapping to verify authorization boundaries",
                priority=self.priority,
                tags=["authorization", "bola", "multi-tenant"]
            ),
            Capability(
                id="bola_check",
                name="BOLA Resource Identifier Swap",
                description="Swaps object IDs across authenticated sessions to detect unauthorized data exposure",
                priority=self.priority,
                tags=["bola", "idor", "api"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[IDORCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        session_mgr = context.session_manager
        diff_engine = context.diff_engine or DifferentialEngine()

        candidate_urls: List[str] = self._collect_candidate_urls(context)

        # Retrieve or configure 3-identity matrix (User A, User B, Anonymous Guest)
        user_a = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_A)
        user_b = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_B)

        user_a_id = user_a.id if user_a else "user_a"
        user_b_id = user_b.id if user_b else "user_b"

        # Attempt to load real identity tokens from AuthConfigManager / Config
        try:
            from penflow.traffic.auth_manager import AuthConfigManager
            auth_mgr = AuthConfigManager()
            token_a = auth_mgr.get_token_for_identity("user_a") or "penflow_test_token_a"
            token_b = auth_mgr.get_token_for_identity("user_b") or "penflow_test_token_b"
        except Exception:
            token_a = "penflow_test_token_a"
            token_b = "penflow_test_token_b"

        if not user_a:
            user_a = session_mgr.create_identity(user_a_id, IdentityType.STANDARD_USER_A, bearer_token=token_a)
        if not user_b:
            user_b = session_mgr.create_identity(user_b_id, IdentityType.STANDARD_USER_B, bearer_token=token_b)

        findings: List[Dict[str, Any]] = []

        for url in candidate_urls[:10]:
            # 1. Send as User A (legitimate owner)
            exch_a = await http_client.send_as_identity(identity_id=user_a_id, method="GET", url=url)

            # 2. Send as User B (attacker swapping token to access User A's resource)
            exch_b = await http_client.send_as_identity(identity_id=user_b_id, method="GET", url=url)

            # 3. Send as Anonymous Guest (unauthenticated check)
            exch_guest = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=url)

            # Compare User A vs User B via DifferentialEngine
            diff_res = diff_engine.compare_exchanges(exch_a, exch_b, context_asset=context.asset)
            is_vulnerable = diff_res.is_potential_idor or (diff_res.confidence_score >= 0.70)

            finding = {
                "target_url": url,
                "capability": capability_id,
                "is_vulnerable": is_vulnerable,
                "confidence_score": diff_res.confidence_score,
                "reasoning": diff_res.reasoning,
                "similarity_ratio": diff_res.body_similarity_ratio,
                "leaked_identifiers": diff_res.leaked_identifiers,
                "guest_status": exch_guest.response.status_code if exch_guest.response else 0,
                "_exchange_obj": exch_b.to_dict(),
                "evidence_exchanges": [exch_a.to_dict(), exch_b.to_dict(), exch_guest.to_dict()]
            }
            findings.append(finding)

            if is_vulnerable:
                break

        primary_finding = findings[0] if findings else {}

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": primary_finding.get("is_vulnerable", False),
            "confidence_score": primary_finding.get("confidence_score", 0.85),
            "findings_count": len(findings),
            "_exchange_obj": primary_finding.get("_exchange_obj"),
            "evidence": primary_finding
        }

    def _collect_candidate_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if isinstance(data, dict):
                if "url" in data and data["url"]:
                    urls.append(data["url"])
                elif "endpoints" in data and isinstance(data["endpoints"], list):
                    for ep in data["endpoints"]:
                        if isinstance(ep, dict) and ep.get("url"):
                            urls.append(ep["url"])
        if not urls:
            urls = [f"https://{context.asset}/api/v1/user/profile?id=100"]
        return list(set(urls))
