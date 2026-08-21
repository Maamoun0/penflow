"""
IDORCapabilityAgent — Multi-Identity BOLA (Broken Object Level Authorization) Specialist for PenFlow.

Executes 3-Identity Cross-Account Authorization Matrix testing across targeted candidate endpoints:
  - User A (Resource Owner) vs User B (Cross-Tenant Attacker) vs Anonymous Guest
  - Swaps tokens, authorization headers (Bearer, Cookie, X-API-Key), and URL object IDs
  - Scrutinizes body similarity ratio, leaked identifiers, and JSON key structures
  - Enforces strict grounding: Public endpoints and static catalogs are NEVER flagged as IDOR.
"""
from typing import List, Dict, Any, Optional
import urllib.parse
import re
import asyncio
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.result import AgentExecutionResult
from penflow.traffic.models import IdentityType, TrafficRequest, TrafficExchange
from penflow.traffic.diff_engine import DifferentialEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.idor")

ID_PARAM_REGEX = re.compile(
    r'[?&](?:id|userId|user_id|account|accountId|account_id|order|orderId|order_id|doc|docId|profile_id|uuid|num)=\d+',
    re.IGNORECASE
)


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

        candidate_urls: List[str] = self._collect_candidate_urls(context, capability_id)

        if not candidate_urls:
            logger.info(f"[IDORCapabilityAgent] No qualified object/tenant endpoints discovered on '{context.asset}' for capability '{capability_id}'. Skipping.")
            return AgentExecutionResult(
                agent=self.name,
                capability=capability_id,
                asset=context.asset,
                status="COMPLETED",
                is_vulnerable=False,
                confidence_score=0.0,
                reasoning="No parameter-driven or tenant-isolated object endpoints identified for BOLA/IDOR testing.",
                target_url=f"https://{context.asset}",
                findings=[],
                evidence={},
                metadata={"findings_count": 0}
            ).to_dict()

        # Retrieve or configure 3-identity matrix (User A, User B, Anonymous Guest)
        user_a = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_A)
        user_b = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_B)

        user_a_id = user_a.id if user_a else "user_a"
        user_b_id = user_b.id if user_b else "user_b"

        # Attempt to load real identity tokens from AuthConfigManager / Config
        try:
            from penflow.traffic.auth_manager import AuthConfigManager
            auth_mgr = AuthConfigManager()
            token_a = auth_mgr.get_token_for_identity("user_a") or ""
            token_b = auth_mgr.get_token_for_identity("user_b") or ""
        except Exception:
            token_a = ""
            token_b = ""

        if not user_a:
            user_a = session_mgr.create_identity(user_a_id, IdentityType.STANDARD_USER_A, bearer_token=token_a)
        if not user_b:
            user_b = session_mgr.create_identity(user_b_id, IdentityType.STANDARD_USER_B, bearer_token=token_b)

        findings: List[Dict[str, Any]] = []

        for url in candidate_urls[:5]:
            # 1. Send as User A (legitimate owner)
            exch_a = await http_client.send_as_identity(identity_id=user_a_id, method="GET", url=url)

            # 2. Send as User B (attacker swapping token to access User A's resource)
            exch_b = await http_client.send_as_identity(identity_id=user_b_id, method="GET", url=url)

            # 3. Send as Anonymous Guest (unauthenticated check)
            exch_guest = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=url)

            # Compare User A vs User B via DifferentialEngine
            diff_res = diff_engine.compare_exchanges(exch_a, exch_b, context_asset=context.asset)
            
            # Grounding check: If guest gets 200 OK with identical body as user_a, it's public content!
            guest_is_200 = exch_guest.response and exch_guest.response.status_code == 200
            guest_body = exch_guest.response.body_text if exch_guest.response else ""
            user_a_body = exch_a.response.body_text if exch_a.response else ""
            
            is_public_content = guest_is_200 and guest_body and user_a_body and (guest_body == user_a_body)
            
            if is_public_content:
                logger.debug(f"[IDORCapabilityAgent] Endpoint '{url}' returned identical content to unauthenticated guest. Falsifying IDOR claim.")
                is_vulnerable = False
            else:
                is_vulnerable = diff_res.is_potential_idor and (diff_res.confidence_score >= 0.85)

            if is_vulnerable and diff_res.leaked_identifiers and context.state_store:
                for leaked_id in diff_res.leaked_identifiers:
                    # Heuristically guess if it's an email
                    if "@" in leaked_id and "." in leaked_id:
                        asyncio.create_task(context.state_store.add_fact(
                            key="leaked_user_email",
                            value=leaked_id,
                            source_agent=self.name,
                            asset=context.asset,
                            confidence=diff_res.confidence_score
                        ))
                    else:
                        asyncio.create_task(context.state_store.add_fact(
                            key="leaked_user_id",
                            value=leaked_id,
                            source_agent=self.name,
                            asset=context.asset,
                            confidence=diff_res.confidence_score
                        ))

            finding = {
                "target_url": url,
                "capability": capability_id,
                "is_vulnerable": is_vulnerable,
                "confidence_score": diff_res.confidence_score if is_vulnerable else 0.0,
                "reasoning": diff_res.reasoning if is_vulnerable else "No authorization boundary breach observed.",
                "similarity_ratio": diff_res.body_similarity_ratio,
                "leaked_identifiers": diff_res.leaked_identifiers,
                "guest_status": exch_guest.response.status_code if exch_guest.response else 0,
                "_exchange_obj": exch_b.to_dict(),
                "evidence_exchanges": [exch_a.to_dict(), exch_b.to_dict(), exch_guest.to_dict()]
            }
            findings.append(finding)

            if is_vulnerable:
                break

        vulnerable_findings = [f for f in findings if f.get("is_vulnerable")]
        primary_finding = vulnerable_findings[0] if vulnerable_findings else (findings[0] if findings else {})

        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=primary_finding.get("is_vulnerable", False),
            confidence_score=primary_finding.get("confidence_score", 0.0),
            reasoning=primary_finding.get("reasoning", "No BOLA/IDOR vulnerability detected."),
            target_url=primary_finding.get("target_url", f"https://{context.asset}"),
            findings=findings,
            evidence=primary_finding,
            metadata={
                "findings_count": len(findings),
                "_exchange_obj": primary_finding.get("_exchange_obj"),
            },
        ).to_dict()

    def _collect_candidate_urls(self, context: CapabilityExecutionContext, capability_id: str) -> List[str]:
        raw_urls = []
        for data in context.get_observation_data():
            if isinstance(data, dict):
                if "url" in data and data["url"]:
                    raw_urls.append(data["url"])
                elif "endpoints" in data and isinstance(data["endpoints"], list):
                    for ep in data["endpoints"]:
                        if isinstance(ep, dict) and ep.get("url"):
                            raw_urls.append(ep["url"])
                elif "assets" in data and isinstance(data["assets"], list):
                    for a in data["assets"]:
                        if isinstance(a, dict) and a.get("asset_type") == "endpoint":
                            raw_urls.append(a.get("canonical_name", ""))

        filtered_urls = []
        id_param_patterns = [
            r'[?&](?:id|userId|user_id|account|accountId|account_id|order|orderId|order_id|doc|docId|profile_id|uuid|num)=\d+',
            r'/(?:api|v\d)/(?:user|account|order|invoice|profile|billing|wallet|tenant|customer)s?/\d+',
            r'/(?:user|account|order|invoice|profile|billing|wallet|tenant|customer)s?/\d+',
            r'/(?:api|v\d)/(?:user|account|order|invoice|profile|me|billing|wallet|tenant)(?:/|$)',
        ]

        for u in raw_urls:
            u_clean = u.strip()
            if not u_clean:
                continue
            parsed = urllib.parse.urlparse(u_clean)
            path = parsed.path.rstrip("/")
            
            # Skip bare root homepage
            if path in ("", "/"):
                continue
            
            # Skip public catalog / static endpoints
            if any(p in path.lower() for p in ["/product", "/item", "/catalog", "/category", "/image", "/resources", "/static", "/css", "/js", "/labheader"]):
                continue

            if any(re.search(pat, u_clean, re.IGNORECASE) for pat in id_param_patterns):
                filtered_urls.append(u_clean)

        return list(set(filtered_urls))
