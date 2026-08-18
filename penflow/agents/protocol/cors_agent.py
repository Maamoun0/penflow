"""
CORSCapabilityAgent — Elite Multi-Vector CORS Misconfiguration Specialist for PenFlow.

Tests all discovered API endpoints across 7 CORS bypass vectors:
  1. Dynamic Arbitrary Origin Reflection + Credentials (ACAC: true)
  2. Null Origin Reflection (`Origin: null`)
  3. Trusted Subdomain Trust Bypass (`Origin: https://sub.target.com`)
  4. Pre-domain Prefix Bypass (`Origin: https://targetcom.evil.com`)
  5. Post-domain Suffix Bypass (`Origin: https://eviltarget.com`)
  6. HTTP Protocol Downgrade (`Origin: http://target.com`)
  7. Wildcard Origin with Credentials (`ACAO: *` + `ACAC: true`)
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.agents.base.registry_loader import register_agent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.result import AgentExecutionResult
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.cors")

CORS_VECTORS = [
    {
        "id": "arbitrary_origin",
        "name": "Arbitrary External Origin",
        "origin_fn": lambda asset: "https://evil-attacker.com",
        "severity": "critical",
        "min_confidence": 0.96,
        "description": "Server reflects untrusted external origin with Access-Control-Allow-Credentials: true."
    },
    {
        "id": "null_origin",
        "name": "Null Origin (Sandboxed iframe / local file)",
        "origin_fn": lambda asset: "null",
        "severity": "high",
        "min_confidence": 0.92,
        "description": "Server allows 'null' origin — exploitable via sandboxed iframe or file:// context."
    },
    {
        "id": "subdomain_trust",
        "name": "Subdomain Trust Bypass",
        "origin_fn": lambda asset: f"https://evilsub.{asset}",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Server blindly trusts any subdomain — vulnerable if any subdomain suffers XSS or takeover."
    },
    {
        "id": "prefix_bypass",
        "name": "Pre-domain Prefix Bypass",
        "origin_fn": lambda asset: f"https://{asset}.attacker.com",
        "severity": "high",
        "min_confidence": 0.90,
        "description": "Server uses regex prefix match flaw (e.g. target.com.attacker.com)."
    },
    {
        "id": "suffix_bypass",
        "name": "Post-domain Suffix Bypass",
        "origin_fn": lambda asset: f"https://evil{asset}",
        "severity": "high",
        "min_confidence": 0.90,
        "description": "Server uses suffix match flaw (e.g. eviltarget.com)."
    },
    {
        "id": "http_downgrade",
        "name": "HTTP Protocol Downgrade",
        "origin_fn": lambda asset: f"http://{asset}",
        "severity": "medium",
        "min_confidence": 0.75,
        "description": "Server allows unencrypted HTTP origin for HTTPS target — vulnerable to MITM origin spoofing."
    },
]


@register_agent(capabilities=["cors_misconfig_check"], tags=["cors"])
class CORSCapabilityAgent(BaseCapabilityAgent):
    """
    Elite CORS Misconfiguration Specialist Capability Agent.
    Executes 7-vector CORS probing across all discovered API endpoints.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="CORSCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="cors_misconfig_check",
                name="CORS Multi-Vector Misconfiguration Analysis",
                description="Tests endpoints against 7 CORS bypass vectors: arbitrary origin, null origin, subdomain trust, prefix/suffix flaws, and HTTP downgrade",
                priority=self.priority,
                tags=["cors", "headers", "security", "api"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[CORSCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_api_urls(context)

        findings: List[Dict[str, Any]] = []

        for target_url in target_urls[:8]:
            for vec in CORS_VECTORS:
                test_origin = vec["origin_fn"](context.asset)
                result = await self._probe_cors_vector(http_client, target_url, test_origin, vec)
                if result:
                    findings.append(result)
                    if result.get("is_vulnerable") and result.get("confidence_score", 0) >= 0.90:
                        break  # Found critical vulnerability on this URL, move to next

        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=best.get("confidence_score", 0.0),
            reasoning=best.get("reasoning", "CORS policy enforced safely across all tested vectors."),
            target_url=best.get("target_url", f"https://{context.asset}"),
            findings=findings,
            evidence={
                "target_url": best.get("target_url", f"https://{context.asset}"),
                "tested_origin": best.get("tested_origin", ""),
                "response_acao": best.get("response_acao", ""),
                "response_acac": best.get("response_acac", ""),
                "tested_endpoints_count": len(target_urls),
                "reasoning": best.get("reasoning", "CORS policy enforced safely across all tested vectors."),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")],
            },
        ).to_dict()

    def _collect_api_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        for data in context.get_observation_data():
            if isinstance(data, dict):
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url"):
                        urls.append(ep["url"])
                if data.get("url"):
                    urls.append(data["url"])
        if not urls:
            urls = [
                f"https://{context.asset}/api/v1/user/profile",
                f"https://{context.asset}/api/v1/me",
                f"https://{context.asset}/api/v1/config",
            ]
        return list(set(urls))

    async def _probe_cors_vector(
        self,
        http_client: Any,
        target_url: str,
        test_origin: str,
        vector: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        from penflow.analysis.sensitive_data_exfiltrator import CORSSensitiveDataVerifier
        verifier = CORSSensitiveDataVerifier()

        try:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=target_url,
                headers={"Origin": test_origin}
            )
            resp = exch.response
            if not resp:
                return None

            headers = resp.headers if resp.headers else {}
            body_text = getattr(resp, "body_snippet", "") or getattr(resp, "body_text", "") or ""
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").lower()
            vary_origin = "origin" in headers.get("vary", "").lower()

            # Inspect response body for sensitive data & PII exfiltration proof
            inspection = verifier.inspect_response(resp.status_code, headers, body_text)

            is_vuln = False
            confidence = 0.0
            reasoning = ""

            # ── Chain Validation Logic ─────────────────────────────────────────
            # Check 1: CRITICAL — Exact origin reflection + credentials enabled
            if acao == test_origin and acac == "true":
                if inspection["has_exfiltration_impact"]:
                    is_vuln = True
                    confidence = 0.97
                    reasoning = (
                        f"CRITICAL CORS Chain Confirmed [{vector['name']}]: "
                        f"Origin '{test_origin}' reflected exactly, ACAC=true, and response body "
                        f"contains sensitive/PII data at '{target_url}'. "
                        f"Full exploit chain: attacker cross-origin fetch → read response body."
                    )
                else:
                    is_vuln = True
                    confidence = 0.72
                    reasoning = (
                        f"HIGH CORS Misconfiguration [{vector['name']}]: Origin '{test_origin}' "
                        f"reflected with ACAC=true on '{target_url}', but response body is public/static. "
                        f"Impact depends on whether authenticated endpoints share this policy."
                    )

            # Check 2: CRITICAL — Wildcard origin with credentials (browser blocks, but signals misconfiguration)
            elif acao == "*" and acac == "true":
                is_vuln = True
                confidence = 0.90
                reasoning = (
                    f"CRITICAL Config Error: ACAO=* with ACAC=true on '{target_url}'. "
                    f"Browsers block this combination, but it signals a dangerously misconfigured CORS policy."
                )

            # Check 3: HIGH — Reflection without credentials but Vary: Origin confirms dynamic reflection
            elif acao == test_origin and acac != "true" and vary_origin:
                is_vuln = True
                confidence = 0.55
                reasoning = (
                    f"MEDIUM CORS Dynamic Reflection [{vector['name']}]: "
                    f"Origin reflected without credentials, but Vary: Origin header confirms "
                    f"server dynamically sets ACAO from request. Risk escalates if ACAC enabled later."
                )

            # Check 4: LOW — Reflection without credentials, no Vary
            elif acao == test_origin and acac != "true":
                confidence = 0.35
                reasoning = (
                    f"LOW CORS Signal [{vector['name']}]: Origin '{test_origin}' reflected "
                    f"without credentials on '{target_url}'. No immediate impact."
                )

            else:
                reasoning = f"Vector '{vector['name']}' safely rejected by CORS policy on '{target_url}'."

            return {
                "vector_id": vector["id"],
                "vector_name": vector["name"],
                "target_url": target_url,
                "tested_origin": test_origin,
                "response_acao": acao,
                "response_acac": acac,
                "vary_origin": vary_origin,
                "is_vulnerable": is_vuln,
                "confidence_score": confidence,
                "reasoning": reasoning,
                "exfiltration_inspection": inspection,
                "exchange": exch.to_dict()
            }
        except Exception as e:
            logger.debug(f"[CORSAgent] Vector {vector['id']} probe failed on {target_url}: {e}")
        return None

