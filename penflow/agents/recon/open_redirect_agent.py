"""
Open Redirect & OAuth Destination Tampering Specialist Capability Agent for PenFlow.
Tests URL redirect parameters and OAuth callback destinations.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.open_redirect")


class OpenRedirectCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for Open Redirect and OAuth Destination Manipulation.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="OpenRedirectCapabilityAgent", priority=priority)
        self.payload_engine = PayloadTemplateEngine()
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="open_redirect",
                name="Open Redirect & OAuth Callback Tampering",
                description="Tests parameters for arbitrary external redirects, protocol-relative bypasses, and OAuth destination hijacking",
                priority=self.priority,
                tags=["open_redirect", "oauth", "redirect", "phishing"]
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[OpenRedirectCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        dynamic_endpoints = context.get_dynamic_endpoints()

        target_url = f"https://{context.asset}/api/v1/auth/callback?redirect=https://legit.com"
        param_name = "redirect"

        if dynamic_endpoints:
            for ep in dynamic_endpoints:
                if isinstance(ep, dict):
                    ep_url = ep.get("url", "")
                    parsed = urlparse(ep_url)
                    qs = parse_qs(parsed.query)
                    for p in qs:
                        if p.lower() in {"redirect", "next", "return", "dest", "callback", "r", "goto", "out"}:
                            target_url = ep_url
                            param_name = p
                            break

        payloads = self.payload_engine.generate_open_redirect_payloads(target_url, param_name=param_name)

        is_vuln = False
        confidence = 0.0
        reasoning = ""
        tested_payloads = []
        recorded_exchanges = []
        findings = []

        for p in payloads:
            tested_payloads.append(p.to_dict())
            # Step 1: fire the request WITHOUT following redirects to capture the raw 3xx
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=p.url,
                headers=p.headers
            )
            recorded_exchanges.append(exch.to_dict())
            resp = exch.response
            if not resp:
                continue

            status = resp.status_code
            loc = resp.headers.get("Location", "") or resp.headers.get("location", "")
            body_snippet = (getattr(resp, "body_text", "") or "")[:1000]

            # ── Check 1: Direct HTTP redirect pointing to our canary domain ──────
            if status in (301, 302, 303, 307, 308) and "evil.com" in loc:
                is_vuln = True
                confidence = 0.97
                reasoning = (
                    f"CONFIRMED Open Redirect: '{param_name}' accepted external domain — "
                    f"HTTP {status} Location: {loc}"
                )
                curl_cmd = self.poc_generator.generate_curl_command(exch)
                findings.append({
                    "vulnerability_type": "open_redirect",
                    "target_url": p.url,
                    "param_name": param_name,
                    "http_status": status,
                    "location_header": loc,
                    "severity": "MEDIUM",
                    "confidence": confidence,
                    "is_vulnerable": True,
                    "redirect_type": "header",
                    "exploit_curl": curl_cmd,
                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Open Redirect", p.url, curl_cmd),
                    "description": reasoning
                })
                break

            # ── Check 2: Redirect destination appears in response body (meta-refresh / JS redirect) ──
            lower_body = body_snippet.lower()
            if any(sig in lower_body for sig in ("evil.com", "window.location", "document.location")):
                if "meta" in lower_body and "refresh" in lower_body and "evil.com" in lower_body:
                    redirect_type = "meta-refresh"
                elif "window.location" in lower_body and "evil.com" in lower_body:
                    redirect_type = "js-location"
                else:
                    redirect_type = "body-reflection"
                is_vuln = True
                confidence = 0.80
                reasoning = (
                    f"POTENTIAL Open Redirect ({redirect_type}): Parameter '{param_name}' — "
                    f"attacker domain found in response body via '{redirect_type}' pattern."
                )
                curl_cmd = self.poc_generator.generate_curl_command(exch)
                findings.append({
                    "vulnerability_type": "open_redirect",
                    "target_url": p.url,
                    "param_name": param_name,
                    "http_status": status,
                    "severity": "MEDIUM",
                    "confidence": confidence,
                    "is_vulnerable": True,
                    "redirect_type": redirect_type,
                    "exploit_curl": curl_cmd,
                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Open Redirect", p.url, curl_cmd),
                    "description": reasoning
                })
                break

        if not is_vuln:
            reasoning = f"Redirect parameter '{param_name}' properly validated against domain allowlist."

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence": confidence if is_vuln else 0.0,
            "confidence_score": confidence if is_vuln else 0.0,
            "findings": findings,
            "evidence": {
                "target_url": target_url,
                "param_name": param_name,
                "tested_payloads": tested_payloads,
                "reasoning": reasoning,
                "findings": findings,
                "evidence_exchanges": recorded_exchanges
            }
        }
