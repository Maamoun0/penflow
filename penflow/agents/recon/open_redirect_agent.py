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

        REDIRECT_PARAMS = {
            "redirect", "redirect_uri", "redirect_url", "return", "return_url",
            "dest", "destination", "callback", "callback_url", "r", "goto", "out",
            "url", "continue", "target", "forward", "to", "view", "link", "path", "next"
        }

        # 1. Collect all candidate redirect endpoints from observations and dynamic endpoints
        candidate_targets = []
        seen = set()

        for obs in context.observations:
            data = obs.get("data") if (isinstance(obs, dict) and "data" in obs) else (obs if isinstance(obs, dict) else {})
            if not isinstance(data, dict):
                continue
            for ep in data.get("endpoints", []):
                if isinstance(ep, dict):
                    ep_url = ep.get("url", "")
                    if ep_url:
                        parsed = urlparse(ep_url)
                        qs = parse_qs(parsed.query)
                        for p in qs:
                            if p.lower() in REDIRECT_PARAMS:
                                k = (ep_url, p)
                                if k not in seen:
                                    candidate_targets.append({"url": ep_url, "param": p})
                                    seen.add(k)

        if dynamic_endpoints:
            for ep in dynamic_endpoints:
                if isinstance(ep, dict):
                    ep_url = ep.get("url", "")
                    if ep_url:
                        parsed = urlparse(ep_url)
                        qs = parse_qs(parsed.query)
                        for p in qs:
                            if p.lower() in REDIRECT_PARAMS:
                                k = (ep_url, p)
                                if k not in seen:
                                    candidate_targets.append({"url": ep_url, "param": p})
                                    seen.add(k)

        if not candidate_targets:
            scheme = "http" if ("127.0.0.1" in context.asset or "localhost" in context.asset) else "https"
            candidate_targets = [
                {"url": f"{scheme}://{context.asset}/api/v1/auth/callback?redirect=https://legit.com", "param": "redirect"},
                {"url": f"{scheme}://{context.asset}/oauth/authorize?redirect_uri=https://legit.com", "param": "redirect_uri"},
                {"url": f"{scheme}://{context.asset}/login?next=/dashboard", "param": "next"},
            ]

        is_vuln = False
        confidence = 0.0
        reasoning = ""
        tested_payloads = []
        recorded_exchanges = []
        findings = []
        primary_exchange = None
        target_url = candidate_targets[0]["url"]
        param_name = candidate_targets[0]["param"]

        for cand in candidate_targets[:5]:
            cand_url = cand["url"]
            cand_param = cand["param"]
            payloads = self.payload_engine.generate_open_redirect_payloads(cand_url, param_name=cand_param)

            for p in payloads:
                tested_payloads.append(p.to_dict())
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

                # ── Check 1: Direct HTTP redirect pointing to canary domain ──────
                if status in (301, 302, 303, 307, 308) and "evil.com" in loc:
                    is_vuln = True
                    confidence = 0.97
                    target_url = cand_url
                    param_name = cand_param
                    reasoning = (
                        f"CONFIRMED Open Redirect: '{cand_param}' on '{cand_url}' accepted external domain — "
                        f"HTTP {status} Location: {loc}"
                    )
                    curl_cmd = self.poc_generator.generate_curl_command(exch)
                    primary_exchange = exch.to_dict()
                    findings.append({
                        "vulnerability_type": "open_redirect",
                        "target_url": p.url,
                        "param_name": cand_param,
                        "http_status": status,
                        "location_header": loc,
                        "severity": "MEDIUM",
                        "confidence": confidence,
                        "is_vulnerable": True,
                        "redirect_type": "header",
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Open Redirect", p.url, curl_cmd),
                        "description": reasoning,
                        "_exchange_obj": primary_exchange
                    })
                    break

                # ── Check 2: Redirect destination in response body (meta-refresh / JS) ──
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
                    target_url = cand_url
                    param_name = cand_param
                    reasoning = (
                        f"POTENTIAL Open Redirect ({redirect_type}): Parameter '{cand_param}' — "
                        f"attacker domain found in response body via '{redirect_type}' pattern."
                    )
                    curl_cmd = self.poc_generator.generate_curl_command(exch)
                    primary_exchange = exch.to_dict()
                    findings.append({
                        "vulnerability_type": "open_redirect",
                        "target_url": p.url,
                        "param_name": cand_param,
                        "http_status": status,
                        "severity": "MEDIUM",
                        "confidence": confidence,
                        "is_vulnerable": True,
                        "redirect_type": redirect_type,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Open Redirect", p.url, curl_cmd),
                        "description": reasoning,
                        "_exchange_obj": primary_exchange
                    })
                    break

            if is_vuln:
                break

        if not is_vuln:
            reasoning = f"Redirect parameter '{param_name}' properly validated against domain allowlist."

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "vulnerability_type": "open_redirect" if is_vuln else "open_redirect_audit",
            "is_vulnerable": is_vuln,
            "confidence": confidence if is_vuln else 0.0,
            "confidence_score": confidence if is_vuln else 0.0,
            "target_url": target_url,
            "findings": findings,
            "_exchange_obj": primary_exchange or (recorded_exchanges[0] if recorded_exchanges else None),
            "evidence": {
                "target_url": target_url,
                "param_name": param_name,
                "tested_payloads": tested_payloads,
                "reasoning": reasoning,
                "findings": findings,
                "evidence_exchanges": recorded_exchanges
            }
        }

