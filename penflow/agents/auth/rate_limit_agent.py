"""
Rate Limit & Anti-Automation Bypass Specialist Capability Agent for PenFlow.
Tests sensitive endpoints (login, OTP, reset) for IP-spoofing header bypasses.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.rate_limit")


class RateLimitCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for Rate Limit and Anti-Automation Bypass Testing.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="RateLimitCapabilityAgent", priority=priority)
        self.payload_engine = PayloadTemplateEngine()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="rate_limit_bypass",
                name="Rate Limit & Anti-Automation Header Bypass",
                description="Tests sensitive API endpoints for IP header spoofing (X-Forwarded-For, X-Real-IP) bypasses of rate limiting",
                priority=self.priority,
                tags=["rate_limit", "anti_automation", "brute_force", "bypass"]
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[RateLimitCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        dynamic_endpoints = context.get_dynamic_endpoints()

        target_url = f"https://{context.asset}/api/v1/auth/login"

        if dynamic_endpoints:
            for ep in dynamic_endpoints:
                if isinstance(ep, dict):
                    ep_url = ep.get("url", "")
                    if "login" in ep_url or "auth" in ep_url or "otp" in ep_url or "reset" in ep_url:
                        target_url = ep_url
                        break

        is_vuln = False
        confidence = 0.0
        reasoning = ""
        exchanges = []

        # 1. Simulate burst of 5 identical requests
        statuses = []
        for i in range(5):
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="POST",
                url=target_url,
                json_data={"username": f"user_{i}", "password": "wrongpassword"}
            )
            exchanges.append(exch.to_dict())
            if exch.response:
                statuses.append(exch.response.status_code)

        # 2. Test IP header rotation bypass
        bypass_probes = self.payload_engine.generate_rate_limit_bypass_headers(target_url, ip_index=42)
        bypass_success_count = 0

        for p in bypass_probes[:4]:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method=p.method,
                url=p.url,
                headers=p.headers,
                json_data={"username": "target_user", "password": "wrongpassword"}
            )
            exchanges.append(exch.to_dict())
            if exch.response and exch.response.status_code in (200, 401):
                bypass_success_count += 1

        # Evaluate vulnerability
        # If rate limit triggers (429) on normal burst, but header rotation succeeds (200/401)
        if 429 in statuses and bypass_success_count > 0:
            is_vuln = True
            confidence = 0.90
            reasoning = f"MEDIUM: Rate limit (HTTP 429) was successfully bypassed by spoofing client IP headers (X-Forwarded-For)."
        elif 429 not in statuses and len(statuses) >= 5 and all(s in (200, 401) for s in statuses):
            # No rate limiting implemented on sensitive login route
            is_vuln = True
            confidence = 0.75
            reasoning = f"MEDIUM: Sensitive endpoint '{target_url}' permits unrestricted request bursts without anti-automation throttling."
        else:
            reasoning = f"Endpoint '{target_url}' properly throttles requests across spoofed headers."

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": confidence,
            "evidence": {
                "target_url": target_url,
                "burst_statuses": statuses,
                "reasoning": reasoning,
                "evidence_exchanges": exchanges
            }
        }
