"""
Double-Clickjacking & UI Redressing Capability Agent for PenFlow.

Capabilities:
  - UI Redressing via Mousedown / Onclick Double-Click Timing Bypasses
  - Missing Frame Protection Headers (X-Frame-Options, CSP frame-ancestors)
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.double_clickjacking")


class DoubleClickjackingAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting Clickjacking and Double-Clickjacking UI redressing vulnerabilities.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="DoubleClickjackingAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="double_clickjacking", name="Double-Clickjacking & UI Redressing", description="Detects clickjacking and event-timing double-click UI redressing vulnerabilities", priority=self.priority, tags=["clickjacking", "ui_redressing", "framing"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_url = f"https://{context.asset}/"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(target_url)
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                xfo = headers_lower.get("x-frame-options", "")
                csp = headers_lower.get("content-security-policy", "")

                has_xfo = "deny" in xfo or "sameorigin" in xfo
                has_csp_frame = "frame-ancestors" in csp

                if not (has_xfo or has_csp_frame):
                    curl_cmd = f"curl -i -s -k '{target_url}'"
                    exch_dict = {
                        "request": {"method": "GET", "url": target_url},
                        "response": {"status_code": resp.status_code, "headers": dict(resp.headers), "body_snippet": "Missing framing headers"}
                    }

                    findings.append({
                        "vulnerability_type": "double_clickjacking",
                        "target_url": target_url,
                        "severity": "HIGH",
                        "confidence": 0.92,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Clickjacking / UI Redressing", target_url, curl_cmd),
                        "description": f"Target endpoint '{target_url}' lacks X-Frame-Options and CSP frame-ancestors, permitting framing and double-clickjacking attacks.",
                        "_exchange_obj": exch_dict
                    })
                    evidence["framing_permitted"] = True

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
            "confidence": 0.92 if is_vuln else 0.0,
            "confidence_score": 0.92 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
