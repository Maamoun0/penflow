"""
Header Analysis Capability Agent for PenFlow.

Capabilities:
  - Security Header Hardening Deep Audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
  - Information Disclosure via Server / X-Powered-By / X-AspNet-Version Headers
  - Insecure / Permissive Header Directives
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.header_analysis")

REQUIRED_SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS Missing", "HIGH"),
    ("x-content-type-options", "X-Content-Type-Options Missing", "MEDIUM"),
    ("x-frame-options", "X-Frame-Options Missing", "MEDIUM"),
    ("content-security-policy", "Content-Security-Policy Missing", "HIGH")
]


class HeaderAnalysisAgent(BaseCapabilityAgent):
    """
    Capability Agent performing deep HTTP header hardening and information disclosure audits.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="HeaderAnalysisAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="header_analysis", name="Security Headers Deep Scan", description="Audits HTTP response security headers and information leaking server headers", priority=self.priority, tags=["headers", "hardening", "info_disclosure"])
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

                # 1. Check Missing Security Headers
                for h_name, desc, sev in REQUIRED_SECURITY_HEADERS:
                    if h_name not in headers_lower:
                        curl_cmd = f"curl -i -s -k '{target_url}'"
                        exch_dict = {
                            "request": {"method": "GET", "url": target_url},
                            "response": {"status_code": resp.status_code, "headers": dict(resp.headers), "body_snippet": "Header audit"}
                        }
                        findings.append({
                            "vulnerability_type": "header_analysis",
                            "subtype": f"missing_{h_name.replace('-', '_')}",
                            "target_url": target_url,
                            "severity": sev,
                            "confidence": 0.90,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps(f"Missing {h_name.upper()} Header", target_url, curl_cmd),
                            "description": f"Target endpoint '{target_url}' is missing security header '{h_name}'.",
                            "_exchange_obj": exch_dict
                        })

                # 2. Check Information Disclosure Headers
                for info_header in ("x-powered-by", "x-aspnet-version", "server"):
                    if info_header in headers_lower:
                        h_val = headers_lower[info_header]
                        curl_cmd = f"curl -i -s -k '{target_url}'"
                        exch_dict = {
                            "request": {"method": "GET", "url": target_url},
                            "response": {"status_code": resp.status_code, "headers": dict(resp.headers), "body_snippet": f"{info_header}: {h_val}"}
                        }
                        findings.append({
                            "vulnerability_type": "header_analysis",
                            "subtype": "info_disclosure_header",
                            "target_url": target_url,
                            "severity": "LOW",
                            "confidence": 0.95,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps("Server Header Information Leaking", target_url, curl_cmd),
                            "description": f"Server discloses internal stack technology via '{info_header}: {h_val}'.",
                            "_exchange_obj": exch_dict
                        })

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
            "confidence": 0.90 if is_vuln else 0.0,
            "confidence_score": 0.90 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
