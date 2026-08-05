"""
Security Posture & Configuration Capability Agent for PenFlow.
Audits security headers, HSTS, and Content-Security-Policy (CSP) configurations.
"""
from typing import List, Dict, Any
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.recon.security_headers_audit import SecurityHeadersAuditor
from penflow.validation.csp_analyzer import CSPPolicyAnalyzer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.security_config")

class SecurityConfigCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for Security Posture and Configuration Auditing.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="SecurityConfigCapabilityAgent", priority=priority)
        self.auditor = SecurityHeadersAuditor()
        self.csp_analyzer = CSPPolicyAnalyzer()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="security_config_audit",
                name="Security Posture & Headers Audit",
                description="Audits HTTP security headers, HSTS, clickjacking, and CSP directives",
                priority=self.priority,
                tags=["security_headers", "csp", "hsts", "hardening"]
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[SecurityConfigCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        target_url = f"https://{context.asset}"
        audit_res = await self.auditor.audit_url(target_url)
        headers = audit_res.get("headers", {})
        csp_header = headers.get("content-security-policy", "")
        csp_res = self.csp_analyzer.analyze_csp(csp_header)

        all_findings = audit_res.get("findings", []) + csp_res.get("findings", [])

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "target": context.asset,
            "evidence": {
                "headers": headers,
                "findings": all_findings,
                "evidence_exchanges": [{
                    "request": {"method": "GET", "url": target_url, "headers": {}},
                    "response": {"status_code": 200, "headers": headers, "body_text": ""}
                }]
            },
            "is_vulnerable": len(all_findings) > 0,
            "confidence": 0.90 if len(all_findings) > 0 else 0.0,
            "reasoning": f"Identified {len(all_findings)} security configuration observations for {context.asset}."
        }
