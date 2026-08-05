"""
Information Disclosure & Debug Endpoint Specialist Capability Agent for PenFlow.
Probes for exposed Spring Boot actuators, OpenAPI definitions, .env files, and sensitive configurations.
"""
from typing import List, Dict, Any, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.testing.response_analyzer import SemanticResponseAnalyzer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.info_disclosure")


class InfoDisclosureCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for Sensitive Route and Information Disclosure Discovery.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="InfoDisclosureCapabilityAgent", priority=priority)
        self.payload_engine = PayloadTemplateEngine()
        self.analyzer = SemanticResponseAnalyzer()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="info_disclosure",
                name="Exposed Debug & Actuator Route Discovery",
                description="Scans for publicly accessible Spring Actuator routes, Swagger/OpenAPI docs, .env secrets, and server metadata",
                priority=self.priority,
                tags=["info_disclosure", "actuator", "swagger", "misconfiguration"]
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[InfoDisclosureCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        origin = f"https://{context.asset}"

        probes = self.payload_engine.generate_info_disclosure_probes(origin)

        is_vuln = False
        confidence = 0.0
        reasoning = ""
        vulnerable_paths = []
        recorded_exchanges = []

        for p in probes:
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method=p.method,
                url=p.url,
                headers=p.headers
            )
            recorded_exchanges.append(exch.to_dict())
            resp = exch.response
            if resp and resp.status_code == 200:
                body = resp.body_text
                analysis = self.analyzer.analyze_response(resp.status_code, resp.headers, body)
                # Check for genuine actuator/swagger/secret indicators (avoiding generic HTML pages)
                has_actuator = any(f.get("type") == "actuator_env_leak" for f in analysis.get("findings", []))
                has_swagger = "swagger" in body.lower() or "openapi" in body.lower() or "paths" in body.lower()
                has_git = "ref: refs/heads" in body
                has_env = "DB_PASSWORD" in body or "SECRET_KEY" in body or "API_KEY" in body

                if has_actuator or has_git or has_env or (has_swagger and "{" in body):
                    is_vuln = True
                    confidence = 0.95
                    vulnerable_paths.append(p.url)
                    reasoning = f"HIGH Information Leakage: Unprotected endpoint {p.url} exposes sensitive system configuration."
                    break

        if not is_vuln:
            reasoning = f"All probed management and debug endpoints returned 404/403 or were properly protected."

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": confidence,
            "evidence": {
                "origin": origin,
                "vulnerable_paths": vulnerable_paths,
                "reasoning": reasoning,
                "evidence_exchanges": recorded_exchanges
            }
        }
