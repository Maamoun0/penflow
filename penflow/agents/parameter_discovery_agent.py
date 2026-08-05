"""
ParameterDiscoveryCapabilityAgent — Hidden Parameter & Header Bypass Agent Wrapper for PenFlow.
Runs ParameterDiscoveryEngine on target assets during swarm execution.
"""
from typing import List, Dict, Any
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.recon.parameter_discovery import ParameterDiscoveryEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.param_discovery")


class ParameterDiscoveryCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent wrapper for ParameterDiscoveryEngine.
    Runs hidden parameter brute-force and header override probes across target endpoints.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="ParameterDiscoveryCapabilityAgent", priority=priority)
        self.engine = ParameterDiscoveryEngine()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="parameter_discovery",
                name="Hidden Parameter & Routing Header Discovery",
                description="Brute-forces hidden query parameters (debug, admin, format, callback) and header bypasses",
                priority=self.priority,
                tags=["recon", "parameters", "bypass", "routing"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[ParameterDiscoveryCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        target_url = f"https://{context.asset}/"
        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if isinstance(data, dict) and data.get("url"):
                target_url = data["url"]
                break

        disc_res = await self.engine.discover_hidden_parameters(target_url)

        found_count = disc_res.get("discovered_count", 0)
        is_vuln = found_count > 0

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": 0.85 if is_vuln else 0.0,
            "evidence": {
                "target_url": target_url,
                "discovered_count": found_count,
                "discovered_parameters": disc_res.get("discovered_parameters", []),
                "discovered_headers": disc_res.get("discovered_headers", []),
                "reasoning": f"Discovered {found_count} hidden parameters/header bypasses on target." if is_vuln else "No hidden parameters or header overrides accepted."
            }
        }
