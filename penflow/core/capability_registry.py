from typing import Dict, List, Optional, Any
import time
from penflow.utils.logger import get_logger

logger = get_logger("penflow.core.capability_registry")

class CapabilityRegistry:
    """
    Capability Registry engine decoupling task definitions from concrete agent implementations.
    Matches required capabilities to registered worker agents based on lowest cost factor.
    """

    def __init__(self):
        self._registry: Dict[str, List[Dict[str, Any]]] = {}

    def register_capability(self, agent_id: str, capability: str, cost_factor: float = 1.0, version: str = "1.0.0"):
        if capability not in self._registry:
            self._registry[capability] = []
        
        # Remove existing entry for same agent_id if present
        self._registry[capability] = [item for item in self._registry[capability] if item["agent_id"] != agent_id]
        
        self._registry[capability].append({
            "agent_id": agent_id,
            "cost_factor": cost_factor,
            "version": version,
            "registered_at": time.time()
        })
        # Sort by cost_factor ascending
        self._registry[capability].sort(key=lambda x: x["cost_factor"])
        logger.debug(f"[CapabilityRegistry] Registered agent '{agent_id}' for capability '{capability}' (cost={cost_factor})")

    def find_best_agent(self, capability: str) -> Optional[str]:
        agents = self._registry.get(capability, [])
        if not agents:
            logger.warn(f"[CapabilityRegistry] No agent registered for capability '{capability}'")
            return None
        return agents[0]["agent_id"]
