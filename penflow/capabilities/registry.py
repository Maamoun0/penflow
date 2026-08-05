from typing import Dict, List, Set, Optional, Tuple
from penflow.capabilities.capability import Capability
from penflow.capabilities.interfaces import ICapabilityProvider
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.capabilities.registry")

class CapabilityRegistry:
    """
    Decoupled Capability Registry where agents register provided capabilities.
    """
    def __init__(self):
        self._capabilities: Dict[str, Capability] = {}  # capability_id -> Capability
        self._providers: Dict[str, List[Tuple[ICapabilityProvider, str]]] = {}  # capability_id -> List[(provider, agent_name)]

    def register_capability(self, capability: Capability, provider: ICapabilityProvider, agent_name: str) -> None:
        self._capabilities[capability.id] = capability
        if capability.id not in self._providers:
            self._providers[capability.id] = []
        self._providers[capability.id].append((provider, agent_name))
        logger.info(f"[CapabilityRegistry] Agent '{agent_name}' registered capability '{capability.id}' ({capability.name})")

    def get_capability(self, capability_id: str) -> Optional[Capability]:
        return self._capabilities.get(capability_id)

    def get_providers(self, capability_id: str) -> List[Tuple[ICapabilityProvider, str]]:
        return self._providers.get(capability_id, [])

    def get_all_capabilities(self) -> List[Capability]:
        return list(self._capabilities.values())
