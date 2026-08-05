from typing import List, Tuple, Optional
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.capability import Capability
from penflow.capabilities.interfaces import ICapabilityProvider
from penflow.capabilities.exceptions import CapabilityNotFoundError

class CapabilityMatcher:
    """
    Matches abstract capability string requests (e.g. "idor", "graphql", "jwt") to registered providers.
    """
    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry

    def match(self, capability_id: str) -> List[Tuple[ICapabilityProvider, str]]:
        providers = self.registry.get_providers(capability_id)
        if not providers:
            raise CapabilityNotFoundError(f"No provider found for requested capability '{capability_id}'")
        return providers
