from typing import Tuple, List
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.matcher import CapabilityMatcher
from penflow.capabilities.selector import CapabilitySelector
from penflow.capabilities.constraints import CapabilityConstraintsEngine
from penflow.capabilities.interfaces import ICapabilityProvider

class CapabilityResolver:
    """
    Resolves abstract capability requests into concrete provider agents.
    """
    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry
        self.matcher = CapabilityMatcher(registry)
        self.selector = CapabilitySelector()
        self.constraints = CapabilityConstraintsEngine(registry)

    def resolve(self, capability_ids: List[str]) -> List[Tuple[ICapabilityProvider, str, str]]:
        # Validate dependencies and conflicts
        self.constraints.validate_constraints(capability_ids)

        resolved = []
        for cap_id in capability_ids:
            providers = self.matcher.match(cap_id)
            if not providers:
                continue
            cap = self.registry.get_capability(cap_id)
            best_provider, agent_name = self.selector.select_best(providers, cap)
            if best_provider and agent_name:
                resolved.append((best_provider, agent_name, cap_id))

        return resolved
