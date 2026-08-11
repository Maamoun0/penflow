from typing import List, Tuple
from penflow.capabilities.interfaces import ICapabilityProvider
from penflow.capabilities.capability import Capability
from penflow.agents.base.base_agent import BaseAgent

class CapabilitySelector:
    """
    Selects the optimal provider if multiple agents register the same capability.
    Uses agent priority, runtime, and capability metrics.
    """
    def select_best(self, providers: List[Tuple[ICapabilityProvider, str]], capability: Capability) -> Tuple[ICapabilityProvider, str]:
        def get_priority(provider_tuple: Tuple[ICapabilityProvider, str]) -> int:
            provider, name = provider_tuple
            if isinstance(provider, BaseAgent):
                return getattr(provider, "priority", 0)
            return getattr(provider, "priority", 0)

        # Sort by provider agent priority descending
        sorted_providers = sorted(providers, key=get_priority, reverse=True)
        return sorted_providers[0]
