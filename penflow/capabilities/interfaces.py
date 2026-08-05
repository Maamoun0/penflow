from abc import ABC, abstractmethod
from typing import Dict, Any, List
from penflow.capabilities.capability import Capability

class ICapabilityProvider(ABC):
    """
    Abstract plugin interface for all future testing agents registering capabilities.
    """
    @abstractmethod
    def get_capabilities(self) -> List[Capability]:
        pass

    @abstractmethod
    async def initialize(self, context: Any) -> None:
        pass

    @abstractmethod
    def supports(self, capability_id: str) -> bool:
        pass

    @abstractmethod
    async def execute(self, capability_id: str, context: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def shutdown(self) -> None:
        pass
