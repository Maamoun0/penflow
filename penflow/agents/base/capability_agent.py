from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from penflow.agents.base.base_agent import BaseAgent
from penflow.capabilities.interfaces import ICapabilityProvider
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import ExecutionContext

class BaseCapabilityAgent(BaseAgent, ICapabilityProvider):
    """
    Bridge class connecting PenFlow BaseAgent plugin lifecycle with the Capability Framework.
    Every specialized vulnerability research agent inherits from this class.
    """
    def __init__(self, agent_name: str, priority: int = 10, **kwargs):
        super().__init__(**kwargs)
        self.name = agent_name
        self.priority = priority

    @abstractmethod
    def get_capabilities(self) -> List[Capability]:
        pass

    async def initialize(self, context: Any) -> None:
        self._is_initialized = True

    def supports(self, capability_id: str) -> bool:
        return any(c.id == capability_id for c in self.get_capabilities())

    @abstractmethod
    async def execute(self, capability_id: str, context: ExecutionContext) -> Dict[str, Any]:
        pass

    async def shutdown(self) -> None:
        self._is_initialized = False
