from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from penflow.agents.agent_context import AgentContext
from penflow.agents.agent_health import AgentHealthStatus, AgentHealthState

class BaseAgent(ABC):
    """
    Abstract Base Class for all PenFlow Research Agents.
    Every agent is a plugin implementing this strict interface.
    """
    name: str = "BaseAgent"
    version: str = "1.0.0"
    description: str = "Abstract Base Agent Interface"
    capabilities: List[str] = []
    priority: int = 0
    requirements: List[str] = []

    def __init__(self, **kwargs):
        self._is_initialized: bool = False
        self._is_paused: bool = False
        self._is_stopped: bool = False

    @abstractmethod
    async def initialize(self, context: AgentContext) -> None:
        """Initialize resources and dependencies for agent."""
        self._is_initialized = True

    @abstractmethod
    async def execute(self, context: AgentContext, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Core execution logic of the agent."""
        pass

    async def pause(self) -> None:
        self._is_paused = True

    async def resume(self) -> None:
        self._is_paused = False

    async def stop(self) -> None:
        self._is_stopped = True

    async def cleanup(self) -> None:
        self._is_initialized = False

    async def health_check(self) -> AgentHealthStatus:
        if not self._is_initialized:
            return AgentHealthStatus(agent_name=self.name, state=AgentHealthState.STOPPED, details="Not initialized")
        if self._is_paused:
            return AgentHealthStatus(agent_name=self.name, state=AgentHealthState.PAUSED, details="Agent paused")
        if self._is_stopped:
            return AgentHealthStatus(agent_name=self.name, state=AgentHealthState.STOPPED, details="Agent stopped")
        return AgentHealthStatus(agent_name=self.name, state=AgentHealthState.HEALTHY, details="Healthy")

class BaseSwarmAgent(BaseAgent):
    """
    Backward compatibility base class supporting flexible positional/keyword arguments.
    """
    def __init__(self, event_bus=None, *args, **kwargs):
        super().__init__(**kwargs)
        self.event_bus = event_bus

    async def publish_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        if self.event_bus:
            await self.event_bus.emit(event_name, payload)

    async def initialize(self, context: Optional[AgentContext] = None) -> None:
        self._is_initialized = True

    async def execute(self, context: Optional[AgentContext] = None, input_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"status": "executed"}
