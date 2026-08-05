from typing import Dict, List, Type, Optional
from penflow.agents.base_agent import BaseAgent
from penflow.shared.exceptions import ValidationError, PluginError
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.agent_registry")

class AgentRegistry:
    """
    Registry for managing agent registrations, status toggling, version tracking,
    and dependency validation.
    """
    def __init__(self):
        self._registered_classes: Dict[str, Type[BaseAgent]] = {}
        self._instances: Dict[str, BaseAgent] = {}
        self._enabled: Dict[str, bool] = {}

    def register(self, agent_cls: Type[BaseAgent]) -> None:
        name = agent_cls.name
        if not issubclass(agent_cls, BaseAgent):
            raise ValidationError(f"Class '{agent_cls}' does not inherit from BaseAgent")

        self._registered_classes[name] = agent_cls
        self._enabled[name] = True
        logger.info(f"[AgentRegistry] Registered agent class '{name}' (v{agent_cls.version})")

    def enable(self, agent_name: str) -> None:
        if agent_name in self._registered_classes:
            self._enabled[agent_name] = True

    def disable(self, agent_name: str) -> None:
        if agent_name in self._registered_classes:
            self._enabled[agent_name] = False

    def is_enabled(self, agent_name: str) -> bool:
        return self._enabled.get(agent_name, False)

    def validate_dependencies(self, agent_name: str) -> bool:
        agent_cls = self._registered_classes.get(agent_name)
        if not agent_cls:
            return False
        for req in agent_cls.requirements:
            if req not in self._registered_classes or not self.is_enabled(req):
                logger.error(f"[AgentRegistry] Dependency '{req}' missing or disabled for agent '{agent_name}'")
                return False
        return True

    def get_agent_instance(self, agent_name: str) -> Optional[BaseAgent]:
        if not self.is_enabled(agent_name):
            return None

        if agent_name not in self._instances:
            agent_cls = self._registered_classes.get(agent_name)
            if not agent_cls:
                return None
            self._instances[agent_name] = agent_cls()

        return self._instances[agent_name]

    def get_all_registered(self) -> List[str]:
        return list(self._registered_classes.keys())
