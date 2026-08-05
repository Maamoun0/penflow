import importlib
import inspect
from typing import Type, List, Optional
from penflow.agents.base_agent import BaseAgent
from penflow.agents.agent_registry import AgentRegistry
from penflow.shared.exceptions import PluginError
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.agent_loader")

class AgentLoader:
    """
    Dynamic loader for discovering, validating, and hot-loading agent plugin classes.
    """
    def __init__(self, registry: AgentRegistry):
        self.registry = registry

    def load_from_module(self, module_path: str) -> List[Type[BaseAgent]]:
        try:
            module = importlib.import_module(module_path)
        except Exception as e:
            raise PluginError(f"Failed to import module '{module_path}': {str(e)}")

        loaded_classes: List[Type[BaseAgent]] = []

        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseAgent) and obj is not BaseAgent:
                if self.validate_agent_class(obj):
                    self.registry.register(obj)
                    loaded_classes.append(obj)
                else:
                    logger.warning(f"[AgentLoader] Agent class '{name}' failed interface validation")

        return loaded_classes

    def validate_agent_class(self, agent_cls: Type[BaseAgent]) -> bool:
        required_attrs = ["name", "version", "description", "capabilities", "priority", "requirements"]
        for attr in required_attrs:
            if not hasattr(agent_cls, attr):
                return False
        return True

    def hot_reload_module(self, module_path: str) -> List[Type[BaseAgent]]:
        try:
            module = importlib.import_module(module_path)
            importlib.reload(module)
            return self.load_from_module(module_path)
        except Exception as e:
            raise PluginError(f"Failed to hot-reload module '{module_path}': {str(e)}")
