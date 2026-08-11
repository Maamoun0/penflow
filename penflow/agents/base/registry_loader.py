"""
Agent Registration and Auto-Discovery Engine for PenFlow.

Provides decorator `@register_agent` and `RegistryLoader` to automatically scan
and register all specialized capability agents upon application startup without manual imports.
"""
import os
import sys
import importlib
import pkgutil
import inspect
from typing import List, Dict, Any, Type, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.registry_loader")

_REGISTERED_AGENT_CLASSES: List[Type[BaseCapabilityAgent]] = []


def register_agent(capabilities: Optional[List[str]] = None, tags: Optional[List[str]] = None):
    """
    Decorator to register a BaseCapabilityAgent class for auto-discovery.
    """
    def decorator(cls: Type[BaseCapabilityAgent]):
        if cls not in _REGISTERED_AGENT_CLASSES:
            _REGISTERED_AGENT_CLASSES.append(cls)
            logger.debug(f"[RegisterAgent] Decorator registered agent class '{cls.__name__}'")
        return cls
    return decorator


class RegistryLoader:
    """
    Scans penflow.agents package subdirectories and instantiates all registered capability agents.
    """
    _loaded = False

    @classmethod
    def discover_and_register_all(cls) -> List[Type[BaseCapabilityAgent]]:
        """
        Dynamically imports all modules under penflow.agents to trigger decorators.
        Returns list of registered agent classes.
        """
        if cls._loaded:
            return _REGISTERED_AGENT_CLASSES

        import penflow.agents as agents_pkg
        pkg_path = agents_pkg.__path__

        for _, module_name, is_pkg in pkgutil.walk_packages(pkg_path, prefix="penflow.agents."):
            try:
                mod = importlib.import_module(module_name)
                for item_name in dir(mod):
                    obj = getattr(mod, item_name)
                    if (
                        inspect.isclass(obj)
                        and issubclass(obj, BaseCapabilityAgent)
                        and obj is not BaseCapabilityAgent
                        and obj.__name__ != "BaseCapabilityAgent"
                        and obj not in _REGISTERED_AGENT_CLASSES
                    ):
                        _REGISTERED_AGENT_CLASSES.append(obj)
            except Exception as e:
                logger.debug(f"[RegistryLoader] Failed to import module '{module_name}': {e}")

        cls._loaded = True
        logger.info(f"[RegistryLoader] Auto-discovered {len(_REGISTERED_AGENT_CLASSES)} agent classes across penflow.agents")
        return _REGISTERED_AGENT_CLASSES

    @classmethod
    def instantiate_all_agents(cls, **agent_kwargs) -> List[BaseCapabilityAgent]:
        """
        Instantiates every registered agent class and returns agent instances.
        """
        classes = cls.discover_and_register_all()
        instances: List[BaseCapabilityAgent] = []

        for agent_cls in classes:
            try:
                agent = agent_cls(**agent_kwargs)
                instances.append(agent)
            except Exception as e:
                logger.error(f"[RegistryLoader] Error instantiating agent class '{agent_cls.__name__}': {e}")

        return instances
