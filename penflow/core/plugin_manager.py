import importlib
import inspect
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Type

from penflow.utils.logger import get_logger

logger = get_logger("penflow.core.plugin_manager")

class BasePlugin(ABC):
    @abstractmethod
    def name(self) -> str:
        pass
        
    @abstractmethod
    def version(self) -> str:
        pass
        
    @abstractmethod
    async def run(self, context: dict) -> dict:
        pass

class BaseScanner(BasePlugin):
    @abstractmethod
    async def scan(self, target: str, endpoints: list) -> list:
        pass

class BaseDetector(BasePlugin):
    @abstractmethod
    async def detect(self, endpoint: str, http_client) -> list:
        pass

class PluginManager:
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.registry: Dict[str, Dict[str, Type[BasePlugin]]] = {
            "scanner": {},
            "detector": {},
            "general": {}
        }

    def discover_plugins(self) -> None:
        """Discover and load all plugins from the plugins directory."""
        if not self.plugins_dir.exists():
            try:
                self.plugins_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created plugins directory: {self.plugins_dir}")
            except Exception as e:
                logger.warning(f"Could not create plugins directory {self.plugins_dir}: {e}")
                return

        # Add plugins dir to path so we can import from it
        if str(self.plugins_dir.parent) not in sys.path:
            sys.path.insert(0, str(self.plugins_dir.parent))

        for file_path in self.plugins_dir.glob("**/*.py"):
            if file_path.name.startswith("__"):
                continue

            module_name = file_path.relative_to(self.plugins_dir.parent).with_suffix("").parts
            module_name = ".".join(module_name)

            try:
                module = importlib.import_module(module_name)
                self._register_classes(module)
            except Exception as e:
                logger.error(f"Failed to load plugin module {module_name}: {e}")

    def _register_classes(self, module) -> None:
        """Register all plugin classes found in a module."""
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if obj is BasePlugin or obj is BaseScanner or obj is BaseDetector:
                continue
                
            if issubclass(obj, BaseScanner):
                instance = obj()
                self.registry["scanner"][instance.name()] = obj
                logger.info(f"Registered Scanner Plugin: {instance.name()} v{instance.version()}")
                
            elif issubclass(obj, BaseDetector):
                instance = obj()
                self.registry["detector"][instance.name()] = obj
                logger.info(f"Registered Detector Plugin: {instance.name()} v{instance.version()}")
                
            elif issubclass(obj, BasePlugin):
                instance = obj()
                self.registry["general"][instance.name()] = obj
                logger.info(f"Registered General Plugin: {instance.name()} v{instance.version()}")

    def get_plugins(self, plugin_type: str) -> List[BasePlugin]:
        """Get instantiated plugins of a specific type."""
        if plugin_type not in self.registry:
            return []
            
        instances = []
        for name, cls in self.registry[plugin_type].items():
            try:
                instances.append(cls())
            except Exception as e:
                logger.error(f"Failed to instantiate plugin {name}: {e}")
                
        return instances
