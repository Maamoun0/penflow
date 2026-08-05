from typing import Dict, Any, Type, TypeVar

T = TypeVar("T")

class Container:
    """
    Lightweight, thread-safe Dependency Injection Container for PenFlow SROS.
    Decouples service instantiation from consumer classes.
    """
    def __init__(self):
        self._services: Dict[str, Any] = {}

    def register(self, service_name: str, instance: Any):
        self._services[service_name] = instance

    def resolve(self, service_name: str) -> Any:
        if service_name not in self._services:
            raise KeyError(f"[Container] Service '{service_name}' is not registered.")
        return self._services[service_name]

    def has(self, service_name: str) -> bool:
        return service_name in self._services
