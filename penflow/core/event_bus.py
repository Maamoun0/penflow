import asyncio
import inspect
import re
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Any, Awaitable, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.core.event_bus")

class _DummyAwaitable:
    def __await__(self):
        return iter([])

@dataclass
class Event:
    """Legacy/Convenience Event model wrapper around event payloads."""
    event_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    topic: str = ""

    @property
    def type(self) -> str:
        return self.event_type

@dataclass(order=True)
class EventSubscriber:
    priority: int
    handler: Callable[[Any], Any] = field(compare=False)

class EventBus:
    """
    Decoupled Event Bus supporting synchronous and asynchronous handlers,
    subscriber prioritization, topic matching, and wildcard delivery.
    """
    _instance: Optional["EventBus"] = None

    def __init__(self):
        self._subscribers: Dict[str, List[EventSubscriber]] = {}

    @classmethod
    def get_instance(cls) -> "EventBus":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _topic_to_regex(self, topic_pattern: str) -> re.Pattern:
        pattern = topic_pattern.replace(".", r"\.").replace("*", r"[^.]+").replace("#", r".*")
        return re.compile(f"^{pattern}$")

    def subscribe(self, topic: str, handler: Callable[[Any], Any], priority: int = 0) -> Any:
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        
        if not any(sub.handler == handler for sub in self._subscribers[topic]):
            sub = EventSubscriber(priority=priority, handler=handler)
            self._subscribers[topic].append(sub)
            self._subscribers[topic].sort(key=lambda s: s.priority, reverse=True)
            logger.debug(f"[EventBus] Subscribed handler to '{topic}' (priority={priority})")
        return _DummyAwaitable()

    def unsubscribe(self, topic: str, handler: Callable[[Any], Any]) -> Any:
        if topic in self._subscribers:
            self._subscribers[topic] = [s for s in self._subscribers[topic] if s.handler != handler]
        return _DummyAwaitable()

    async def publish(self, topic: str, message: Any) -> None:
        matched_subscribers: List[EventSubscriber] = []
        
        for sub_topic, subs in self._subscribers.items():
            if sub_topic == "*" or sub_topic == topic:
                matched_subscribers.extend(subs)
            else:
                regex = self._topic_to_regex(sub_topic)
                if regex.match(topic):
                    matched_subscribers.extend(subs)

        if not matched_subscribers:
            return

        matched_subscribers.sort(key=lambda s: s.priority, reverse=True)

        for sub in matched_subscribers:
            try:
                if inspect.iscoroutinefunction(sub.handler):
                    await sub.handler(message)
                else:
                    sub.handler(message)
            except Exception as e:
                logger.error(f"[EventBus] Error handling event on topic '{topic}': {str(e)}")

    async def emit(self, event_name: str, payload: Dict[str, Any]) -> None:
        evt = Event(event_type=event_name, data=payload, topic=event_name)
        await self.publish(event_name, evt)
