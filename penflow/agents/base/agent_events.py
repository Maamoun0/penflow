import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Any, Awaitable, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.agent_events")

@dataclass
class AgentEvent:
    id: str = field(default_factory=generate_uuid)
    sender_agent: str = ""
    topic: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    reply_to: Optional[str] = None
    timestamp: float = field(default_factory=get_utc_timestamp)

class AgentEventBus:
    """
    Decoupled Event Bus enforcing that Agents communicate exclusively via Events.
    Supports publish, subscribe, broadcast, and asynchronous request-response.
    """
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[AgentEvent], Awaitable[None]]]] = {}
        self._pending_responses: Dict[str, asyncio.Future] = {}

    def subscribe(self, topic: str, handler: Callable[[AgentEvent], Awaitable[None]]) -> None:
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        if handler not in self._subscribers[topic]:
            self._subscribers[topic].append(handler)

    async def publish(self, topic: str, sender_agent: str, payload: Dict[str, Any], reply_to: Optional[str] = None) -> AgentEvent:
        event = AgentEvent(sender_agent=sender_agent, topic=topic, payload=payload, reply_to=reply_to)
        
        # Deliver to matched subscribers
        handlers = []
        for sub_topic, sub_handlers in self._subscribers.items():
            if sub_topic == "*" or sub_topic == topic:
                handlers.extend(sub_handlers)

        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"[AgentEventBus] Exception handling agent event '{topic}': {str(e)}")

        # Handle request-response reply if reply_to is matched
        if reply_to and reply_to in self._pending_responses:
            fut = self._pending_responses.pop(reply_to)
            if not fut.done():
                fut.set_result(payload)

        return event

    async def broadcast(self, sender_agent: str, payload: Dict[str, Any]) -> AgentEvent:
        return await self.publish("*", sender_agent, payload)

    async def request_response(self, topic: str, sender_agent: str, payload: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        correlation_id = generate_uuid()
        fut = asyncio.get_running_loop().create_future()
        self._pending_responses[correlation_id] = fut

        await self.publish(topic, sender_agent, payload, reply_to=correlation_id)

        try:
            result = await asyncio.wait_for(fut, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            self._pending_responses.pop(correlation_id, None)
            raise TimeoutError(f"Agent request-response timed out after {timeout}s on topic '{topic}'")
