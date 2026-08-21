"""
State Manager - Centralized Exploit State Store
Acts as the shared memory for all agents during a live scan.
"""
import asyncio
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import time

from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.state_manager")

@dataclass
class StateFact:
    """Represents a discovered fact in the environment."""
    key: str
    value: Any
    source_agent: str
    asset: str
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)

class ExploitStateStore:
    """
    In-memory Key-Value store for sharing exploit state between agents dynamically.
    Future: Can be backed by Redis for distributed deployments.
    """
    def __init__(self):
        self._store: Dict[str, List[StateFact]] = {}
        self._lock = asyncio.Lock()
        self._subscribers: List[Any] = []

    async def add_fact(self, key: str, value: Any, source_agent: str, asset: str, confidence: float = 1.0) -> None:
        """Adds a fact to the state store and notifies subscribers."""
        fact = StateFact(key=key, value=value, source_agent=source_agent, asset=asset, confidence=confidence)
        
        async with self._lock:
            if key not in self._store:
                self._store[key] = []
            self._store[key].append(fact)
            logger.debug(f"[StateStore] New Fact Added: {key} = {value} (by {source_agent})")
            
        # Notify subscribers
        for sub in self._subscribers:
            asyncio.create_task(sub.on_fact_added(fact))

    async def get_facts(self, key: str) -> List[StateFact]:
        """Retrieves all facts for a given key."""
        async with self._lock:
            return self._store.get(key, []).copy()

    async def get_latest_fact(self, key: str) -> Optional[StateFact]:
        """Retrieves the most recent fact for a given key."""
        facts = await self.get_facts(key)
        if not facts:
            return None
        return sorted(facts, key=lambda x: x.timestamp)[-1]

    def subscribe(self, subscriber: Any) -> None:
        """Subscribe to state changes. Subscriber must implement `on_fact_added(fact)`."""
        if subscriber not in self._subscribers:
            self._subscribers.append(subscriber)

    def unsubscribe(self, subscriber: Any) -> None:
        """Unsubscribe from state changes."""
        if subscriber in self._subscribers:
            self._subscribers.remove(subscriber)
