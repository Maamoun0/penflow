import asyncio
from typing import Optional, List
from penflow.core.task import Task, TaskState
from penflow.shared.utils import get_utc_timestamp

class PriorityTaskQueue:
    """
    Thread-safe asynchronous Priority Task Queue with aging to prevent task starvation.
    """
    def __init__(self):
        self._queue: List[Task] = []
        self._lock = asyncio.Lock()

    async def enqueue(self, task: Task) -> None:
        async with self._lock:
            task.status = TaskState.QUEUED
            self._queue.append(task)

    async def dequeue(self) -> Optional[Task]:
        async with self._lock:
            if not self._queue:
                return None
            
            # Sort by effective priority: base_priority + age_seconds * 0.1
            now = get_utc_timestamp()
            self._queue.sort(
                key=lambda t: t.priority + (now - t.created_at) * 0.1,
                reverse=True
            )
            return self._queue.pop(0)

    async def size(self) -> int:
        async with self._lock:
            return len(self._queue)

    async def clear(self) -> None:
        async with self._lock:
            self._queue.clear()
