import asyncio
from typing import Dict, Any, List, Optional, Callable, Awaitable
from penflow.core.state_machine import RuntimeStateMachine, RuntimeState
from penflow.core.lifecycle import LifecycleManager
from penflow.core.task import Task, TaskState
from penflow.core.task_queue import PriorityTaskQueue
from penflow.core.worker_pool import WorkerPool
from penflow.core.scheduler import Scheduler
from penflow.core.event_bus import EventBus
from penflow.core.context import ExecutionContext
from penflow.shared.utils import get_utc_timestamp
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.core.orchestrator")

class Orchestrator:
    """
    Single central coordinator starting/stopping runtime, observing workers,
    tracking metrics, and managing scheduler without containing business logic.
    """
    def __init__(self, max_workers: int = 8):
        self.state_machine = RuntimeStateMachine()
        self.lifecycle = LifecycleManager(self.state_machine)
        self.event_bus = EventBus()
        self.task_queue = PriorityTaskQueue()
        self.worker_pool = WorkerPool(max_workers=max_workers)
        self.scheduler = Scheduler(self.task_queue, self.worker_pool)

        # Tracked tasks for metrics
        self.tracked_tasks: List[Task] = []
        self._execution_times: List[float] = []

    async def start(self) -> None:
        await self.lifecycle.start()
        await self.scheduler.start()
        logger.info("[Orchestrator] PenFlow Core Runtime successfully started.")

    async def stop(self) -> None:
        await self.scheduler.stop()
        await self.worker_pool.shutdown()
        await self.lifecycle.stop()
        logger.info("[Orchestrator] PenFlow Core Runtime successfully stopped.")

    def create_task(
        self,
        task_type: str,
        payload: Optional[Dict[str, Any]] = None,
        priority: int = 0,
        timeout: float = 30.0
    ) -> Task:
        task = Task(
            priority=priority,
            timeout=timeout,
            payload=payload or {},
            metadata={"task_type": task_type}
        )
        self.tracked_tasks.append(task)
        return task

    def register_task_handler(
        self,
        task_type: str,
        handler: Callable[[ExecutionContext], Awaitable[Any]]
    ) -> None:
        async def wrapped_handler(ctx: ExecutionContext) -> Any:
            start_time = get_utc_timestamp()
            try:
                res = await handler(ctx)
                duration = get_utc_timestamp() - start_time
                self._execution_times.append(duration)
                return res
            except Exception as e:
                duration = get_utc_timestamp() - start_time
                self._execution_times.append(duration)
                raise e

        self.scheduler.register_handler(task_type, wrapped_handler)

    async def submit_task(self, task: Task) -> None:
        await self.scheduler.submit(task)

    async def get_metrics(self) -> Dict[str, Any]:
        running_tasks = sum(1 for w in self.worker_pool.workers if w.is_running)
        queued_tasks = await self.task_queue.size()
        completed_tasks = sum(1 for t in self.tracked_tasks if t.status == TaskState.COMPLETED)
        failed_tasks = sum(1 for t in self.tracked_tasks if t.status == TaskState.FAILED)
        
        avg_exec_time = (
            sum(self._execution_times) / len(self._execution_times)
            if self._execution_times else 0.0
        )
        worker_utilization = (
            running_tasks / self.worker_pool.max_workers
            if self.worker_pool.max_workers > 0 else 0.0
        )

        return {
            "runtime_state": self.state_machine.current_state.value,
            "running_tasks": running_tasks,
            "queued_tasks": queued_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "average_execution_time": round(avg_exec_time, 4),
            "worker_utilization": round(worker_utilization, 2)
        }
