import asyncio
from typing import Dict, Callable, Awaitable, Any, Optional, List
from penflow.core.task import Task, TaskState
from penflow.core.task_queue import PriorityTaskQueue
from penflow.core.worker_pool import WorkerPool
from penflow.core.context import ExecutionContext
from penflow.domain.models import Plan, Task as DomainTask
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.core.scheduler")

class DAGScheduler:
    """
    Topological DAG Task Scheduler resolving task dependencies before dispatching.
    """

    def get_runnable_tasks(self, plan: Plan) -> List[DomainTask]:
        completed_task_ids = {t.id for t in plan.tasks if t.status == "COMPLETED"}
        runnable = []

        for task in plan.tasks:
            if task.status in ["PENDING", "CREATED"]:
                deps_satisfied = all(dep_id in completed_task_ids for dep_id in getattr(task, "dag_dependencies", []))
                if deps_satisfied:
                    runnable.append(task)

        return runnable

class Scheduler:
    """
    Task Scheduler accepting tasks, sorting by priority with anti-starvation aging,
    and dispatching to dynamic workers in the worker pool.
    """
    def __init__(self, task_queue: PriorityTaskQueue, worker_pool: WorkerPool):
        self.queue = task_queue
        self.worker_pool = worker_pool
        self._handlers: Dict[str, Callable[[ExecutionContext], Awaitable[Any]]] = {}
        self._is_running = False
        self._dispatch_task: Optional[asyncio.Task] = None

    def register_handler(self, task_type: str, handler: Callable[[ExecutionContext], Awaitable[Any]]) -> None:
        self._handlers[task_type] = handler

    async def submit(self, task: Task) -> None:
        await self.queue.enqueue(task)

    async def start(self) -> None:
        self._is_running = True
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())
        logger.info("[Scheduler] Task Scheduler loop started.")

    async def stop(self) -> None:
        self._is_running = False
        if self._dispatch_task:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
        logger.info("[Scheduler] Task Scheduler loop stopped.")

    async def _dispatch_loop(self) -> None:
        while self._is_running:
            worker = self.worker_pool.get_idle_worker()
            if worker:
                task = await self.queue.dequeue()
                if task:
                    task_type = task.metadata.get("task_type", "default")
                    handler = self._handlers.get(task_type)
                    if handler:
                        asyncio.create_task(worker.run_task(task, handler))
                    else:
                        task.fail(f"No handler registered for task_type '{task_type}'")
                else:
                    await asyncio.sleep(0.02)
            else:
                await asyncio.sleep(0.02)
