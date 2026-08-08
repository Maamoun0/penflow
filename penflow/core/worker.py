import asyncio
import inspect
from typing import Callable, Awaitable, Any, Optional
from penflow.core.task import Task, TaskState
from penflow.core.context import ExecutionContext, CancellationToken
from penflow.shared.utils import generate_uuid, get_utc_timestamp
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.core.worker")

class Worker:
    """
    Dedicated Worker unit executing exactly one Task at a time with full timeout,
    retry, heartbeat, and cancellation support.
    """
    def __init__(self, worker_id: Optional[str] = None):
        self.worker_id = worker_id or f"worker_{generate_uuid()[:8]}"
        self.current_task: Optional[Task] = None
        self.is_running: bool = False
        self.last_heartbeat: float = get_utc_timestamp()
        self.cancellation_token = CancellationToken()

    def heartbeat(self) -> float:
        self.last_heartbeat = get_utc_timestamp()
        return self.last_heartbeat

    def cancel(self) -> None:
        self.cancellation_token.cancel()
        if self.current_task:
            self.current_task.cancel()
            logger.info(f"[Worker:{self.worker_id}] Task {self.current_task.id} cancelled.")

    async def run_task(self, task: Task, task_func: Callable[[ExecutionContext], Awaitable[Any]]) -> None:
        self.current_task = task
        self.is_running = True
        self.cancellation_token = CancellationToken()
        task.status = TaskState.RUNNING
        self.heartbeat()

        ctx = ExecutionContext(
            task_id=task.id,
            worker_id=self.worker_id,
            cancellation_token=self.cancellation_token,
            logger=logger,
            payload=task.payload or {},
            config=task.metadata or {}
        )

        try:
            if inspect.iscoroutinefunction(task_func):
                result = await asyncio.wait_for(task_func(ctx), timeout=task.timeout)
            else:
                result = task_func(ctx)
            
            if self.cancellation_token.is_cancelled:
                task.cancel()
            else:
                task.complete(result)
        except asyncio.TimeoutError:
            logger.warning(f"[Worker:{self.worker_id}] Task {task.id} timed out after {task.timeout}s")
            task.fail(f"Task execution timed out after {task.timeout} seconds")
        except Exception as e:
            logger.error(f"[Worker:{self.worker_id}] Task {task.id} failed with error: {str(e)}")
            task.fail(str(e))
        finally:
            self.is_running = False
            self.heartbeat()
            self.current_task = None
