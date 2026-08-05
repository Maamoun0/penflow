import pytest
import asyncio
from penflow.core.task import Task, TaskState
from penflow.core.task_queue import PriorityTaskQueue
from penflow.core.context import ExecutionContext, CancellationToken
from penflow.core.state_machine import RuntimeStateMachine, RuntimeState
from penflow.core.lifecycle import LifecycleManager
from penflow.core.event_bus import EventBus
from penflow.core.worker import Worker
from penflow.core.worker_pool import WorkerPool
from penflow.core.scheduler import Scheduler
from penflow.core.orchestrator import Orchestrator
from penflow.shared.exceptions import DomainError

@pytest.mark.asyncio
async def test_task_model_and_transitions():
    task = Task(priority=5, timeout=10.0)
    assert task.status == TaskState.CREATED
    assert task.retry_count == 0

    task.complete({"status": "ok"})
    assert task.status == TaskState.COMPLETED
    assert task.result == {"status": "ok"}

    task_retryable = Task(max_retries=1)
    assert task_retryable.retry() is True
    assert task_retryable.status == TaskState.QUEUED
    assert task_retryable.retry_count == 1

    assert task_retryable.retry() is False
    assert task_retryable.status == TaskState.FAILED

@pytest.mark.asyncio
async def test_priority_task_queue_aging():
    queue = PriorityTaskQueue()
    t_low = Task(id="low", priority=1)
    t_high = Task(id="high", priority=10)

    await queue.enqueue(t_low)
    await queue.enqueue(t_high)

    first = await queue.dequeue()
    assert first.id == "high"

    second = await queue.dequeue()
    assert second.id == "low"
    assert await queue.size() == 0

@pytest.mark.asyncio
async def test_runtime_state_machine_invalid_transitions():
    sm = RuntimeStateMachine()
    assert sm.current_state == RuntimeState.STOPPED

    sm.transition_to(RuntimeState.STARTING)
    assert sm.current_state == RuntimeState.STARTING

    with pytest.raises(DomainError):
        sm.transition_to(RuntimeState.PAUSED)

@pytest.mark.asyncio
async def test_event_bus_sync_and_async_handlers():
    bus = EventBus()
    received = []

    def sync_handler(msg):
        received.append(f"sync:{msg}")

    async def async_handler(msg):
        received.append(f"async:{msg}")

    bus.subscribe("test_topic", sync_handler, priority=1)
    bus.subscribe("test_topic", async_handler, priority=10)

    await bus.publish("test_topic", "hello")

    assert received == ["async:hello", "sync:hello"]

    bus.unsubscribe("test_topic", sync_handler)
    received.clear()
    await bus.publish("test_topic", "world")
    assert received == ["async:world"]

@pytest.mark.asyncio
async def test_worker_execution_and_cancellation():
    worker = Worker("test_w1")
    task = Task(timeout=0.1, max_retries=0)

    async def slow_work(ctx: ExecutionContext):
        await asyncio.sleep(0.5)

    await worker.run_task(task, slow_work)
    assert task.status == TaskState.FAILED
    assert "timed out" in task.error

@pytest.mark.asyncio
async def test_worker_pool_restart_and_shutdown():
    pool = WorkerPool(max_workers=2)
    assert len(pool.workers) == 2

    restarted = pool.restart_worker("pool_worker_1")
    assert restarted.worker_id == "pool_worker_1"

    await pool.shutdown()
    assert len(pool.workers) == 0

@pytest.mark.asyncio
async def test_orchestrator_runtime_and_metrics():
    orchestrator = Orchestrator(max_workers=2)
    await orchestrator.start()

    metrics_initial = await orchestrator.get_metrics()
    assert metrics_initial["runtime_state"] == "RUNNING"
    assert metrics_initial["queued_tasks"] == 0

    executed_tasks = []

    async def sample_handler(ctx: ExecutionContext):
        await asyncio.sleep(0.05)
        executed_tasks.append(ctx.task_id)
        return "success"

    orchestrator.register_task_handler("sample_type", sample_handler)

    task1 = orchestrator.create_task("sample_type", priority=5)
    await orchestrator.submit_task(task1)

    await asyncio.sleep(0.2)

    metrics_after = await orchestrator.get_metrics()
    assert metrics_after["completed_tasks"] == 1
    assert task1.id in executed_tasks

    await orchestrator.stop()
    metrics_stopped = await orchestrator.get_metrics()
    assert metrics_stopped["runtime_state"] == "STOPPED"
