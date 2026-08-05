import asyncio
from typing import List, Optional
from penflow.core.worker import Worker
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.core.worker_pool")

class WorkerPool:
    """
    Dynamic Worker Pool managing worker lifecycle, restart of failed workers,
    and graceful shutdown.
    """
    def __init__(self, max_workers: int = 8):
        self.max_workers = max_workers
        self.workers: List[Worker] = []
        self._init_pool()

    def _init_pool(self) -> None:
        self.workers = [Worker(f"pool_worker_{i+1}") for i in range(self.max_workers)]

    def get_idle_worker(self) -> Optional[Worker]:
        for worker in self.workers:
            if not worker.is_running:
                return worker
        return None

    def restart_worker(self, worker_id: str) -> Worker:
        logger.info(f"[WorkerPool] Restarting worker '{worker_id}'")
        for i, w in enumerate(self.workers):
            if w.worker_id == worker_id:
                w.cancel()
                new_worker = Worker(worker_id)
                self.workers[i] = new_worker
                return new_worker
        new_worker = Worker(worker_id)
        self.workers.append(new_worker)
        return new_worker

    async def shutdown(self) -> None:
        logger.info("[WorkerPool] Gracefully shutting down worker pool...")
        for worker in self.workers:
            if worker.is_running:
                worker.cancel()
        self.workers.clear()
