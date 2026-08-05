"""
Distributed Swarm Architecture for PenFlow.

Provides an asynchronous task broker and worker node framework enabling distributed scanning
across multiple parallel worker nodes.
Manages node registrations, task queues, heartbeat monitoring, and result aggregation.
"""
import time
import asyncio
from typing import Dict, List, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.infrastructure.distributed_swarm")


class SwarmTaskBroker:
    """
    Central Task Broker managing distributed worker nodes and task assignments.
    """
    def __init__(self):
        self.workers: Dict[str, Dict[str, Any]] = {}
        self.task_queue: List[Dict[str, Any]] = []
        self.completed_results: List[Dict[str, Any]] = []

    def register_worker(self, worker_id: str, capabilities: List[str]) -> bool:
        self.workers[worker_id] = {
            "worker_id": worker_id,
            "capabilities": capabilities,
            "status": "IDLE",
            "last_heartbeat": time.time(),
            "tasks_processed": 0
        }
        logger.info(f"[SwarmBroker] Worker registered: '{worker_id}' with {len(capabilities)} capabilities.")
        return True

    def submit_task(self, task_id: str, capability_id: str, target_asset: str, payload_data: Dict[str, Any]) -> str:
        task = {
            "task_id": task_id,
            "capability_id": capability_id,
            "target_asset": target_asset,
            "payload_data": payload_data,
            "status": "PENDING",
            "assigned_worker": None,
            "submitted_at": time.time()
        }
        self.task_queue.append(task)
        logger.info(f"[SwarmBroker] Task queued: '{task_id}' for capability '{capability_id}' on '{target_asset}'.")
        return task_id

    def dispatch_next_task(self, worker_id: str) -> Optional[Dict[str, Any]]:
        if worker_id not in self.workers:
            return None

        w_info = self.workers[worker_id]
        w_info["last_heartbeat"] = time.time()

        for idx, task in enumerate(self.task_queue):
            if task["status"] == "PENDING" and task["capability_id"] in w_info["capabilities"]:
                task["status"] = "ASSIGNED"
                task["assigned_worker"] = worker_id
                w_info["status"] = "BUSY"
                logger.info(f"[SwarmBroker] Dispatched task '{task['task_id']}' to worker '{worker_id}'.")
                return task

        return None

    def record_task_result(self, worker_id: str, task_id: str, result: Dict[str, Any]) -> bool:
        if worker_id in self.workers:
            self.workers[worker_id]["status"] = "IDLE"
            self.workers[worker_id]["tasks_processed"] += 1
            self.workers[worker_id]["last_heartbeat"] = time.time()

        result_entry = {
            "task_id": task_id,
            "worker_id": worker_id,
            "completed_at": time.time(),
            "result": result
        }
        self.completed_results.append(result_entry)
        logger.info(f"[SwarmBroker] Received task result for '{task_id}' from worker '{worker_id}'.")
        return True


class SwarmWorkerNode:
    """
    Autonomous Distributed Worker Node executing tasks assigned by SwarmTaskBroker.
    """
    def __init__(self, worker_id: str, capabilities: List[str], broker: SwarmTaskBroker):
        self.worker_id = worker_id
        self.capabilities = capabilities
        self.broker = broker
        self.broker.register_worker(self.worker_id, self.capabilities)

    async def poll_and_execute(self) -> Optional[Dict[str, Any]]:
        task = self.broker.dispatch_next_task(self.worker_id)
        if not task:
            return None

        # Simulate execution
        await asyncio.sleep(0.01)
        res = {
            "status": "SUCCESS",
            "task_id": task["task_id"],
            "asset": task["target_asset"],
            "finding_verified": True
        }
        self.broker.record_task_result(self.worker_id, task["task_id"], res)
        return res
