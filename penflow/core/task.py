from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from penflow.shared.utils import generate_uuid, get_utc_timestamp

class TaskState(Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"

@dataclass
class Task:
    """
    Generic task envelope executing inside PenFlow Core Runtime.
    """
    id: str = field(default_factory=generate_uuid)
    priority: int = 0  # Higher numbers = higher priority
    status: TaskState = TaskState.CREATED
    metadata: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=get_utc_timestamp)
    updated_at: float = field(default_factory=get_utc_timestamp)
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 30.0  # seconds
    result: Optional[Any] = None
    error: Optional[str] = None

    def cancel(self) -> None:
        self.status = TaskState.CANCELLED
        self.updated_at = get_utc_timestamp()

    def complete(self, result_data: Any = None) -> None:
        self.status = TaskState.COMPLETED
        self.result = result_data
        self.updated_at = get_utc_timestamp()

    def fail(self, error_message: str) -> None:
        self.status = TaskState.FAILED
        self.error = error_message
        self.updated_at = get_utc_timestamp()

    def retry(self) -> bool:
        if self.retry_count < self.max_retries:
            self.retry_count += 1
            self.status = TaskState.QUEUED
            self.updated_at = get_utc_timestamp()
            return True
        self.fail("Max retries exceeded")
        return False
