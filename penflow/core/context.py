import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from penflow.shared.utils import generate_uuid

@dataclass
class CancellationToken:
    """Token to signal cancellation across asynchronous worker tasks."""
    _is_cancelled: bool = False

    def cancel(self) -> None:
        self._is_cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled

@dataclass
class ExecutionContext:
    """
    Context passed into every running task execution containing tracking details,
    cancellation tokens, logger references, and execution configuration.
    """
    correlation_id: str = field(default_factory=generate_uuid)
    task_id: str = ""
    worker_id: str = ""
    cancellation_token: CancellationToken = field(default_factory=CancellationToken)
    logger: Optional[logging.Logger] = None
    config: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
