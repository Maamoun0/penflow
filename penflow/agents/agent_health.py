from enum import Enum
from dataclasses import dataclass, field
from penflow.shared.utils import get_utc_timestamp

class AgentHealthState(Enum):
    HEALTHY = "HEALTHY"
    BUSY = "BUSY"
    WAITING = "WAITING"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"

@dataclass
class AgentHealthStatus:
    agent_name: str
    state: AgentHealthState = AgentHealthState.HEALTHY
    details: str = "Operating normally"
    last_check: float = field(default_factory=get_utc_timestamp)
