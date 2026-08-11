from dataclasses import dataclass, field
from typing import Dict, List, Any
from penflow.shared.utils import get_utc_timestamp

@dataclass
class AgentMetricRecord:
    agent_name: str
    execution_count: int = 0
    total_runtime: float = 0.0
    errors: int = 0
    successes: int = 0
    memory_usage_mb: float = 0.0
    cpu_time_s: float = 0.0

    @property
    def average_runtime(self) -> float:
        if self.execution_count == 0:
            return 0.0
        return round(self.total_runtime / self.execution_count, 4)

    @property
    def success_rate(self) -> float:
        total = self.successes + self.errors
        if total == 0:
            return 1.0
        return round(self.successes / total, 4)

class AgentMetricsTracker:
    """
    Per-agent metrics tracker collecting performance, error rates, and resource utilization.
    """
    def __init__(self):
        self._metrics: Dict[str, AgentMetricRecord] = {}

    def record_execution(self, agent_name: str, duration: float, is_success: bool, error_msg: str = "") -> None:
        if agent_name not in self._metrics:
            self._metrics[agent_name] = AgentMetricRecord(agent_name=agent_name)

        rec = self._metrics[agent_name]
        rec.execution_count += 1
        rec.total_runtime += duration
        if is_success:
            rec.successes += 1
        else:
            rec.errors += 1

    def get_metrics(self, agent_name: str) -> AgentMetricRecord:
        return self._metrics.get(agent_name, AgentMetricRecord(agent_name=agent_name))

    def get_all_metrics(self) -> Dict[str, AgentMetricRecord]:
        return dict(self._metrics)
