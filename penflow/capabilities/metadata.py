from typing import Dict, Any, List
from penflow.capabilities.capability import Capability
from penflow.shared.utils import get_utc_timestamp

class CapabilityMetadataTracker:
    """
    Tracks metadata and historical performance stats for registered capabilities.
    """
    def __init__(self):
        self._stats: Dict[str, Dict[str, Any]] = {}

    def record_capability_use(self, capability_id: str, success: bool, runtime: float) -> None:
        if capability_id not in self._stats:
            self._stats[capability_id] = {"uses": 0, "successes": 0, "total_runtime": 0.0}

        st = self._stats[capability_id]
        st["uses"] += 1
        if success:
            st["successes"] += 1
        st["total_runtime"] += runtime

    def get_stats(self, capability_id: str) -> Dict[str, Any]:
        return self._stats.get(capability_id, {"uses": 0, "successes": 0, "total_runtime": 0.0})
