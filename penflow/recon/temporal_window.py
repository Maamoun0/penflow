"""
TemporalAttackWindowDetector — Transient Deployment & Cache Drift Monitor.

Monitors sensitive target endpoints across time intervals to catch transient deployment windows,
blue-green rollout state discrepancies, and temporary debug mode activations.
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.temporal_window")

class TemporalAttackWindowDetector:
    def __init__(self):
        self.endpoint_snapshots: Dict[str, List[Dict[str, Any]]] = {}

    def record_snapshot(
        self,
        endpoint: str,
        status_code: int,
        content_length: int,
        server_header: str = "",
        timestamp: float = 0.0
    ) -> Optional[Dict[str, Any]]:
        if endpoint not in self.endpoint_snapshots:
            self.endpoint_snapshots[endpoint] = []

        snapshot = {
            "status_code": status_code,
            "content_length": content_length,
            "server_header": server_header,
            "timestamp": timestamp
        }

        previous = list(self.endpoint_snapshots[endpoint])
        self.endpoint_snapshots[endpoint].append(snapshot)

        # Compare with previous snapshot if available
        if previous:
            last = previous[-1]
            if last["status_code"] != status_code:
                return {
                    "endpoint": endpoint,
                    "event": "status_code_drift",
                    "previous_status": last["status_code"],
                    "current_status": status_code,
                    "detail": f"Status code shifted from {last['status_code']} to {status_code} (Possible deployment/canary rollout)"
                }
            if abs(last["content_length"] - content_length) > 500:
                return {
                    "endpoint": endpoint,
                    "event": "content_length_delta",
                    "previous_length": last["content_length"],
                    "current_length": content_length,
                    "detail": f"Significant content length change: {last['content_length']} -> {content_length} bytes"
                }

        return None
