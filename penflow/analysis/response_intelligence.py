"""
ResponseIntelligenceEngine — Deceptive Response Detector & Differential Timing Engine for PenFlow.

Discriminates pseudo-200 responses containing soft errors and analyzes response timing variance.
"""

import time
import re
from typing import List, Dict, Any, Optional

ERROR_SIGNATURES = [
    "access denied", "unauthorized", "forbidden", "permission denied",
    "invalid token", "expired session", "not allowed", "error",
    "\"success\": false", "\"status\": \"error\"", "\"code\": 401", "\"code\": 403"
]


class DeceptiveResponseDetector:
    """Detects HTTP 200 responses that hide internal authorization/authentication failures."""

    @staticmethod
    def is_deceptive_success(status_code: int, response_body: str) -> bool:
        """Returns True if the response status is 200/201 but contains soft error text."""
        if status_code not in (200, 201, 202):
            return False
        
        body_lower = response_body.lower()
        return any(sig in body_lower for sig in ERROR_SIGNATURES)


class DifferentialTimingAnalyzer:
    """Analyzes response latency variance to infer internal routing and database logic."""

    @staticmethod
    def calculate_timing_anomaly(baseline_time: float, test_time: float, threshold_sec: float = 2.0) -> Dict[str, Any]:
        delta = abs(test_time - baseline_time)
        is_anomaly = delta >= threshold_sec
        return {
            "baseline_time_sec": round(baseline_time, 3),
            "test_time_sec": round(test_time, 3),
            "delta_sec": round(delta, 3),
            "is_anomaly": is_anomaly,
            "reasoning": f"Response timing anomaly detected: {delta:.2f}s difference (threshold: {threshold_sec}s)"
        }
