"""
CuriosityDrivenExplorer — Anomaly-Triggered Autonomous Exploration Engine.

Monitors HTTP response metrics (timing deltas, content-length shifts, unique header presence)
to dynamically spawn targeted research hypotheses and follow anomalies.
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.curiosity_explorer")

class CuriosityDrivenExplorer:
    def __init__(self, baseline_latency_ms: float = 200.0, baseline_size_bytes: int = 1024):
        self.baseline_latency_ms = baseline_latency_ms
        self.baseline_size_bytes = baseline_size_bytes

    def evaluate_response_anomaly(
        self,
        endpoint: str,
        latency_ms: float,
        response_size: int,
        headers: Dict[str, str],
        status_code: int
    ) -> Optional[Dict[str, Any]]:
        anomalies = []
        
        # Check latency anomaly (e.g. > 3x baseline)
        if latency_ms > self.baseline_latency_ms * 3.0:
            anomalies.append({
                "type": "latency_spike",
                "detail": f"Response took {latency_ms:.1f}ms (baseline: {self.baseline_latency_ms}ms)",
                "hypotheses": ["Potential Time-based Blind SQLi", "External Network Call / SSRF", "Heavy Backend Computation"]
            })

        # Check response size shift (e.g. unexpected large response)
        if response_size > self.baseline_size_bytes * 5:
            anomalies.append({
                "type": "size_expansion",
                "detail": f"Response size {response_size} bytes exceeds baseline {self.baseline_size_bytes} bytes",
                "hypotheses": ["Data Exposure / Info Disclosure", "Verbose Stack Trace", "ORM Record Dumping"]
            })

        # Check unique headers
        debug_headers = [h for h in headers.keys() if any(k in h.lower() for k in ["debug", "x-runtime", "x-powered-by", "x-aspnet"])]
        if debug_headers:
            anomalies.append({
                "type": "debug_header_presence",
                "detail": f"Detected diagnostic headers: {debug_headers}",
                "hypotheses": ["Information Disclosure", "Framework Version Leaks"]
            })

        if not anomalies:
            return None

        return {
            "endpoint": endpoint,
            "status_code": status_code,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "suggested_actions": [h for a in anomalies for h in a["hypotheses"]]
        }
