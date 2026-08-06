"""
Passive Traffic Anomaly Detector for PenFlow.

Capabilities:
  - Inspects HTTP responses passively for information leaks:
      • X-Internal-Server / X-Backend-Server headers
      • Stack traces (Traceback (most recent call last))
      • SQL syntax error messages (ORA-, MySQL, SyntaxError)
      • Debug information & internal path disclosures
"""
import re
from typing import Dict, Any, List
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.passive_anomaly_detector")

ANOMALY_PATTERNS = {
    "stack_trace": re.compile(r"(?:Traceback \(most recent call last\)|Exception in thread|Fatal error:)", re.IGNORECASE),
    "sql_error": re.compile(r"(?:ORA-\d{5}|SQL syntax.*MySQL|PostgreSQL.*ERROR|sqlite3\.OperationalError)", re.IGNORECASE),
    "internal_path": re.compile(r"(?:/var/www/|/home/[a-z0-9_-]+/|C:\\\\Users\\\\|C:\\\\Inetpub\\\\)", re.IGNORECASE)
}


class PassiveTrafficAnomalyDetector:
    """
    Passively inspects traffic response headers and body content for sensitive anomalies.
    """

    def inspect_exchange(self, url: str, status_code: int, headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []

        # 1. Header disclosures
        for h_name, h_val in headers.items():
            if h_name.lower().startswith("x-internal") or h_name.lower().startswith("x-backend"):
                anomalies.append({
                    "type": "internal_header_leak",
                    "url": url,
                    "header_name": h_name,
                    "header_value": h_val,
                    "severity": "LOW"
                })

        # 2. Body disclosures
        for anomaly_type, pattern in ANOMALY_PATTERNS.items():
            matches = pattern.findall(body)
            if matches:
                anomalies.append({
                    "type": anomaly_type,
                    "url": url,
                    "matched_sample": matches[0][:100],
                    "severity": "MEDIUM"
                })

        if anomalies:
            logger.info(f"[PassiveAnomalyDetector] Identified {len(anomalies)} anomalies in response from '{url}'.")

        return anomalies
