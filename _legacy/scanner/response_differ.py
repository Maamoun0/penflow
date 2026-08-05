import difflib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Any

from penflow.network.http_client import HttpResponse
from penflow.utils.hash_utils import sha256_hash

@dataclass
class DiffResult:
    deviation_score: float # 0.0 (identical) to 1.0 (completely different)
    diffs: Dict[str, Any] = field(default_factory=dict)
    is_anomalous: bool = False
    anomaly_reasons: List[str] = field(default_factory=list)

class ResponseDiffer:
    def __init__(self):
        # Known error signatures
        self.sql_errors = [
            "SQL syntax", "mysql_fetch", "ORA-01756", "PostgreSQL query failed",
            "SQLite/JDBCDriver", "System.Data.OleDb.OleDbException", "SQLServer JDBC Driver"
        ]
        
    def compare(self, baseline: HttpResponse, payload_response: HttpResponse, payload: str = "") -> DiffResult:
        """Compare two HTTP responses to find significant behavioral deviations."""
        if not baseline or not payload_response:
            return DiffResult(deviation_score=0.0)
            
        diffs = {}
        reasons = []
        score = 0.0
        
        # 1. Status Code Deviation (Highest weight)
        if baseline.status != payload_response.status:
            diffs["status"] = {"baseline": baseline.status, "payload": payload_response.status}
            # Special case: 200 -> 500 is a strong anomaly
            if baseline.status == 200 and payload_response.status >= 500:
                score += 0.4
                reasons.append("Status changed to Server Error (5xx)")
            else:
                score += 0.3
                reasons.append(f"Status changed from {baseline.status} to {payload_response.status}")
                
        # 2. Content Length Deviation
        len_b = len(baseline.body)
        len_p = len(payload_response.body)
        if len_b > 0:
            diff_ratio = abs(len_b - len_p) / len_b
            if diff_ratio > 0.1: # More than 10% change
                diffs["length"] = {"baseline": len_b, "payload": len_p, "ratio": diff_ratio}
                score += 0.2
                reasons.append(f"Content length changed by {diff_ratio:.0%}")
                
        # 3. Content Hash Deviation
        if sha256_hash(baseline.body) != sha256_hash(payload_response.body):
            diffs["hash_changed"] = True
            
        # 4. Error Keyword Detection
        if payload_response.status >= 500 or payload_response.status == 200:
            found_errors = [e for e in self.sql_errors if e.lower() in payload_response.body.lower()]
            if found_errors:
                diffs["sql_errors"] = found_errors
                score += 0.5
                reasons.append(f"SQL Error signatures detected: {found_errors}")
                
        # 5. Reflection Check (if payload provided)
        if payload and payload in payload_response.body:
            diffs["reflection"] = True
            # Only count as anomaly if it wasn't in baseline
            if payload not in baseline.body:
                score += 0.3
                reasons.append("Payload reflected in response body")
                
        # 6. JSON Structure Deviation (if applicable)
        if "application/json" in payload_response.headers.get("content-type", "").lower():
            try:
                j_base = json.loads(baseline.body)
                j_pay = json.loads(payload_response.body)
                if isinstance(j_base, dict) and isinstance(j_pay, dict):
                    base_keys = set(j_base.keys())
                    pay_keys = set(j_pay.keys())
                    if base_keys != pay_keys:
                        diffs["json_keys"] = {
                            "added": list(pay_keys - base_keys),
                            "removed": list(base_keys - pay_keys)
                        }
                        score += 0.2
                        reasons.append("JSON response structure changed")
            except Exception:
                pass

        # Finalize
        score = min(1.0, score)
        is_anomalous = score >= 0.3
        
        return DiffResult(
            deviation_score=score,
            diffs=diffs,
            is_anomalous=is_anomalous,
            anomaly_reasons=reasons
        )
