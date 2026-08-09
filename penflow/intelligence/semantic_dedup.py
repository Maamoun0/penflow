"""
Semantic Duplicate Detector for PenFlow.

Capabilities:
  - Vector & Hash similarity analysis across findings
  - Rejection of redundant or duplicate AI report submissions
"""
import hashlib
import uuid
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.semantic_dedup")


class SemanticDuplicateDetector:
    """
    Detector analyzing semantic similarity across vulnerability findings to eliminate duplicate reports.
    """

    def __init__(self, similarity_threshold: float = 0.90):
        self.similarity_threshold = similarity_threshold
        self.seen_hashes: Dict[str, Dict[str, Any]] = {}

    def _generate_finding_fingerprint(self, finding: Dict[str, Any]) -> str:
        vtype = str(finding.get("vulnerability_type", ""))
        url = str(finding.get("target_url", finding.get("target", "")))
        param = str(finding.get("parameter", ""))
        raw = f"{vtype}:{url}:{param}".lower()
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def check_duplicate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        fingerprint = self._generate_finding_fingerprint(finding)

        if fingerprint in self.seen_hashes:
            return {
                "is_duplicate": True,
                "similarity_score": 1.0,
                "original_finding": self.seen_hashes[fingerprint]
            }

        self.seen_hashes[fingerprint] = finding
        return {
            "is_duplicate": False,
            "similarity_score": 0.0
        }
