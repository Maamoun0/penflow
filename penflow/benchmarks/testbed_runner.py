"""
OWASP Benchmark & Testbed Runner for PenFlow.

Evaluates PenFlow agent findings against real-world testbed ground truth endpoints
(e.g., OWASP Juice Shop, WebGoat, DVWA, NodeGoat).
Calculates True Positive Rate (TPR), False Positive Rate (FPR), Precision, Recall, and F1-Score metrics.
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.benchmarks.testbed_runner")


class TestbedBenchmarkRunner:
    """
    Field Evaluation & Benchmark Runner.
    Compares verified PenFlow findings against known ground truth vulnerability ground-truth maps.
    """
    __test__ = False

    def __init__(self):
        pass

    def evaluate_findings(self, target_name: str, verified_findings: List[Dict[str, Any]],
                          ground_truth: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate agent findings against ground truth.
        
        ground_truth element structure:
          {"endpoint": "/api/v1/user", "vuln_type": "idor", "is_vulnerable": True}
        """
        logger.info(f"[TestbedRunner] Evaluating {len(verified_findings)} findings against {len(ground_truth)} ground truth records for '{target_name}'...")

        true_positives = 0
        false_positives = 0
        false_negatives = 0
        true_negatives = 0

        # Build lookup for ground truth
        gt_map = {(gt["endpoint"].lower(), gt["vuln_type"].lower()): gt.get("is_vulnerable", True) for gt in ground_truth}

        finding_map = {}
        for vf in verified_findings:
            ep = vf.get("target_url", vf.get("target", "")).lower()
            vtype = vf.get("vulnerability_type", vf.get("capability", "")).lower()
            finding_map[(ep, vtype)] = vf

        all_keys = set(gt_map.keys()).union(finding_map.keys())

        for key in all_keys:
            is_gt_vuln = gt_map.get(key, False)
            reported_finding = finding_map.get(key)
            is_reported_vuln = reported_finding.get("is_vulnerable", True) if reported_finding else False

            if is_gt_vuln and is_reported_vuln:
                true_positives += 1
            elif not is_gt_vuln and is_reported_vuln:
                false_positives += 1
            elif is_gt_vuln and not is_reported_vuln:
                false_negatives += 1
            else:
                true_negatives += 1

        precision = true_positives / max(1, (true_positives + false_positives))
        recall = true_positives / max(1, (true_positives + false_negatives))
        f1_score = 2 * (precision * recall) / max(0.001, (precision + recall))
        fpr = false_positives / max(1, (false_positives + true_negatives))

        metrics = {
            "target_name": target_name,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "false_positive_rate": round(fpr, 4)
        }

        logger.info(f"[TestbedRunner] Benchmark Results for '{target_name}': F1-Score={metrics['f1_score']}, Precision={metrics['precision']}, Recall={metrics['recall']}, FPR={metrics['false_positive_rate']}")
        return metrics
