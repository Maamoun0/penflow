"""
SARIF v2.1.0 Exporter & Enterprise Webhook Integrations for PenFlow.

Generates compliant SARIF v2.1.0 (Static Analysis Results Interchange Format) JSON reports
compatible with GitHub Code Security, SonarQube, and enterprise IDEs.
Provides webhook integrations for Slack and Jira incident management APIs.
"""
import json
import httpx
from typing import List, Dict, Any, Optional
from penflow.reporting.cvss_calculator import CVSSCalculator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.sarif_exporter")


class SARIFExporter:
    """
    SARIF v2.1.0 Standard JSON Exporter.
    """
    def __init__(self):
        self.cvss_calc = CVSSCalculator()

    def export_sarif(self, target_domain: str, verified_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert verified findings into SARIF v2.1.0 specification dictionary."""
        rules = []
        results = []

        rule_indices: Dict[str, int] = {}

        for idx, vf in enumerate(verified_findings):
            vtype = vf.get("vulnerability_type", vf.get("capability", "unknown_vuln"))
            if vtype not in rule_indices:
                rule_idx = len(rules)
                rule_indices[vtype] = rule_idx
                metrics = self.cvss_calc.get_metrics_for(vtype)
                cvss = self.cvss_calc.calculate_score(metrics)

                rules.append({
                    "id": f"PENFLOW-{vtype.upper()}",
                    "name": vtype,
                    "shortDescription": {"text": f"PenFlow Security Finding: {vtype}"},
                    "fullDescription": {"text": vf.get("reasoning", "Autonomous security finding verified by PenFlow.")},
                    "defaultConfiguration": {
                        "level": "error" if cvss["severity"] in ("CRITICAL", "HIGH") else "warning"
                    },
                    "properties": {
                        "precision": "high",
                        "security-severity": str(cvss["base_score"])
                    }
                })

            rule_index = rule_indices[vtype]
            target_url = vf.get("target_url", vf.get("target", target_domain))

            results.append({
                "ruleId": f"PENFLOW-{vtype.upper()}",
                "ruleIndex": rule_index,
                "level": "error" if vf.get("confidence_score", 0.9) >= 0.85 else "warning",
                "message": {
                    "text": vf.get("reasoning", f"Verified vulnerability '{vtype}' detected at {target_url}.")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target_url
                            }
                        }
                    }
                ]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PenFlow SROS",
                            "version": "28.0.0",
                            "informationUri": "https://github.com/Maamoun0/penflow",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }

        logger.info(f"[SARIFExporter] Generated SARIF v2.1.0 report containing {len(results)} findings.")
        return sarif_doc

    def save_sarif_file(self, target_domain: str, sarif_dict: Dict[str, Any], output_path: str = "reports/penflow_results.sarif") -> str:
        import os
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_dict, f, indent=2)
        logger.info(f"[SARIFExporter] Saved SARIF file to '{output_path}'.")
        return output_path


class EnterpriseWebhookNotifier:
    """
    Enterprise Slack & Jira Webhook Alert Dispatcher.
    """

    async def send_slack_alert(self, webhook_url: str, target_domain: str, findings_count: int, critical_count: int) -> bool:
        if not webhook_url:
            return False

        payload = {
            "text": f"🚨 *PenFlow Security Assessment Alert: {target_domain}*\n"
                    f"• *Total Verified Findings*: {findings_count}\n"
                    f"• *Critical Severity*: {critical_count}\n"
                    f"• *Report Platform*: PenFlow SROS Enterprise v28.0"
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(webhook_url, json=payload)
                return resp.status_code == 200
        except Exception as e:
            logger.error(f"[WebhookNotifier] Slack alert failed: {e}")
            return False
