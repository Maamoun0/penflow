"""
HackerOne Report Exporter for PenFlow.

Generates professional, copy-paste ready HackerOne submission markdown writeups
formatted with CVSS v3.1 vectors, CWE tags, Summary, Steps to Reproduce, Business Impact, and Remediation.
"""
from typing import Dict, Any
from penflow.reporting.impact_scorer import ImpactScorer
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.hackerone_exporter")


class HackerOneReportExporter:
    """
    Generates industry-standard HackerOne submission report markdown documents.
    """

    def __init__(self):
        self.impact_scorer = ImpactScorer()

    def export_report(self, finding: Dict[str, Any]) -> str:
        vtype = finding.get("vulnerability_type", "Security Vulnerability").upper()
        target = finding.get("target_url", "https://target.com")
        severity = finding.get("severity", "HIGH")
        desc = finding.get("description", "Vulnerability detected by PenFlow Autonomous Engine.")

        impact_info = self.impact_scorer.evaluate_impact(finding)

        report_md = f"""# [{severity}] {vtype} in {target}

**Severity**: {severity}
**CVSS v3.1 Vector**: `{impact_info['cvss_vector']}`
**Weakness Enumeration**: `{impact_info['cwe']}`

---

## 1. Summary
{desc}

---

## 2. Steps to Reproduce
1. Navigate to target endpoint: `{target}`
2. Inject the verified payload or submit cross-tenant authorization request.
3. Observe HTTP response returning unauthorized sensitive data or executing unauthorized operation.

---

## 3. Business Impact
{impact_info['business_impact']}

---

## 4. Supporting Evidence
```json
{finding}
```

---

## 5. Remediation Recommendations
- Enforce strict input validation, parameter sanitization, and context-aware escaping.
- Implement server-side authorization checks on every state-changing endpoint.
"""
        logger.info(f"[H1Exporter] Exported HackerOne markdown report for '{vtype}' on '{target}'.")
        return report_md
