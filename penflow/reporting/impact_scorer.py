"""
Business Impact Scoring Engine for PenFlow.

Capabilities:
  - Translates technical vulnerabilities into business impact metrics:
      • Financial Fraud / Payment Data Compromise
      • Personally Identifiable Information (PII) Data Exfiltration
      • Administrative Privilege Escalation
      • Remote System Infrastructure Takeover
"""
from typing import Dict, Any
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.impact_scorer")

IMPACT_MAPPINGS = {
    "ssrf": {
        "business_impact": "Attacker can pivot into internal network, read cloud metadata credentials, and achieve full infrastructure takeover.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-918"
    },
    "idor": {
        "business_impact": "Attacker can enumerate and harvest private user PII, credit card details, and account records across all registered users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-639"
    },
    "account_takeover": {
        "business_impact": "Attacker can hijack arbitrary user accounts, alter credentials, and gain full unauthorized access.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-640"
    },
    "exploit_chain": {
        "business_impact": "Combined exploit chain allows complete end-to-end compromise of user accounts and administrative controls.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-693"
    }
}


class ImpactScorer:
    """
    Evaluates finding attributes and returns business impact descriptions.
    """

    def evaluate_impact(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        vtype = finding.get("vulnerability_type", "").lower()
        mapping = IMPACT_MAPPINGS.get(vtype, {
            "business_impact": "Potential unauthorized access or information disclosure impact.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe": "CWE-200"
        })
        return mapping
