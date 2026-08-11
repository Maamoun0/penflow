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
        "business_impact": "An unauthenticated attacker can pivot into internal private network boundaries, access AWS/GCP cloud instance metadata credentials (IAM keys), and achieve full infrastructure compromise.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-918"
    },
    "ssrf_redirect_chain": {
        "business_impact": "An attacker can bypass network firewall filters via HTTP redirect chaining to reach internal management endpoints and leak internal services.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe": "CWE-918"
    },
    "idor": {
        "business_impact": "An attacker can systematically enumerate and exfiltrate private user PII, order histories, and financial records belonging to all tenants across the platform.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-639"
    },
    "jwt_security_analysis": {
        "business_impact": "An attacker can forge administrative JWT tokens using 'alg: none' or key confusion, completely bypassing authentication to control any user account.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-347"
    },
    "polyglot_ssti": {
        "business_impact": "An attacker can execute arbitrary remote code on the web server host process, gaining interactive shell access and compromising system databases.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-1336"
    },
    "orm_leak": {
        "business_impact": "An attacker can exploit ORM filter parameter parsing differentials to extract hidden database columns and exfiltrate database records.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-89"
    },
    "framework_cache_poisoning": {
        "business_impact": "An attacker can poison CDN and edge proxy caches with malicious unkeyed headers, serving compromised JavaScript payloads to all visiting legitimate users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cwe": "CWE-444"
    },
    "prompt_injection_audit": {
        "business_impact": "An attacker can override system instructions in downstream AI features, forcing the model to exfiltrate private tenant data or run arbitrary tool actions.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-1393"
    },
    "rag_poisoning_audit": {
        "business_impact": "An attacker can inject malicious instruction text into shared knowledge base documents, hijacking context retrieval for all enterprise users.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-1393"
    },
    "ai_agent_security_audit": {
        "business_impact": "An attacker can trick autonomous AI agents into executing arbitrary system commands or unauthorized tool calls with server privileges.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-77"
    },
    "nosql_injection": {
        "business_impact": "An attacker can inject NoSQL query operators ($ne, $gt) into JSON requests to bypass login authentication without a valid password.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-943"
    },
    "ai_supply_chain_security": {
        "business_impact": "Exposed OpenAI/HuggingFace API keys in configuration files allow unauthorized third parties to hijack AI infrastructure and bill usage to the victim organization.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-798"
    }
}


class ImpactScorer:
    """
    Evaluates finding attributes and returns business impact descriptions.
    """

    def evaluate_impact(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        vtype = finding.get("vulnerability_type", "").lower()
        mapping = IMPACT_MAPPINGS.get(vtype, {
            "business_impact": "Unsanitized parameter handling permits unauthorized information disclosure or security control bypass.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe": "CWE-200"
        })
        return mapping

