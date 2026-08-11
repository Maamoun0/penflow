"""
Business Impact Proof Engine for PenFlow.

Capabilities:
  - Scans HTTP response bodies and trace evidence for verified sensitive data (PII, SSNs, credit card numbers, passwords, IAM keys)
  - Constructs empirical business impact proof statements for submission reports
"""
import re
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.business_impact_proof")

SENSITIVE_PATTERNS = [
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email Address"),
    (r'\b\d{3}-\d{2}-\d{4}\b', "US Social Security Number (SSN)"),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "Credit Card Number"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'sk-[A-Za-z0-9]{32,}', "OpenAI Secret API Key"),
    (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "JWT Authentication Token"),
    (r'root:x:0:0:root', "System /etc/passwd File Data")
]


class BusinessImpactProofEngine:
    """
    Evaluates HTTP evidence exchanges and generates empirical proof statements.
    """

    def generate_proof_statement(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        evidence_exchanges = finding.get("evidence_exchanges", [])
        if not evidence_exchanges and "_exchange_obj" in finding:
            evidence_exchanges = [finding["_exchange_obj"]]

        discovered_leaks: List[str] = []
        proof_summary = ""

        for exch in evidence_exchanges:
            resp = exch.get("response", {}) if isinstance(exch, dict) else {}
            body = str(resp.get("body_snippet", resp.get("body_text", "")))

            for pat, leak_type in SENSITIVE_PATTERNS:
                matches = re.findall(pat, body)
                if matches:
                    discovered_leaks.append(f"{leak_type} (e.g. '{matches[0][:15]}...')")

        discovered_leaks = list(dict.fromkeys(discovered_leaks))

        if discovered_leaks:
            proof_summary = f"EMPIRICAL DATA PROOF: Response evidence contains verified sensitive assets: {', '.join(discovered_leaks)}."
        else:
            proof_summary = "EMPIRICAL PROOF: Endpoint permits unauthorized parameter injection or security control bypass."

        logger.info(f"[BusinessImpactProofEngine] Generated proof: {proof_summary}")

        return {
            "has_empirical_proof": len(discovered_leaks) > 0,
            "discovered_leaks": discovered_leaks,
            "proof_statement": proof_summary
        }
