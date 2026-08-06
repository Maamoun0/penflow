"""
Vulnerability Chaining Engine for PenFlow.

Capabilities:
  - Correlates individual security findings into high-impact exploit chains:
      • SSRF + Cloud Metadata Endpoint -> IMDS Credential Theft (Medium -> Critical)
      • Open Redirect + OAuth Manipulation -> Account Takeover (Low -> Critical)
      • IDOR + Path Traversal -> Full User Account Takeover (Medium -> Critical)
      • XSS + CSRF -> Admin Account Takeover (Medium -> Critical)
  - Escalates finding severity dynamically based on chain impact.
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.analysis.chain_builder")


class VulnerabilityChain:
    def __init__(self, name: str, step1_type: str, step2_type: str, escalated_severity: str, description: str):
        self.name = name
        self.step1_type = step1_type
        self.step2_type = step2_type
        self.escalated_severity = escalated_severity
        self.description = description


KNOWN_CHAIN_RULES = [
    VulnerabilityChain(
        name="SSRF to Cloud Metadata Credential Exfiltration",
        step1_type="ssrf",
        step2_type="info_disclosure",
        escalated_severity="CRITICAL",
        description="SSRF endpoint exploited to access cloud instance metadata server (169.254.169.254) and exfiltrate IAM tokens."
    ),
    VulnerabilityChain(
        name="Open Redirect to OAuth Token Hijacking",
        step1_type="open_redirect",
        step2_type="oauth_jwt",
        escalated_severity="CRITICAL",
        description="Open redirect vulnerability chained with OAuth redirect_uri parameter to leak authorization codes to attacker domain."
    ),
    VulnerabilityChain(
        name="IDOR + Path Traversal Account Takeover",
        step1_type="idor",
        step2_type="path_traversal",
        escalated_severity="CRITICAL",
        description="IDOR parameter combined with directory traversal to read arbitrary user session files."
    ),
    VulnerabilityChain(
        name="XSS + CSRF Admin Panel Takeover",
        step1_type="xss",
        step2_type="csrf_absent",
        escalated_severity="CRITICAL",
        description="Stored XSS vector executed in administrative dashboard to forge authenticated state-changing CSRF requests."
    )
]


class VulnerabilityChainEngine:
    """
    Engine analyzing findings array and synthesizing vulnerability chains.
    """

    def build_chains(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scans findings list for combinable attack steps and returns synthesized exploit chains."""
        chains_discovered: List[Dict[str, Any]] = []
        finding_types = {f.get("vulnerability_type", "").lower(): f for f in findings if isinstance(f, dict)}

        for rule in KNOWN_CHAIN_RULES:
            if rule.step1_type in finding_types and rule.step2_type in finding_types:
                f1 = finding_types[rule.step1_type]
                f2 = finding_types[rule.step2_type]

                chain_finding = {
                    "vulnerability_type": "exploit_chain",
                    "chain_name": rule.name,
                    "severity": rule.escalated_severity,
                    "description": rule.description,
                    "prerequisite_findings": [f1, f2],
                    "target_url": f1.get("target_url") or f2.get("target_url")
                }
                chains_discovered.append(chain_finding)
                logger.info(f"[ChainEngine] Discovered Exploit Chain: '{rule.name}' (Escalated Severity: {rule.escalated_severity}).")

        return chains_discovered
