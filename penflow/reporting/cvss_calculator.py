"""
CVSS v3.1 Calculator for PenFlow.
Computes a detailed CVSS Base Score with Attack Vector, Complexity, Impact metrics.
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.cvss")


@dataclass
class CVSSMetrics:
    """CVSS v3.1 Base Score components."""
    # Attack Vector: Network (N), Adjacent (A), Local (L), Physical (P)
    attack_vector: str = "N"
    # Attack Complexity: Low (L), High (H)
    attack_complexity: str = "L"
    # Privileges Required: None (N), Low (L), High (H)
    privileges_required: str = "N"
    # User Interaction: None (N), Required (R)
    user_interaction: str = "N"
    # Scope: Unchanged (U), Changed (C)
    scope: str = "U"
    # Confidentiality Impact: None (N), Low (L), High (H)
    confidentiality: str = "L"
    # Integrity Impact: None (N), Low (L), High (H)
    integrity: str = "N"
    # Availability Impact: None (N), Low (L), High (H)
    availability: str = "N"


# CVSS v3.1 metric weight lookup tables
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


class CVSSCalculator:
    """Compute CVSS v3.1 Base Score from metrics."""

    # Default metric profiles for common vulnerability types
    VULN_PROFILES: Dict[str, CVSSMetrics] = {
        "id_access_analysis": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="L",
            user_interaction="N", scope="U", confidentiality="H", integrity="L", availability="N"
        ),
        "authorization": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="L",
            user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
        ),
        "bola_check": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="L",
            user_interaction="N", scope="U", confidentiality="H", integrity="L", availability="N"
        ),
        "bfla_analysis": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="L",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="N"
        ),
        "graphql_introspection": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="L", integrity="N", availability="N"
        ),
        "graphql_depth_analysis": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="N", integrity="N", availability="H"
        ),
        "mass_assignment_analysis": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="L",
            user_interaction="N", scope="U", confidentiality="L", integrity="H", availability="N"
        ),
        "oauth_misconfiguration": CVSSMetrics(
            attack_vector="N", attack_complexity="H", privileges_required="N",
            user_interaction="R", scope="C", confidentiality="H", integrity="H", availability="N"
        ),
        "jwt_validation": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="N"
        ),
        "cors_misconfiguration": CVSSMetrics(
            attack_vector="N", attack_complexity="H", privileges_required="N",
            user_interaction="R", scope="U", confidentiality="H", integrity="N", availability="N"
        ),
        "ssrf_analysis": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="L", availability="L"
        ),
        "race_condition_analysis": CVSSMetrics(
            attack_vector="N", attack_complexity="H", privileges_required="L",
            user_interaction="N", scope="U", confidentiality="N", integrity="H", availability="N"
        ),
        "nosql_injection": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="L"
        ),
        "sql_injection": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"
        ),
        "ssti_analysis": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
        ),
        "ssti_rce": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
        ),
        "command_injection": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
        ),
        "rate_limit_bypass": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="N", integrity="L", availability="L"
        ),
        "info_disclosure": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"
        ),
        "open_redirect": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="R", scope="C", confidentiality="L", integrity="L", availability="N"
        ),
        "websocket_auth_flaw": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="R", scope="U", confidentiality="H", integrity="H", availability="N"
        ),
        "http_smuggling": CVSSMetrics(
            attack_vector="N", attack_complexity="H", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
        ),
        "grpc_web_bypass": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="N"
        ),
        "saml_xml_wrapping": CVSSMetrics(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="N"
        ),
    }

    def get_metrics_for(self, vuln_type: str) -> CVSSMetrics:
        """Get CVSS metrics for a vulnerability type, with defaults for unknown types."""
        return self.VULN_PROFILES.get(vuln_type, CVSSMetrics())

    def calculate_score(self, metrics: CVSSMetrics) -> Dict[str, Any]:
        """Calculate CVSS v3.1 Base Score."""
        av = _AV.get(metrics.attack_vector, 0.85)
        ac = _AC.get(metrics.attack_complexity, 0.77)

        pr_table = _PR_CHANGED if metrics.scope == "C" else _PR_UNCHANGED
        pr = pr_table.get(metrics.privileges_required, 0.85)
        ui = _UI.get(metrics.user_interaction, 0.85)

        c = _CIA.get(metrics.confidentiality, 0.0)
        i = _CIA.get(metrics.integrity, 0.0)
        a = _CIA.get(metrics.availability, 0.0)

        # ISS (Impact Sub-Score)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Impact
        if metrics.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif metrics.scope == "U":
            base_score = min(10.0, self._roundup(impact + exploitability))
        else:
            base_score = min(10.0, self._roundup(1.08 * (impact + exploitability)))

        # Severity rating
        if base_score == 0.0:
            severity = "None"
        elif base_score < 4.0:
            severity = "Low"
        elif base_score < 7.0:
            severity = "Medium"
        elif base_score < 9.0:
            severity = "High"
        else:
            severity = "Critical"

        vector_string = (
            f"CVSS:3.1/AV:{metrics.attack_vector}/AC:{metrics.attack_complexity}/"
            f"PR:{metrics.privileges_required}/UI:{metrics.user_interaction}/"
            f"S:{metrics.scope}/C:{metrics.confidentiality}/"
            f"I:{metrics.integrity}/A:{metrics.availability}"
        )

        return {
            "base_score": round(base_score, 1),
            "severity": severity,
            "vector_string": vector_string,
            "impact_subscore": round(impact, 1),
            "exploitability_subscore": round(exploitability, 1),
        }

    def _roundup(self, value: float) -> float:
        """CVSS v3.1 roundup function."""
        import math
        return math.ceil(value * 10) / 10


CVSSv31Calculator = CVSSCalculator

