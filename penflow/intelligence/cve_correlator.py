"""
CVE Correlation Engine for PenFlow.

Capabilities:
  - Matches detected technology stack fingerprints (Next.js, Django, Log4j, Spring Boot)
    against known CVE vulnerability databases and CVSS scores.
"""
from typing import List, Dict, Any
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.cve_correlator")

KNOWN_CVE_DATABASE = [
    {
        "tech_pattern": "next.js",
        "cve_id": "CVE-2023-46298",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "title": "Next.js Regular Expression Denial of Service (ReDoS)",
        "remediation": "Upgrade Next.js to version 13.4.2 or higher."
    },
    {
        "tech_pattern": "log4j",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "remediation": "Upgrade Log4j2 to version 2.17.1 or disable JNDI lookup."
    },
    {
        "tech_pattern": "spring",
        "cve_id": "CVE-2022-22965",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "title": "Spring Framework RCE via Data Binding (Spring4Shell)",
        "remediation": "Upgrade Spring Framework to 5.3.18 / 5.2.20 or Java 9+ patches."
    },
    {
        "tech_pattern": "django",
        "cve_id": "CVE-2022-34265",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "title": "Django Trunc & Extract SQL Injection",
        "remediation": "Upgrade Django to 4.0.6, 3.2.14 or higher."
    }
]


class CVECorrelationEngine:
    """
    Correlates technology stack fingerprints with known CVE vulnerability records.
    """

    def correlate(self, tech_stack: List[str]) -> List[Dict[str, Any]]:
        """Matches list of technology strings against CVE database."""
        matches: List[Dict[str, Any]] = []

        for tech in tech_stack:
            tech_low = tech.lower()
            for record in KNOWN_CVE_DATABASE:
                if record["tech_pattern"] in tech_low:
                    matches.append(record)
                    logger.info(f"[CVECorrelator] Matched '{tech}' to {record['cve_id']} (CVSS {record['cvss_score']}).")

        # Sort matches by CVSS score descending
        matches.sort(key=lambda x: x["cvss_score"], reverse=True)
        return matches
