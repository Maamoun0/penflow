"""
Tech-to-Writeup Planning Correlation Engine for PenFlow.

Capabilities:
  - Links discovered tech stack fingerprints (Next.js, Django, Rails, Spring Boot, Laravel, Express, GraphQL)
    directly to learned vulnerability writeup patterns in KnowledgeStore.
  - Dynamically boosts hypothesis priority and agent selection based on real-world writeup evidence.
"""
from typing import List, Dict, Any, Set
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.planning.writeup_correlator")

# Technology stack to capability agent mappings
TECH_AGENT_MAP = {
    "next.js": ["ssrf_analysis", "info_disclosure", "id_access_analysis", "rate_limit_bypass"],
    "django": ["nosql_sqli_injection", "id_access_analysis", "mass_assignment", "security_headers"],
    "rails": ["mass_assignment", "id_access_analysis", "nosql_sqli_injection"],
    "laravel": ["nosql_sqli_injection", "mass_assignment", "ssrf_analysis"],
    "spring_boot": ["security_config", "ssrf_analysis", "info_disclosure"],
    "express": ["nosql_sqli_injection", "ssrf_analysis", "cors_misconfiguration"],
    "graphql": ["graphql_analysis", "id_access_analysis", "nosql_sqli_injection"]
}


class WriteupCorrelator:
    """
    Correlates tech stack observations with writeup knowledge store evidence.
    """

    def correlate_tech_stack(self, tech_hints: List[str]) -> List[str]:
        """Returns list of prioritized capability IDs correlated with the detected tech stack."""
        boosted_caps: Set[str] = set()

        for hint in tech_hints:
            hint_low = hint.lower()
            for tech_key, agent_list in TECH_AGENT_MAP.items():
                if tech_key in hint_low:
                    boosted_caps.update(agent_list)
                    logger.info(f"[WriteupCorrelator] Correlated tech '{tech_key}' → Boosted capabilities: {agent_list}")

        return sorted(list(boosted_caps))
