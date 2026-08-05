import re
import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.writeup_miner")

VULN_TYPE_KEYWORDS = {
    "idor": ["idor", "bola", "broken object level", "parameter tampering", "insecure direct object"],
    "bfla": ["bfla", "broken function level", "privilege escalation", "admin bypass", "method tampering"],
    "mass_assignment": ["mass assignment", "auto binding", "parameter pollution", "property injection"],
    "graphql": ["graphql", "introspection", "query batching", "nested query"],
    "race_condition": ["race condition", "toctou", "double spend", "concurrency", "parallel requests"],
    "oauth_jwt": ["oauth", "jwt", "token", "algorithm confusion", "none algorithm", "header forgery"],
    "ssrf": ["ssrf", "server-side request forgery", "metadata", "169.254.169.254", "internal network"],
    "cors": ["cors", "cross-origin", "origin reflection", "allow-credentials"],
    "nosql": ["nosql", "mongodb", "$gt", "$ne", "operator injection"],
    "websocket": ["websocket", "cswsh", "hijacking"],
    "smuggling": ["smuggling", "cl.te", "te.cl", "transfer-encoding"],
    "sqli": ["sql injection", "sqli", "union select", "sql syntax", "error-based"],
    "ssti": ["ssti", "template injection", "jinja", "twig", "freemarker", "expression evaluation"],
    "rce": ["rce", "remote code execution", "command injection", "shell injection", "os command"],
    "rate_limit": ["rate limit", "rate-limit", "throttling", "429", "anti-automation", "ip spoofing"],
    "open_redirect": ["open redirect", "redirect_uri", "oauth redirect", "callback manipulation"],
    "info_disclosure": ["actuator", "swagger", "openapi", "information disclosure", "debug endpoint", "env file"],
}

@dataclass
class SecurityWriteup:
    id: str
    title: str
    target_technology: str
    detected_vulnerabilities: List[str]
    extracted_patterns: List[str]
    raw_content: str
    source_url: Optional[str] = None
    created_at: str = ""

class WriteupMiner:
    """
    Parses and mines public bug bounty writeups (HackerOne, Bugcrowd, Medium)
    and extracts tactical vulnerability patterns, regexes, and endpoint structures.
    """

    def parse_writeup_text(self, title: str, content: str, source_url: Optional[str] = None) -> SecurityWriteup:
        logger.info(f"[WriteupMiner] Mining writeup: '{title}'...")

        content_lower = content.lower()
        detected_types: List[str] = []

        for vtype, keywords in VULN_TYPE_KEYWORDS.items():
            if any(kw in content_lower for kw in keywords):
                detected_types.append(vtype)

        # Extract path & parameter patterns (e.g., /api/v1/user?id=123)
        path_matches = re.findall(r"(/[a-zA-Z0-9_\-\.\?=/&%]+)", content)
        unique_paths = list(set([p for p in path_matches if len(p) > 3 and not p.startswith("//")]))[:15]

        # Extract technology indicators
        techs = ["graphql", "node", "express", "django", "rails", "laravel", "spring", "asp.net", "aws"]
        found_techs = [t for t in techs if t in content_lower]
        target_tech = ", ".join(found_techs) if found_techs else "generic"

        writeup_id = f"wu_{hash(title) & 0xffffffff:08x}"

        writeup = SecurityWriteup(
            id=writeup_id,
            title=title,
            target_technology=target_tech,
            detected_vulnerabilities=detected_types,
            extracted_patterns=unique_paths,
            raw_content=content,
            source_url=source_url
        )
        logger.info(f"[WriteupMiner] Mined writeup '{title}': Found vulnerabilities {detected_types}")
        return writeup
