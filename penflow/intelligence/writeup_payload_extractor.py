"""
WriteupPayloadExtractor — Dynamic Writeup-to-Payload Miner & Vulnerability Chain Extractor.

Mines raw writeup contents to extract reusable payloads, parameter names, and multi-stage exploit chains.
"""

import re
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.writeup_payload_extractor")

# RegEx patterns to extract actionable payloads from markdown / raw writeup texts
PAYLOAD_REGEXES = {
    "ssrf": [r"(http://169\.254\.169\.254[^\s'\"]+)", r"(http://metadata\.google\.internal[^\s'\"]+)"],
    "nosql": [r"(\{\$ne[^\}]+\})", r"(\{\$gt[^\}]+\})", r"(\{\$regex[^\}]+\})"],
    "ssti": [r"(\{\{7\*7\}\})", r"(\$\{7\*7\})", r"(\{\{config[^\}]+\}\})"],
    "sqli": [r"(' \+ AND SLEEP\(\d+\)--)", r"(UNION SELECT [^\n]+)", r"(' OR '1'='1)"],
    "idor_params": [r"(\?user_?id=\d+)", r"(\?account_?id=\d+)", r"(\?id=\d+)"],
    "headers": [r"(X-Forwarded-For: [^\n]+)", r"(Origin: [^\n]+)"]
}


class WriteupPayloadExtractor:
    """Extracts actionable payloads and constructs dynamic vulnerability chains from mined writeups."""

    def extract_payloads(self, writeup_content: str) -> Dict[str, List[str]]:
        extracted: Dict[str, List[str]] = {}
        for category, patterns in PAYLOAD_REGEXES.items():
            found: List[str] = []
            for pat in patterns:
                matches = re.findall(pat, writeup_content, re.IGNORECASE)
                found.extend(matches)
            if found:
                extracted[category] = list(set(found))
        return extracted

    def extract_dynamic_chains(self, writeup_title: str, writeup_content: str) -> Optional[Dict[str, Any]]:
        """Constructs an exploit chain scenario if writeup contains chaining indicators."""
        content_lower = writeup_content.lower()
        if any(kw in content_lower for kw in ["chained", "combining", "lead to", "escalated to"]):
            return {
                "chain_id": f"CHAIN_MINED_{hash(writeup_title) & 0xffffffff:08x}",
                "title": f"Mined Exploit Chain: {writeup_title[:60]}",
                "composite_severity": "HIGH",
                "narrative": writeup_content[:300] + "..."
            }
        return None
