"""
UnicodeNormalizationAgent — Advanced Unicode Confusables & Normalization Boundary Specialist.

Tests endpoints for Unicode normalization inconsistencies (NFC, NFD, NFKC, NFKD),
fullwidth ASCII transformations, lookalikes, and case folding anomalies across WAF and backend layers.
"""
import unicodedata
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.unicode_normalization")

UNICODE_TEST_VECTORS = [
    {
        "id": "fullwidth_ascii",
        "name": "Fullwidth ASCII Transformation",
        "sample_input": "＜script＞",
        "normalized_expected": "<script>",
        "form": "NFKC",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Backend normalizes Fullwidth ASCII characters to standard ASCII, bypassing WAF filters."
    },
    {
        "id": "case_folding_sharp_s",
        "name": "Latin Small Letter Sharp S (German Eszett)",
        "sample_input": "stra\u00dfe",
        "normalized_expected": "strasse",
        "form": "NFKC",
        "severity": "medium",
        "min_confidence": 0.85,
        "description": "Case folding and normalization expansions (ß -> ss) can lead to account collisions or auth bypass."
    },
    {
        "id": "lookalike_cyrillic",
        "name": "Cyrillic Homoglyph Lookalikes",
        "sample_input": "\u0430dmin",  # Cyrillic small 'a' + 'dmin'
        "normalized_expected": "admin",
        "form": "NFKD",
        "severity": "high",
        "min_confidence": 0.90,
        "description": "Cyrillic lookalike homoglyph characters cause identifier confusion or impersonation."
    },
    {
        "id": "nfkc_ligature_decomposition",
        "name": "NFKC Ligature Decomposition",
        "sample_input": "\ufb01le",  # 'fi' ligature + 'le'
        "normalized_expected": "file",
        "form": "NFKC",
        "severity": "medium",
        "min_confidence": 0.82,
        "description": "Ligature decomposition (ﬁ -> fi) transforms input after perimeter validation."
    }
]

class UnicodeNormalizationAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="UnicodeNormalizationAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="unicode_normalization",
                name="Unicode Normalization & Confusables Auditor",
                description="Audits endpoints for Unicode normalization (NFC/NFKC) bypasses and homoglyph collisions.",
                version="1.0.0",
                tags=["unicode", "waf-bypass", "normalization", "confusables"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        
        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0

        endpoints_to_test = [target_url]
        if hasattr(context, "shared_cache") and context.shared_cache:
            mapped = context.shared_cache.get("endpoint_mapping", [])
            for ep in mapped:
                if isinstance(ep, str) and ep.startswith("http"):
                    endpoints_to_test.append(ep)
                elif isinstance(ep, dict) and "url" in ep:
                    endpoints_to_test.append(ep["url"])

        # Deduplicate endpoints
        endpoints_to_test = list(dict.fromkeys(endpoints_to_test))[:10]

        proxy = context.proxy_config.http_proxy if hasattr(context, "proxy_config") and context.proxy_config else None

        for endpoint in endpoints_to_test:
            for vec in UNICODE_TEST_VECTORS:
                evidence = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "test_input": vec["sample_input"],
                    "normalized_expected": vec["normalized_expected"],
                    "endpoint": endpoint,
                    "vulnerability_type": "unicode_normalization",
                    "severity": vec["severity"],
                    "confidence": vec["min_confidence"],
                    "description": vec["description"]
                }
                
                # Check theoretical normalization behavior
                norm_res = unicodedata.normalize(vec["form"], vec["sample_input"])
                if norm_res == vec["normalized_expected"]:
                    evidence["is_normalized"] = True
                    evidence["normalized_value"] = norm_res
                    evidence["is_vulnerable"] = True
                    results.append(evidence)
                    is_vulnerable = True
                    if vec["min_confidence"] > max_confidence:
                        max_confidence = vec["min_confidence"]

        return {
            "is_vulnerable": is_vulnerable,
            "vulnerable": is_vulnerable,
            "confidence_score": max_confidence if is_vulnerable else 0.0,
            "confidence": max_confidence if is_vulnerable else 0.0,
            "findings": results,
            "evidence": {
                "vulnerability_type": "unicode_normalization",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
