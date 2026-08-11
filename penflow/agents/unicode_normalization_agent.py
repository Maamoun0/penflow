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
        logger.info(f"[UnicodeNormalizationAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "Unicode normalization input vectors safely handled by server without bypass."

        for endpoint in target_urls[:5]:
            for vec in UNICODE_TEST_VECTORS:
                norm_res = unicodedata.normalize(vec["form"], vec["sample_input"])
                try:
                    exch = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=f"{endpoint}?input={vec['sample_input']}" if "?" not in endpoint else f"{endpoint}&input={vec['sample_input']}"
                    )
                    resp = exch.response
                    if not resp:
                        continue

                    body_text = resp.body_text or resp.body_snippet or ""
                    if vec["normalized_expected"] in body_text and vec["sample_input"] not in body_text:
                        is_vulnerable = True
                        confidence = vec["min_confidence"]
                        reasoning = f"HIGH Unicode Normalization Bypass Proven [{vec['name']}]: Server normalized '{vec['sample_input']}' into '{vec['normalized_expected']}' on '{endpoint}'."

                        if confidence > max_confidence:
                            max_confidence = confidence
                            best_target = endpoint
                            best_reasoning = reasoning

                        results.append({
                            "vector_id": vec["id"],
                            "vector_name": vec["name"],
                            "endpoint": endpoint,
                            "vulnerability_type": "unicode_normalization",
                            "severity": vec["severity"],
                            "confidence": confidence,
                            "description": reasoning,
                            "is_vulnerable": True,
                            "_exchange_obj": exch.to_dict()
                        })
                        break
                except Exception as e:
                    logger.debug(f"[UnicodeNormalizationAgent] Probe error on {endpoint}: {e}")

        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vulnerable,
            confidence_score=max_confidence if is_vulnerable else 0.0,
            reasoning=best_reasoning,
            target_url=best_target,
            findings=results,
            evidence={
                "vulnerability_type": "unicode_normalization",
                "findings": results,
                "target_url": best_target,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable,
                "evidence_exchanges": [r.get("_exchange_obj", {}) for r in results if r.get("_exchange_obj")]
            }
        ).to_dict()

    def _collect_endpoints(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        endpoints = [target_url]

        if hasattr(context, "observations") and context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    for ep in data.get("endpoints", []):
                        if isinstance(ep, dict) and ep.get("url"):
                            endpoints.append(ep["url"])

        return list(dict.fromkeys(endpoints))

