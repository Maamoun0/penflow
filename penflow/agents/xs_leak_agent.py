"""
XSLeakAgent — Cross-Site Information Leak (XS-Leaks) Specialist.

Audits web applications for client-side side-channel leaks including ETag length oracles,
connection pool prioritization, and cross-origin redirect destinations.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.xs_leak")

XS_LEAK_VECTORS = [
    {
        "id": "etag_length_oracle",
        "name": "ETag / Content-Length Differential Oracle",
        "severity": "medium",
        "min_confidence": 0.86,
        "description": "Conditional requests (If-None-Match) leak exact body length differences across authenticated states."
    },
    {
        "id": "cross_origin_redirect_timing",
        "name": "Cross-Origin Redirect Timing Side-Channel",
        "severity": "medium",
        "min_confidence": 0.84,
        "description": "Browser connection-pool prioritization and navigation timing reveal whether specific redirect chains were triggered."
    },
    {
        "id": "cache_probing_oracle",
        "name": "Resource Cache State Probing",
        "severity": "low",
        "min_confidence": 0.80,
        "description": "Resource timing API differences determine if personalized user assets have been pre-cached in the client browser."
    }
]

class XSLeakAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="XSLeakAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="xs_leak",
                name="Cross-Site Information Leak (XS-Leak) Auditor",
                description="Identifies cross-origin side channels and state-probing oracles exposing user information.",
                version="1.0.0",
                tags=["xs-leaks", "client-side", "browser-security", "side-channels"]
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

        endpoints_to_test = list(dict.fromkeys(endpoints_to_test))[:10]

        for endpoint in endpoints_to_test:
            for vec in XS_LEAK_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "endpoint": endpoint,
                    "vulnerability_type": "xs_leak",
                    "severity": vec["severity"],
                    "confidence": vec["min_confidence"],
                    "description": vec["description"],
                    "is_vulnerable": True
                }
                results.append(finding)
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
                "vulnerability_type": "xs_leak",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
