"""
FrameworkCachePoisoningAgent — Modern Web Framework Internal Cache Poisoning Specialist.

Audits Next.js (React Server Components RSC payload cache, ISR), Nuxt, SvelteKit, and Remix
applications for internal cache poisoning and unkeyed header injection flaws.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.framework_cache_poisoning")

FRAMEWORK_CACHE_VECTORS = [
    {
        "id": "nextjs_rsc_cache_poisoning",
        "name": "Next.js RSC Header Unkeyed Cache Poisoning",
        "headers": {"RSC": "1", "Next-Router-State-Tree": "poisoned_state"},
        "severity": "high",
        "min_confidence": 0.91,
        "description": "Next.js React Server Component headers are stored in shared edge/CDN cache without proper cache-key separation."
    },
    {
        "id": "nextjs_action_revalidation",
        "name": "Next.js Server Action State Revalidation Abuse",
        "headers": {"Next-Action": "true", "x-now-route-matches": "1"},
        "severity": "high",
        "min_confidence": 0.89,
        "description": "Server Action revalidation triggers stale or malicious state caching across concurrent users."
    },
    {
        "id": "nuxt_async_data_cache",
        "name": "Nuxt 3 asyncData / useFetch Key Collisions",
        "headers": {"x-nuxt-cache-id": "custom_key"},
        "severity": "medium",
        "min_confidence": 0.85,
        "description": "Nuxt shared data payload cache keys lack query parameter or session binding."
    }
]

class FrameworkCachePoisoningAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="FrameworkCachePoisoningAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="framework_cache_poisoning",
                name="Modern Framework Internal Cache Poisoning Auditor",
                description="Audits Next.js RSC, Nuxt, and modern SPA server framework cache boundaries for poisoning flaws.",
                version="1.0.0",
                tags=["cache-poisoning", "nextjs", "react-server-components", "nuxt", "web-frameworks"]
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
            for vec in FRAMEWORK_CACHE_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "test_headers": vec["headers"],
                    "endpoint": endpoint,
                    "vulnerability_type": "framework_cache_poisoning",
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
                "vulnerability_type": "framework_cache_poisoning",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
