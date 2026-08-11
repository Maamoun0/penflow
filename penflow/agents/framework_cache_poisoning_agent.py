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
        logger.info(f"[FrameworkCachePoisoningAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "Framework internal cache headers were safely ignored or properly keyed."

        evil_host = f"evil-{context.asset}"

        for endpoint in target_urls[:6]:
            for vec in FRAMEWORK_CACHE_VECTORS:
                headers = vec["headers"].copy()
                headers["X-Forwarded-Host"] = evil_host

                try:
                    # Request 1: Poisoning attempt
                    exch1 = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=endpoint,
                        headers=headers
                    )
                    resp1 = exch1.response
                    if not resp1:
                        continue

                    body1 = (resp1.body_text or resp1.body_snippet or "").lower()
                    headers1_str = str(resp1.headers or {}).lower()

                    # Check if unkeyed header was reflected
                    if evil_host.lower() in body1 or evil_host.lower() in headers1_str:
                        # Request 2: Follow-up request WITHOUT unkeyed headers to confirm cache persistence
                        exch2 = await http_client.send_as_identity(
                            identity_id="anonymous_guest",
                            method="GET",
                            url=endpoint
                        )
                        resp2 = exch2.response
                        body2 = (resp2.body_text or resp2.body_snippet or "").lower() if resp2 else ""
                        headers2_str = str(resp2.headers or {}).lower() if resp2 else ""

                        if resp2 and (evil_host.lower() in body2 or evil_host.lower() in headers2_str):
                            is_vulnerable = True
                            confidence = vec["min_confidence"]
                            reasoning = f"HIGH Framework Cache Poisoning Proven [{vec['name']}]: Unkeyed header '{evil_host}' was cached and served on clean follow-up request to '{endpoint}'."

                            if confidence > max_confidence:
                                max_confidence = confidence
                                best_target = endpoint
                                best_reasoning = reasoning

                            results.append({
                                "vector_id": vec["id"],
                                "vector_name": vec["name"],
                                "test_headers": headers,
                                "endpoint": endpoint,
                                "vulnerability_type": "framework_cache_poisoning",
                                "severity": vec["severity"],
                                "confidence": confidence,
                                "description": reasoning,
                                "is_vulnerable": True,
                                "_exchange_obj": exch2.to_dict()
                            })
                            break
                except Exception as e:
                    logger.debug(f"[FrameworkCachePoisoningAgent] Probe error on {endpoint}: {e}")

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
                "vulnerability_type": "framework_cache_poisoning",
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

        if hasattr(context, "shared_cache") and context.shared_cache:
            mapped = context.shared_cache.get("endpoint_mapping", [])
            for ep in mapped:
                if isinstance(ep, str) and ep.startswith("http"):
                    endpoints.append(ep)
                elif isinstance(ep, dict) and "url" in ep:
                    endpoints.append(ep["url"])

        return list(dict.fromkeys(endpoints))

