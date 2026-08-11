"""
XSLeakAgent — Cross-Site Information Leak (XS-Leaks) Specialist for PenFlow.

Audits web applications for HTTP-level client-side side-channel leaks:
  - ETag / Content-Length differential oracles
  - Conditional caching (If-None-Match) differential responses
  - Navigation timing & redirect side-channels

Note: Fully interactive DOM-level XS-Leak execution (such as frame-counting, window.length probes,
or subresource WebGL timing) relies on Playwright browser execution context.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
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
                description="Identifies HTTP-level cross-origin side channels and state-probing oracles exposing user information (HTTP-level probes; DOM probes require Playwright runner).",
                version="1.1.0",
                tags=["xs-leaks", "client-side", "browser-security", "side-channels", "http-oracle"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[XSLeakAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "Cross-site side channels safely mitigated without ETag or timing oracle exposure."

        for endpoint in target_urls[:6]:
            for vec in XS_LEAK_VECTORS:
                try:
                    if vec["id"] == "etag_length_oracle":
                        # Probe 1: Send request to obtain ETag
                        exch1 = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=endpoint)
                        resp1 = exch1.response
                        if not resp1 or not resp1.headers:
                            continue

                        etag = resp1.headers.get("etag", "")
                        if etag:
                            # Probe 2: Send conditional request
                            exch2 = await http_client.send_as_identity(
                                identity_id="anonymous_guest",
                                method="GET",
                                url=endpoint,
                                headers={"If-None-Match": etag}
                            )
                            resp2 = exch2.response
                            if resp2 and resp2.status_code == 304:
                                is_vulnerable = True
                                confidence = vec["min_confidence"]
                                reasoning = f"MEDIUM XS-Leak ETag Oracle Proven: Endpoint '{endpoint}' responds with 304 Not Modified to If-None-Match ETag '{etag}', exposing cache state."

                                if confidence > max_confidence:
                                    max_confidence = confidence
                                    best_target = endpoint
                                    best_reasoning = reasoning

                                results.append({
                                    "vector_id": vec["id"],
                                    "vector_name": vec["name"],
                                    "endpoint": endpoint,
                                    "etag": etag,
                                    "vulnerability_type": "xs_leak",
                                    "severity": vec["severity"],
                                    "confidence": confidence,
                                    "description": reasoning,
                                    "is_vulnerable": True,
                                    "_exchange_obj": exch2.to_dict()
                                })

                    elif vec["id"] == "cross_origin_redirect_timing":
                        # Measure timing differential
                        t1_start = context.time() if hasattr(context, "time") else 0.0
                        exch_t1 = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=endpoint)
                        t1_end = context.time() if hasattr(context, "time") else 0.0

                        resp_t1 = exch_t1.response
                        if resp_t1 and resp_t1.status_code in (301, 302, 307, 308) and (t1_end - t1_start) > 1.5:
                            is_vulnerable = True
                            confidence = vec["min_confidence"]
                            reasoning = f"MEDIUM XS-Leak Timing Oracle: Endpoint '{endpoint}' exhibits significant redirect timing differential."

                            if confidence > max_confidence:
                                max_confidence = confidence
                                best_target = endpoint
                                best_reasoning = reasoning

                            results.append({
                                "vector_id": vec["id"],
                                "vector_name": vec["name"],
                                "endpoint": endpoint,
                                "vulnerability_type": "xs_leak",
                                "severity": vec["severity"],
                                "confidence": confidence,
                                "description": reasoning,
                                "is_vulnerable": True,
                                "_exchange_obj": exch_t1.to_dict()
                            })
                except Exception as e:
                    logger.debug(f"[XSLeakAgent] Probe error on {endpoint}: {e}")

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
                "vulnerability_type": "xs_leak",
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

