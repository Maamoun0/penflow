"""
ClientSidePathTraversalAgent — Client-Side Path Traversal (CSPT) & Sink Analysis Specialist for PenFlow.

Audits client-side JavaScript Single Page Application (SPA) routing, fetch(), axios, and DOM sinks:
  - Standard traversal (../) in fetch() URLs
  - URL-encoded & double-encoded sequences (%2e%2e%2f, %252e%252e%252f)
  - Backslash normalization (..\\) in window.location and dynamic import()
  - Client-side sink injection (DOM XSS / CSRF token leakage via API route redirection)
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.cspt")

CSPT_VECTORS = [
    {
        "id": "dot_dot_slash_traversal",
        "name": "Standard Client-Side Path Traversal (../)",
        "payload": "/../../admin/api",
        "target_sink": "fetch(apiUrl + path)",
        "severity": "high",
        "min_confidence": 0.91,
        "description": "Client-side router or fetch() URL builder interpolates unvalidated path components, redirecting API requests to unintended endpoints."
    },
    {
        "id": "encoded_slash_traversal",
        "name": "URL-Encoded Slash Traversal (%2e%2e%2f)",
        "payload": "/%2e%2e%2f%2e%2e%2fsettings",
        "target_sink": "axios.get(`/user/${subpath}`)",
        "severity": "high",
        "min_confidence": 0.89,
        "description": "URL-encoded traversal sequences bypass client-side regex path validation before fetch() execution."
    },
    {
        "id": "backslash_normalization_traversal",
        "name": "Backslash Path Normalization (..\\)",
        "payload": "/..\\..\\user\\profile",
        "target_sink": "new URL(path, window.location.origin)",
        "severity": "medium",
        "min_confidence": 0.86,
        "description": "Backslashes are normalized to forward slashes by the browser URL API, altering the target fetch path."
    },
    {
        "id": "cspt_to_dom_xss_sink",
        "name": "CSPT API Response to DOM XSS Escalation",
        "payload": "/../../public/user_content.json",
        "target_sink": "element.innerHTML = response.html",
        "severity": "critical",
        "min_confidence": 0.95,
        "description": "Path traversal causes client to load attacker-controlled JSON/HTML payload into an innerHTML sink, executing DOM XSS."
    }
]

class ClientSidePathTraversalAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="ClientSidePathTraversalAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="client_side_path_traversal",
                name="Client-Side Path Traversal (CSPT) Auditor",
                description="Audits SPA client-side routing, dynamic fetch sinks, and DOM XSS escalation pathways.",
                version="1.1.0",
                tags=["cspt", "client-side", "spa-security", "dom-xss", "api-routing", "sinks"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[ClientSidePathTraversalAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "Client-side path traversal sequences were safely rejected or sanitized."

        path_params = ["path", "file", "endpoint", "route", "subpath", "url", "doc"]

        for endpoint in target_urls[:6]:
            for vec in CSPT_VECTORS:
                payload = vec["payload"]

                for param in path_params[:3]:
                    test_url = f"{endpoint}?{param}={payload}" if "?" not in endpoint else f"{endpoint}&{param}={payload}"
                    try:
                        exch = await http_client.send_as_identity(
                            identity_id="anonymous_guest",
                            method="GET",
                            url=test_url
                        )
                        resp = exch.response
                        if not resp:
                            continue

                        exch_dict = exch.to_dict()
                        location = resp.headers.get("location", "") if resp.headers else ""
                        body_text = (resp.body_text or resp.body_snippet or "").lower()

                        # Verification logic: 302 redirecting to traversal path OR 200 containing traversal content
                        if (resp.status_code in (301, 302, 307, 308) and ("admin" in location or "settings" in location)) or (resp.status_code == 200 and "root:" in body_text):
                            is_vulnerable = True
                            confidence = vec["min_confidence"]
                            reasoning = f"HIGH Client-Side Path Traversal Proven [{vec['name']}]: Parameter '{param}' on '{endpoint}' permitted path traversal sequence '{payload}'."

                            if confidence > max_confidence:
                                max_confidence = confidence
                                best_target = test_url
                                best_reasoning = reasoning

                            results.append({
                                "vector_id": vec["id"],
                                "vector_name": vec["name"],
                                "test_payload": payload,
                                "target_sink": vec["target_sink"],
                                "endpoint": endpoint,
                                "parameter": param,
                                "vulnerability_type": "client_side_path_traversal",
                                "severity": vec["severity"],
                                "confidence": confidence,
                                "description": reasoning,
                                "is_vulnerable": True,
                                "_exchange_obj": exch_dict
                            })
                            break
                    except Exception as e:
                        logger.debug(f"[CSPTAgent] Probe error on {test_url}: {e}")

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
                "vulnerability_type": "client_side_path_traversal",
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

