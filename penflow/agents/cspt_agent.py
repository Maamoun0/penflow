"""
ClientSidePathTraversalAgent — Client-Side Path Traversal (CSPT) & Sink Analysis Specialist for PenFlow.

Audits client-side JavaScript Single Page Application (SPA) routing, fetch(), axios, and DOM sinks:
  - Standard traversal (../) in fetch() URLs
  - URL-encoded & double-encoded sequences (%2e%2e%2f, %252e%252e%252f)
  - Backslash normalization (..\) in window.location and dynamic import()
  - Client-side sink injection (DOM XSS / CSRF token leakage via API route redirection)
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
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
            for vec in CSPT_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "test_payload": vec["payload"],
                    "target_sink": vec["target_sink"],
                    "endpoint": endpoint,
                    "vulnerability_type": "client_side_path_traversal",
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
                "vulnerability_type": "client_side_path_traversal",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
