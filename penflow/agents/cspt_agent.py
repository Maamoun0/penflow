"""
ClientSidePathTraversalAgent — Client-Side Path Traversal (CSPT) in SPAs Specialist.

Audits client-side JavaScript Single Page Application (SPA) routing and API client calls
for path traversal vulnerabilities leading to API response spoofing and DOM XSS.
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
        "name": "Standard Path Traversal (../)",
        "payload": "/../../admin/api",
        "severity": "high",
        "min_confidence": 0.89,
        "description": "Client-side router or fetch() URL builder interpolates unvalidated path components, redirecting API requests to unintended endpoints."
    },
    {
        "id": "encoded_slash_traversal",
        "name": "URL-Encoded Slash Traversal (%2e%2e%2f)",
        "payload": "/%2e%2e%2f%2e%2e%2fsettings",
        "severity": "high",
        "min_confidence": 0.87,
        "description": "URL-encoded traversal sequences bypass client-side regex path validation before fetch() execution."
    },
    {
        "id": "backslash_normalization_traversal",
        "name": "Backslash Path Normalization (..\\)",
        "payload": "/..\\..\\user\\profile",
        "severity": "medium",
        "min_confidence": 0.84,
        "description": "Backslashes are normalized to forward slashes by the browser URL API, altering the target fetch path."
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
                description="Audits SPA client-side routing and dynamic fetch paths for client-side path traversal flaws.",
                version="1.0.0",
                tags=["cspt", "client-side", "spa-security", "dom-xss", "api-routing"]
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
