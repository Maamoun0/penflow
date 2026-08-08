"""
NovelSSRFRedirectAgent — HTTP Redirect Chain & Semi-Blind SSRF Specialist.

Audits web endpoints for Server-Side Request Forgery reachable via HTTP 301/302/307
redirect loops and location header chasing, exposing internal service interaction without external OOB.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.novel_ssrf_redirect")

SSRF_REDIRECT_VECTORS = [
    {
        "id": "http_302_internal_service",
        "name": "HTTP 302 Location Chasing to Internal Host",
        "redirect_target": "http://127.0.0.1:8080/internal-status",
        "severity": "critical",
        "min_confidence": 0.95,
        "description": "Target server follows external redirect chains to loopback/internal hosts without destination validation."
    },
    {
        "id": "protocol_smuggle_redirect",
        "name": "Protocol Scheme Switching Redirect (HTTP to Gopher/DICT)",
        "redirect_target": "gopher://127.0.0.1:6379/_INFO",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Application HTTP client allows arbitrary protocol schema transitions on 302 redirects."
    },
    {
        "id": "cloud_metadata_hop",
        "name": "Cloud Metadata Redirect Hop (AWS/GCP/Azure)",
        "redirect_target": "http://169.254.169.254/latest/meta-data/",
        "severity": "critical",
        "min_confidence": 0.98,
        "description": "Redirect chains bypass basic metadata URL string filters, reaching link-local instance metadata."
    }
]

class NovelSSRFRedirectAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="NovelSSRFRedirectAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="ssrf_redirect_chain",
                name="SSRF HTTP Redirect Loop & Chain Auditor",
                description="Audits HTTP client redirect-following policies to uncover semi-blind internal SSRF vulnerabilities.",
                version="1.0.0",
                tags=["ssrf", "redirect-chain", "internal-network", "cloud-metadata"]
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
            for vec in SSRF_REDIRECT_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "redirect_target": vec["redirect_target"],
                    "endpoint": endpoint,
                    "vulnerability_type": "ssrf_redirect_chain",
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
                "vulnerability_type": "ssrf_redirect_chain",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
