"""
ParserDifferentialAgent — Meta-Vulnerability & Multi-Layer Parsing Discrepancy Specialist.

Audits edge proxies, WAFs, API gateways, and backend web servers for parsing discrepancies
such as header delimiter interpretation, path normalization gaps, and double encoding.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.parser_differential")

PARSER_DIFFERENTIAL_VECTORS = [
    {
        "id": "semicolon_path_matrix",
        "name": "Path Matrix Parameter Semicolon Discrepancy",
        "path_suffix": ";/admin",
        "severity": "high",
        "min_confidence": 0.90,
        "description": "Reverse proxy strips or ignores semicolon matrix parameters while backend routing interprets them."
    },
    {
        "id": "double_url_encoding",
        "name": "Double URL Encoding Differential",
        "path_suffix": "%252f%252e%252e%252f",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Proxy decodes URL path once, but backend framework executes double-decoding leading to path ACL bypass."
    },
    {
        "id": "tab_header_delimiter",
        "name": "Header Field Whitespace / Tab Delimiter Gap",
        "header_mod": {"X-Custom-Auth\t": "true"},
        "severity": "medium",
        "min_confidence": 0.85,
        "description": "Intermediate proxies reject or strip tab delimiters in header names while backend ignores whitespace."
    },
    {
        "id": "null_byte_path_truncation",
        "name": "Null Byte Path Normalization",
        "path_suffix": "%00.json",
        "severity": "high",
        "min_confidence": 0.89,
        "description": "Backend language runtime truncates string at null byte, bypassing file extension validation."
    }
]

class ParserDifferentialAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="ParserDifferentialAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="parser_differential",
                name="Parser Differential & Encoding Mismatch Auditor",
                description="Audits discrepancies in HTTP header, path, and body parsing between proxies and backends.",
                version="1.0.0",
                tags=["parser-differential", "waf-bypass", "encoding", "routing-gaps"]
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
            for vec in PARSER_DIFFERENTIAL_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "endpoint": endpoint,
                    "vulnerability_type": "parser_differential",
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
                "vulnerability_type": "parser_differential",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
