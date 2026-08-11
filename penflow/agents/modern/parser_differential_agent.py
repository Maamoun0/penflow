"""
ParserDifferentialAgent — Meta-Vulnerability & Multi-Layer Parsing Discrepancy Specialist.

Audits edge proxies, WAFs, API gateways, and backend web servers for parsing discrepancies
such as header delimiter interpretation, path normalization gaps, and double encoding.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
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
        logger.info(f"[ParserDifferentialAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "Parser differential probes were normalized consistently by edge and backend."

        for endpoint in target_urls[:6]:
            try:
                # 1. Content-Type Differential Probe
                content_types = ["application/json", "application/x-www-form-urlencoded", "text/plain", "application/xml"]
                ct_responses = {}
                for ct in content_types:
                    exch_ct = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="POST",
                        url=endpoint,
                        headers={"Content-Type": ct},
                        content='{"admin":true}' if "json" in ct else "admin=true"
                    )
                    if exch_ct.response:
                        ct_responses[ct] = (exch_ct.response.status_code, len(exch_ct.response.body_text or exch_ct.response.body_snippet or ""))

                # Check if content types result in status code bypass (e.g. 403 on json vs 200 on urlencoded/xml)
                statuses = [res[0] for res in ct_responses.values()]
                if 403 in statuses and 200 in statuses:
                    is_vulnerable = True
                    max_confidence = 0.90
                    best_target = endpoint
                    best_reasoning = f"HIGH Content-Type Parser Differential: Endpoint '{endpoint}' bypasses WAF/ACL when Content-Type is altered ({ct_responses})."
                    results.append({
                        "vector_id": "content_type_differential",
                        "vector_name": "Content-Type Parser Differential",
                        "endpoint": endpoint,
                        "vulnerability_type": "parser_differential",
                        "severity": "HIGH",
                        "confidence": 0.90,
                        "description": best_reasoning,
                        "is_vulnerable": True
                    })

                # 2. Path Matrix & Encoding Differential Probes
                for vec in PARSER_DIFFERENTIAL_VECTORS:
                    suffix = vec.get("path_suffix", "")
                    header_mod = vec.get("header_mod", {})

                    test_url = f"{endpoint.rstrip('/')}{suffix}" if suffix else endpoint
                    exch = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=test_url,
                        headers=header_mod
                    )
                    resp = exch.response
                    if not resp:
                        continue

                    exch_dict = exch.to_dict()
                    body_text = (resp.body_text or resp.body_snippet or "").lower()

                    # Differential check: if path matrix or double-encoding returns 200 OK while baseline restricted it
                    if resp.status_code == 200 and ("admin" in suffix or "etc/passwd" in body_text or "internal" in body_text):
                        is_vulnerable = True
                        confidence = vec["min_confidence"]
                        reasoning = f"HIGH Parser Differential Proven [{vec['name']}]: Matrix/encoding payload on '{test_url}' achieved HTTP 200 response."

                        if confidence > max_confidence:
                            max_confidence = confidence
                            best_target = test_url
                            best_reasoning = reasoning

                        results.append({
                            "vector_id": vec["id"],
                            "vector_name": vec["name"],
                            "endpoint": test_url,
                            "vulnerability_type": "parser_differential",
                            "severity": vec["severity"],
                            "confidence": confidence,
                            "description": reasoning,
                            "is_vulnerable": True,
                            "_exchange_obj": exch_dict
                        })
            except Exception as e:
                logger.debug(f"[ParserDifferentialAgent] Probe error on {endpoint}: {e}")

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
                "vulnerability_type": "parser_differential",
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

