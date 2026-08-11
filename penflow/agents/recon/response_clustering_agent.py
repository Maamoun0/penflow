"""
Response Clustering Capability Agent for PenFlow.

Capabilities:
  - Response Body & Structural Differential Analysis
  - Behavior Anomaly Clustering across Inputs
  - WAF / Backend Behavioral Routing Divergence Detection
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.response_clustering")


class ResponseClusteringAgent(BaseCapabilityAgent):
    """
    Capability Agent performing behavioral response clustering to detect anomalous backend handling.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="ResponseClusteringAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="response_clustering", name="Response Clustering Analysis", description="Clusters response structures to isolate backend handling anomalies", priority=self.priority, tags=["behavioral", "clustering", "recon"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        probes = [
            {"id": "normal", "param": "q=normal_user_input", "type": "baseline"},
            {"id": "sqli", "param": "q=admin'--", "type": "injection"},
            {"id": "xss", "param": "q=<script>alert(1)</script>", "type": "xss"},
            {"id": "traversal", "param": "q=../../../../etc/passwd", "type": "traversal"},
            {"id": "timing", "param": "q=SLEEP(5)", "type": "timing"},
        ]

        for target_url in target_urls[:6]:
            try:
                responses = {}
                exchanges = []

                for p in probes:
                    test_url = f"{target_url}?{p['param']}" if "?" not in target_url else f"{target_url}&{p['param']}"
                    exch = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=test_url)
                    resp = exch.response
                    if resp:
                        responses[p["id"]] = {
                            "status": resp.status_code,
                            "length": len(resp.body_text or resp.body_snippet or ""),
                            "body": (resp.body_text or resp.body_snippet or "")[:300],
                            "headers": resp.headers or {}
                        }
                        exchanges.append(exch.to_dict())

                if "normal" in responses:
                    norm = responses["normal"]
                    # Cluster analysis: detect status anomalies or unhandled errors in probes compared to baseline
                    for pid, data in responses.items():
                        if pid == "normal":
                            continue

                        # 1. Unhandled 500 error anomaly
                        if norm["status"] == 200 and data["status"] == 500:
                            curl_cmd = f"curl -i -s -k '{target_url}?{probes[1]['param']}'"
                            findings.append({
                                "vulnerability_type": "response_clustering",
                                "subtype": f"unhandled_{pid}_clustering",
                                "target_url": target_url,
                                "probe_type": pid,
                                "severity": "MEDIUM",
                                "confidence": 0.85,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("Response Anomaly Cluster", target_url, curl_cmd),
                                "description": f"Anomalous response behavior detected at '{target_url}': HTTP 500 error triggered for '{pid}' payload probe while baseline returns HTTP 200.",
                                "_exchange_obj": exchanges[0] if exchanges else {}
                            })
                            evidence["cluster_anomaly"] = True
                            break

                        # 2. Structural size anomaly (>200% size jump)
                        elif norm["status"] == 200 and data["status"] == 200 and data["length"] > (norm["length"] * 2.0) and norm["length"] > 0:
                            curl_cmd = f"curl -i -s -k '{target_url}?{probes[1]['param']}'"
                            findings.append({
                                "vulnerability_type": "response_clustering",
                                "subtype": f"data_expansion_{pid}_clustering",
                                "target_url": target_url,
                                "probe_type": pid,
                                "severity": "HIGH",
                                "confidence": 0.88,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("Response Data Expansion Cluster", target_url, curl_cmd),
                                "description": f"Significant response size differential ({data['length']} bytes vs baseline {norm['length']} bytes) detected for '{pid}' probe on '{target_url}'.",
                                "_exchange_obj": exchanges[0] if exchanges else {}
                            })
                            evidence["cluster_anomaly"] = True
                            break
            except Exception as e:
                logger.debug(f"[{self.name}] Exception testing '{target_url}': {e}")

        is_vuln = len(findings) > 0
        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=0.88 if is_vuln else 0.0,
            reasoning=findings[0]["description"] if findings else "Response structure clustering evaluated safely across inputs.",
            target_url=target_urls[0] if target_urls else f"https://{context.asset}",
            findings=findings,
            evidence={
                "cluster_anomaly": is_vuln,
                "findings": findings,
                "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")]
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

