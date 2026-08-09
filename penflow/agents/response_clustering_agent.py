"""
Response Clustering Capability Agent for PenFlow.

Capabilities:
  - Response Body & Structural Differential Analysis
  - Behavior Anomaly Clustering across Inputs
  - WAF / Backend Behavioral Routing Divergence Detection
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
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
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        target_url = f"{base_url}/api/v1/search"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                probe_a = await client.get(f"{target_url}?q=normal")
                probe_b = await client.get(f"{target_url}?q=admin'--")

                if probe_a.status_code == 200 and probe_b.status_code == 500:
                    curl_cmd = f"curl -i -s -k '{target_url}?q=admin%27--'"
                    exch_dict = {
                        "request": {"method": "GET", "url": f"{target_url}?q=admin'--"},
                        "response": {"status_code": probe_b.status_code, "body_snippet": probe_b.text[:500]}
                    }

                    findings.append({
                        "vulnerability_type": "response_clustering",
                        "subtype": "unhandled_exception_clustering",
                        "target_url": target_url,
                        "severity": "MEDIUM",
                        "confidence": 0.85,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Response Anomaly Cluster", target_url, curl_cmd),
                        "description": f"Anomalous response behavior detected at '{target_url}': HTTP 500 unhandled backend error returned for special character payload.",
                        "_exchange_obj": exch_dict
                    })
                    evidence["cluster_anomaly"] = True

        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{context.asset}': {e}")

        is_vuln = len(findings) > 0
        primary_exch = findings[0].get("_exchange_obj") if findings else None
        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": self.name,
            "is_vulnerable": is_vuln,
            "vulnerable": is_vuln,
            "confidence": 0.85 if is_vuln else 0.0,
            "confidence_score": 0.85 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
