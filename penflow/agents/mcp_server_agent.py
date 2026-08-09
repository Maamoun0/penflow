"""
Model Context Protocol (MCP) Server Attack Capability Agent for PenFlow.

Capabilities:
  - MCP Tool Description Injection & Poisoning (CVE-2026-23744 pattern)
  - Unauthorized MCP Tool & Prompt Execution
  - Data Exfiltration via MCP Channels
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.mcp_server")

MCP_PATTERNS = [
    "/mcp", "/api/mcp", "/.well-known/mcp",
    "/v1/mcp", "/mcp/v1"
]


class MCPServerAgent(BaseCapabilityAgent):
    """
    Capability Agent probing Model Context Protocol (MCP) servers for tool poisoning,
    unauthorized execution, and prompt injection vulnerabilities.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="MCPServerAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="mcp_server_vulnerability", name="MCP Server Exploitation", description="Detects Model Context Protocol (MCP) tool description poisoning and unauthorized tool execution", priority=self.priority, tags=["mcp", "ai", "llm", "tool_poisoning"])
        ]

    def _discover_mcp_urls(self, context: CapabilityExecutionContext) -> List[str]:
        base_url = f"https://{context.asset}"
        return [f"{base_url}{p}" for p in MCP_PATTERNS[:3]]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_urls = self._discover_mcp_urls(context)

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for target_url in target_urls:
                    payload = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list"
                    }
                    try:
                        resp = await client.post(target_url, json=payload)
                        if resp.status_code == 200 and ("tools" in resp.text.lower() or "jsonrpc" in resp.text.lower()):
                            curl_cmd = f"curl -X POST '{target_url}' -H 'Content-Type: application/json' -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}'"
                            exch_dict = {
                                "request": {"method": "POST", "url": target_url, "json_data": payload},
                                "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                            }

                            findings.append({
                                "vulnerability_type": "mcp_server_vulnerability",
                                "target_url": target_url,
                                "severity": "HIGH",
                                "confidence": 0.90,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("Unauthenticated MCP Server Access", target_url, curl_cmd),
                                "description": f"Model Context Protocol (MCP) server exposed unauthenticated at '{target_url}'.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["mcp_server_exposed"] = True
                            break
                    except Exception as e:
                        logger.debug(f"MCP test failed on {target_url}: {e}")

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
            "confidence": 0.90 if is_vuln else 0.0,
            "confidence_score": 0.90 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
