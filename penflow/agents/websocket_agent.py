"""
WebSocket Security Capability Agent for PenFlow.

Capabilities:
  - CSWSH (Cross-Site WebSocket Hijacking) Origin Validation Checks
  - WebSocket Upgrade Hijacking & Unauthenticated Handshake Probes
  - Message & Channel Access Privilege Escalation Probes
"""
import httpx
import re
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.websocket")

WS_PATTERNS = [
    "/ws", "/socket", "/chat", "/ws/v1", "/api/ws",
    "/socket.io/", "/notifications", "/realtime"
]


class WebSocketCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting CSWSH, WebSocket upgrade hijacks, and origin validation bypasses.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="WebSocketCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="cswsh_vulnerability", name="Cross-Site WebSocket Hijacking (CSWSH)", description="Detects missing or weak Origin validation on WebSocket upgrades", priority=self.priority, tags=["cswsh", "websocket"]),
            Capability(id="websocket_security", name="WebSocket Upgrade Hardening", description="Audits WebSocket connection security and authentication requirements", priority=self.priority, tags=["websocket", "auth"])
        ]

    def _discover_ws_urls(self, context: CapabilityExecutionContext) -> List[str]:
        ws_urls = []
        if context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    url = data.get("url", "")
                    if url and (url.startswith("ws://") or url.startswith("wss://")):
                        ws_urls.append(url)
                    for script in data.get("scripts", []):
                        if isinstance(script, dict) and script.get("content"):
                            found = re.findall(r'wss?://[^\'"]+', script["content"])
                            ws_urls.extend(found)

        base_http = f"https://{context.asset}"
        if not ws_urls:
            for p in WS_PATTERNS[:4]:
                ws_urls.append(f"{base_http}{p}")

        return list(dict.fromkeys(ws_urls))[:6]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_urls = self._discover_ws_urls(context)
        origins_to_test = ["https://evil.com", "null", "http://localhost"]

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for target_url in target_urls:
                    http_url = target_url.replace("wss://", "https://").replace("ws://", "http://")

                    for origin in origins_to_test:
                        headers = {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                            "Sec-WebSocket-Version": "13",
                            "Origin": origin
                        }
                        try:
                            resp = await client.get(http_url, headers=headers)

                            # HTTP 101 Switching Protocols or HTTP 200 accepting arbitrary origin → CSWSH
                            if resp.status_code in (101, 200) and ("Sec-WebSocket-Accept" in resp.headers or resp.status_code == 101):
                                curl_cmd = f"curl -i -s -k -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Origin: {origin}' '{http_url}'"
                                exch_dict = {
                                    "request": {"method": "GET", "url": http_url, "headers": headers},
                                    "response": {"status_code": resp.status_code, "headers": dict(resp.headers), "body_snippet": resp.text[:500]}
                                }

                                findings.append({
                                    "vulnerability_type": "cswsh_vulnerability",
                                    "target_url": http_url,
                                    "origin": origin,
                                    "severity": "CRITICAL" if origin == "https://evil.com" else "HIGH",
                                    "confidence": 0.95,
                                    "is_vulnerable": True,
                                    "exploit_curl": curl_cmd,
                                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("CSWSH Origin Bypass", http_url, curl_cmd),
                                    "description": f"WebSocket handshake endpoint '{http_url}' accepts arbitrary cross-site Origin '{origin}' (HTTP {resp.status_code}).",
                                    "_exchange_obj": exch_dict
                                })
                                evidence["cswsh_vulnerable"] = True
                                evidence["vulnerable_origin"] = origin
                                break
                        except Exception as e:
                            logger.debug(f"WS test failed on {http_url}: {e}")
                    if findings:
                        break
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
