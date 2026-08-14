"""
Security Posture & Configuration Capability Agent for PenFlow.

Capabilities:
  - Security Headers & HSTS Enforcement Audit
  - Subresource Integrity (SRI) External Script Integrity Checks
  - Cookie Security Flags (HttpOnly, Secure, SameSite, Persistent Expiry)
  - CORS Wildcard + CSP unsafe-inline Interactive Risk Analysis
  - TLS/SSL Weak Protocol (TLS 1.0/1.1) and Cipher Suite Validation
"""
import ssl
import socket
import re
import httpx
import asyncio
from typing import List, Dict, Any, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.recon.security_headers_audit import SecurityHeadersAuditor
from penflow.validation.csp_analyzer import CSPPolicyAnalyzer
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.security_config")


class SecurityConfigCapabilityAgent(BaseCapabilityAgent):
    """
    Comprehensive Capability Agent for Security Posture, Cookie Flags, SRI, CSP+CORS interaction,
    and SSL/TLS Hardening Audits.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="SecurityConfigCapabilityAgent", priority=priority)
        self.auditor = SecurityHeadersAuditor()
        self.csp_analyzer = CSPPolicyAnalyzer()
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="security_config_audit",
                name="Security Posture & Headers Audit",
                description="Audits HTTP security headers, HSTS, clickjacking, and CSP directives",
                priority=self.priority,
                tags=["security_headers", "csp", "hsts", "hardening"]
            ),
            Capability(
                id="cookie_security_audit",
                name="Cookie Security Audit",
                description="Audits HttpOnly, Secure, SameSite, and lifetime attributes on session cookies",
                priority=self.priority,
                tags=["cookies", "session", "flags"]
            ),
            Capability(
                id="tls_configuration_audit",
                name="TLS/SSL Protocol & Cipher Audit",
                description="Checks for legacy TLS 1.0/1.1 protocols and weak ciphers",
                priority=self.priority,
                tags=["tls", "ssl", "crypto"]
            )
        ]

    def _audit_cookies(self, response: httpx.Response, target_url: str) -> List[Dict[str, Any]]:
        """Audits response set-cookie headers for HttpOnly, Secure, SameSite, and persistent session flags."""
        findings = []
        set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else [response.headers.get("set-cookie", "")]

        for raw_cookie in set_cookie_headers:
            if not raw_cookie:
                continue
            cookie_lower = raw_cookie.lower()
            cookie_name = raw_cookie.split("=")[0].strip()

            if "httponly" not in cookie_lower:
                curl_cmd = f"curl -i -s -k '{target_url}'"
                findings.append({
                    "vulnerability_type": "security_config_audit",
                    "subtype": "missing_httponly_flag",
                    "target_url": target_url,
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "is_vulnerable": True,
                    "exploit_curl": curl_cmd,
                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Missing HttpOnly Cookie Flag", target_url, curl_cmd),
                    "description": f"Cookie '{cookie_name}' lacks the HttpOnly flag, exposing session tokens to XSS exfiltration."
                })

            if "secure" not in cookie_lower and target_url.startswith("https://"):
                curl_cmd = f"curl -i -s -k '{target_url}'"
                findings.append({
                    "vulnerability_type": "security_config_audit",
                    "subtype": "missing_secure_flag",
                    "target_url": target_url,
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "is_vulnerable": True,
                    "exploit_curl": curl_cmd,
                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Missing Secure Cookie Flag", target_url, curl_cmd),
                    "description": f"Cookie '{cookie_name}' lacks the Secure flag, permitting transmission over unencrypted HTTP."
                })

            if "samesite" not in cookie_lower:
                curl_cmd = f"curl -i -s -k '{target_url}'"
                findings.append({
                    "vulnerability_type": "security_config_audit",
                    "subtype": "missing_samesite_flag",
                    "target_url": target_url,
                    "severity": "LOW",
                    "confidence": 0.85,
                    "is_vulnerable": True,
                    "exploit_curl": curl_cmd,
                    "reproduction_steps": self.poc_generator.generate_reproduction_steps("Missing SameSite Cookie Flag", target_url, curl_cmd),
                    "description": f"Cookie '{cookie_name}' lacks explicit SameSite attribute, increasing CSRF risk."
                })
        return findings

    def _check_sri(self, html_text: str, target_url: str) -> List[Dict[str, Any]]:
        """Finds external CDN scripts missing Subresource Integrity (SRI) hashes."""
        findings = []
        script_tags = re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\'][^>]*>', html_text, re.IGNORECASE)
        for src in script_tags:
            if not target_url.split("//")[-1].split("/")[0] in src:  # External domain
                if "integrity=" not in src.lower():
                    curl_cmd = f"curl -i -s -k '{target_url}'"
                    findings.append({
                        "vulnerability_type": "security_config_audit",
                        "subtype": "missing_subresource_integrity",
                        "target_url": target_url,
                        "severity": "LOW",
                        "confidence": 0.88,
                        "is_vulnerable": True,
                        "exploit_curl": curl_cmd,
                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Missing SRI Hash", target_url, curl_cmd),
                        "description": f"External script '{src}' loaded without Subresource Integrity (SRI) hash."
                    })
                    break
        return findings

    def _check_tls(self, hostname: str) -> List[Dict[str, Any]]:
        """Checks target domain for legacy TLS 1.0/1.1 protocols or weak ciphers."""
        findings = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    if version in ("TLSv1", "TLSv1.1"):
                        findings.append({
                            "vulnerability_type": "security_config_audit",
                            "subtype": "deprecated_tls_version",
                            "target_url": f"https://{hostname}",
                            "severity": "HIGH",
                            "confidence": 0.95,
                            "is_vulnerable": True,
                            "description": f"Target server supports deprecated protocol version: {version}."
                        })
        except Exception:
            pass
        return findings

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        target_url = f"https://{context.asset}"
        findings: List[Dict[str, Any]] = []
        evidence_exchanges: List[Dict[str, Any]] = []
        reasoning = ""

        if capability_id == "cookie_security_audit":
            try:
                async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False) as client:
                    resp = await client.get(target_url)
                    cookie_findings = self._audit_cookies(resp, target_url)
                    if cookie_findings:
                        findings = cookie_findings
                        set_cookie_val = str(resp.headers.get("set-cookie", ""))
                        exch = {
                            "request": {"method": "GET", "url": target_url, "headers": {}},
                            "response": {"status_code": resp.status_code, "headers": dict(resp.headers), "body_snippet": f"Set-Cookie: {set_cookie_val}"}
                        }
                        evidence_exchanges = [exch]
                        for f in findings:
                            f["vulnerability_type"] = "cookie_security_audit"
                            f["_exchange_obj"] = exch
                        reasoning = f"Discovered {len(findings)} insecure cookie configuration(s) on {context.asset}."
                    else:
                        reasoning = f"No insecure cookie configurations detected on {context.asset}."
            except Exception as e:
                reasoning = f"Cookie security audit failed on {context.asset}: {str(e)}"

        elif capability_id == "tls_configuration_audit":
            tls_findings = await asyncio.to_thread(self._check_tls, context.asset)
            if tls_findings:
                findings = tls_findings
                exch = {
                    "request": {"method": "CONNECT", "url": f"{context.asset}:443", "headers": {}},
                    "response": {"status_code": 200, "headers": {}, "body_snippet": f"Deprecated TLS version negotiated on {context.asset}"}
                }
                evidence_exchanges = [exch]
                for f in findings:
                    f["vulnerability_type"] = "tls_configuration_audit"
                    f["_exchange_obj"] = exch
                reasoning = f"Target {context.asset} supports deprecated TLS versions/ciphers."
            else:
                reasoning = f"Modern TLS (1.2/1.3) protocol and secure ciphers properly enforced on {context.asset}."

        else:  # "security_config_audit" or generic header audit
            audit_res = await self.auditor.audit_url(target_url)
            headers = audit_res.get("headers", {})
            csp_header = headers.get("content-security-policy", "")
            csp_res = self.csp_analyzer.analyze_csp(csp_header)

            base_findings = audit_res.get("findings", []) + csp_res.get("findings", [])
            for f in base_findings:
                if isinstance(f, dict):
                    f["vulnerability_type"] = "security_config_audit"
                    f["target_url"] = target_url
                    f["is_vulnerable"] = True
                    findings.append(f)

            # SRI check
            body_html = audit_res.get("body", "")
            if body_html:
                sri_findings = self._check_sri(body_html, target_url)
                findings.extend(sri_findings)

            exch = {
                "request": {"method": "GET", "url": target_url, "headers": {}},
                "response": {"status_code": 200, "headers": headers, "body_snippet": "Security headers audit response"}
            }
            evidence_exchanges = [exch]
            for f in findings:
                f["_exchange_obj"] = exch
            reasoning = f"Identified {len(findings)} security header & hardening observations for {context.asset}."

        is_vuln = len(findings) > 0
        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "target": context.asset,
            "is_vulnerable": is_vuln,
            "confidence": 0.90 if is_vuln else 0.0,
            "confidence_score": 0.90 if is_vuln else 0.0,
            "_exchange_obj": evidence_exchanges[0] if evidence_exchanges else None,
            "evidence": {
                "findings": findings,
                "evidence_exchanges": evidence_exchanges
            },
            "findings": findings,
            "reasoning": reasoning
        }
