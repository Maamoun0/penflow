"""
Auto-Login & Auth Replay Engine for PenFlow.

Automates target authentication, extracts dynamic Bearer tokens & session cookies,
and registers active authenticated identities into SessionManager.
"""
import httpx
from typing import Dict, Any, Optional
from penflow.traffic.session_manager import SessionManager
from penflow.traffic.models import IdentityType
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.auto_login_engine")


class AutoLoginEngine:
    """
    Automated Login & Session Replay Handler.
    """

    def __init__(self, session_manager: Optional[SessionManager] = None):
        self.session_manager = session_manager or SessionManager()

    async def authenticate_user(
        self,
        login_url: str,
        username: str,
        password: str,
        identity_id: str = "authenticated_user_a",
        username_field: str = "username",
        password_field: str = "password"
    ) -> Optional[Dict[str, Any]]:
        """Sends POST request to login URL, extracts Bearer token or Cookie, and binds identity."""
        payload = {
            username_field: username,
            password_field: password
        }

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.post(login_url, json=payload)
                
                # Check JSON response for token
                bearer_token = None
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        bearer_token = data.get("token") or data.get("access_token") or data.get("jwt")
                    except Exception:
                        pass

                # Extract cookies
                cookies = dict(resp.cookies)
                cookie_header = "; ".join([f"{k}={v}" for k, v in cookies.items()]) if cookies else None

                headers = {}
                if bearer_token:
                    headers["Authorization"] = f"Bearer {bearer_token}"
                if cookie_header:
                    headers["Cookie"] = cookie_header

                if resp.status_code in (200, 201, 302):
                    ident_type = IdentityType.STANDARD_USER_A if identity_id == "authenticated_user_a" else IdentityType.STANDARD_USER_B
                    ident = self.session_manager.create_identity(
                        identity_id=identity_id,
                        identity_type=ident_type,
                        name=f"Auto-Logged Identity ({username})",
                        bearer_token=bearer_token,
                        headers=headers,
                        cookies=cookies
                    )
                    logger.info(f"[AutoLoginEngine] Successfully authenticated '{username}' against '{login_url}'. Identity registered.")
                    return {
                        "status": "SUCCESS",
                        "identity_id": identity_id,
                        "bearer_token": bearer_token,
                        "cookies": cookies
                    }
                else:
                    logger.warning(f"[AutoLoginEngine] Authentication failed for '{username}' (Status {resp.status_code}).")
        except Exception as e:
            logger.error(f"[AutoLoginEngine] Error during login request to '{login_url}': {e}")

        return None
