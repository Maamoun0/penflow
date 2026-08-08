import json
import base64
import time
from typing import Dict, Optional, List, Any, Callable
from penflow.traffic.models import Identity, IdentityType, AuthCredentials
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.session_manager")


class SessionManager:
    """
    Manages multiple authenticated identities and session contexts with JWT auto-refresh
    and registered re-authentication callbacks to maintain active credentials during long scans.
    """
    def __init__(self):
        self._identities: Dict[str, Identity] = {}
        self._refresh_callbacks: Dict[str, Callable[[], Optional[str]]] = {}
        self._initialize_default_guest()

    def _initialize_default_guest(self) -> None:
        guest = Identity(
            id="anonymous_guest",
            name="Unauthenticated Guest",
            identity_type=IdentityType.UNAUTHENTICATED_GUEST,
            credentials=AuthCredentials(),
            metadata={"role": "guest"}
        )
        self._identities[guest.id] = guest

    def register_refresh_callback(self, identity_id: str, callback: Callable[[], Optional[str]]) -> None:
        """Registers an automated re-authentication callback for a given identity."""
        self._refresh_callbacks[identity_id] = callback
        logger.info(f"[SessionManager] Registered JWT refresh callback for identity '{identity_id}'")

    def is_jwt_expired(self, token: str) -> bool:
        """Parses JWT exp claim and checks if the token has expired."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return False
            payload_b64 = parts[1]
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")))
            exp = decoded.get("exp")
            if exp and isinstance(exp, (int, float)):
                return time.time() >= (exp - 10.0) # 10s grace window
        except Exception as e:
            logger.debug(f"[SessionManager] JWT parsing error: {e}")
        return False

    def refresh_identity(self, identity_id: str) -> bool:
        """Executes the registered refresh callback to acquire a new active token."""
        if identity_id in self._refresh_callbacks:
            try:
                new_token = self._refresh_callbacks[identity_id]()
                if new_token:
                    ident = self._identities.get(identity_id)
                    if ident and ident.credentials:
                        clean_token = new_token.replace("Bearer ", "").strip()
                        ident.credentials.bearer_token = clean_token
                        ident.credentials.headers["Authorization"] = f"Bearer {clean_token}"
                        ident.is_active = True
                        logger.info(f"[SessionManager] Successfully auto-refreshed JWT for identity '{identity_id}'")
                        return True
            except Exception as e:
                logger.error(f"[SessionManager] Exception during identity refresh for '{identity_id}': {e}")
        return False

    def register_identity(self, identity: Identity) -> None:
        self._identities[identity.id] = identity
        logger.info(f"[SessionManager] Registered identity '{identity.id}' ({identity.identity_type.value})")

    def create_identity(
        self,
        identity_id: str,
        identity_type: IdentityType,
        name: Optional[str] = None,
        bearer_token: Optional[str] = None,
        api_key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Identity:
        creds = AuthCredentials(
            headers=headers or {},
            cookies=cookies or {},
            bearer_token=bearer_token,
            api_key=api_key
        )
        ident = Identity(
            id=identity_id,
            name=name or identity_id,
            identity_type=identity_type,
            credentials=creds,
            metadata=metadata or {}
        )
        self.register_identity(ident)
        return ident

    def get_identity(self, identity_id: str) -> Optional[Identity]:
        ident = self._identities.get(identity_id)
        if ident and ident.credentials and ident.credentials.bearer_token:
            if self.is_jwt_expired(ident.credentials.bearer_token):
                logger.warning(f"[SessionManager] JWT expired for identity '{identity_id}'. Attempting auto-refresh...")
                if not self.refresh_identity(identity_id):
                    ident.is_active = False
        return ident

    def get_identity_by_type(self, identity_type: IdentityType) -> Optional[Identity]:
        for ident in self._identities.values():
            if ident.identity_type == identity_type:
                if ident.credentials and ident.credentials.bearer_token and self.is_jwt_expired(ident.credentials.bearer_token):
                    if not self.refresh_identity(ident.id):
                        ident.is_active = False
                        continue
                if ident.is_active:
                    return ident
        return None

    def list_identities(self) -> List[Identity]:
        return list(self._identities.values())

    def get_headers_for(self, identity_id: Optional[str]) -> Dict[str, str]:
        if not identity_id:
            return {}
        ident = self.get_identity(identity_id)
        if not ident or not ident.is_active:
            return {}
        return ident.credentials.get_effective_headers()

    def get_cookies_for(self, identity_id: Optional[str]) -> Dict[str, str]:
        if not identity_id:
            return {}
        ident = self.get_identity(identity_id)
        if not ident or not ident.is_active:
            return {}
        return dict(ident.credentials.cookies)

    def has_multi_tenant_pair(self) -> bool:
        has_a = any(i.identity_type == IdentityType.STANDARD_USER_A for i in self._identities.values())
        has_b = any(i.identity_type == IdentityType.STANDARD_USER_B for i in self._identities.values())
        if has_a and has_b:
            return True
        non_guests = [i for i in self._identities.values() if i.identity_type != IdentityType.UNAUTHENTICATED_GUEST and i.is_active]
        return len(non_guests) >= 2

    def configure_authenticated_session(
        self,
        bearer_token: Optional[str] = None,
        cookie_header: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        refresh_callback: Optional[Callable[[], Optional[str]]] = None
    ) -> Identity:
        headers = dict(custom_headers or {})
        cookies = {}

        if bearer_token:
            clean_token = bearer_token.replace("Bearer ", "").strip()
            headers["Authorization"] = f"Bearer {clean_token}"

        if cookie_header:
            headers["Cookie"] = cookie_header
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k] = v

        ident = self.create_identity(
            identity_id="authenticated_user_a",
            identity_type=IdentityType.STANDARD_USER_A,
            name="Authenticated User Session A",
            bearer_token=bearer_token,
            headers=headers,
            cookies=cookies
        )
        if refresh_callback:
            self.register_refresh_callback(ident.id, refresh_callback)

        logger.info(f"[SessionManager] Configured authenticated user session (Token: {bool(bearer_token)}, Cookie: {bool(cookie_header)}, RefreshCallback: {bool(refresh_callback)})")
        return ident
