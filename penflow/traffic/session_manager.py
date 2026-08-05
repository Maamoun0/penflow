from typing import Dict, Optional, List, Any
from penflow.traffic.models import Identity, IdentityType, AuthCredentials
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.session_manager")

class SessionManager:
    """
    Manages multiple authenticated identities and session contexts
    to enable stateful cross-user authorization (IDOR/BOLA/BFLA) testing.
    """
    def __init__(self):
        self._identities: Dict[str, Identity] = {}
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
        return self._identities.get(identity_id)

    def get_identity_by_type(self, identity_type: IdentityType) -> Optional[Identity]:
        for ident in self._identities.values():
            if ident.identity_type == identity_type and ident.is_active:
                return ident
        return None

    def list_identities(self) -> List[Identity]:
        return list(self._identities.values())

    def get_headers_for(self, identity_id: Optional[str]) -> Dict[str, str]:
        if not identity_id:
            return {}
        ident = self.get_identity(identity_id)
        if not ident:
            return {}
        return ident.credentials.get_effective_headers()

    def get_cookies_for(self, identity_id: Optional[str]) -> Dict[str, str]:
        if not identity_id:
            return {}
        ident = self.get_identity(identity_id)
        if not ident:
            return {}
        return dict(ident.credentials.cookies)

    def has_multi_tenant_pair(self) -> bool:
        """
        Returns True if at least two distinct user accounts (or User A and User B) are configured.
        """
        has_a = any(i.identity_type == IdentityType.STANDARD_USER_A for i in self._identities.values())
        has_b = any(i.identity_type == IdentityType.STANDARD_USER_B for i in self._identities.values())
        if has_a and has_b:
            return True
        # Or any 2 active non-guest identities
        non_guests = [i for i in self._identities.values() if i.identity_type != IdentityType.UNAUTHENTICATED_GUEST and i.is_active]
        return len(non_guests) >= 2
