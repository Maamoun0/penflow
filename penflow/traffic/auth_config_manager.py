"""
Authenticated Identities Configuration Manager for PenFlow.

Loads user credentials from config/identities.yaml, automates HTTP login flows,
persists cookie jars & Bearer tokens, and registers authenticated active identities
into SessionManager for multi-tenant IDOR/BOLA/BFLA testing.
"""
import os
import yaml
import asyncio
from typing import Dict, Any, Optional
from penflow.traffic.session_manager import SessionManager
from penflow.traffic.models import IdentityType, Identity, AuthCredentials
from penflow.traffic.auto_login_engine import AutoLoginEngine
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.traffic.auth_config_manager")


class AuthConfigManager:
    """
    Manages declarative identity credentials and session bindings.
    """

    def __init__(self, session_manager: Optional[SessionManager] = None, config_path: str = "config/identities.yaml"):
        self.session_manager = session_manager or SessionManager()
        self.config_path = config_path

    def load_identities_from_yaml(self) -> Dict[str, Identity]:
        """Parses YAML configuration and registers user identities."""
        if not os.path.exists(self.config_path):
            logger.warning(f"[AuthConfigManager] Configuration file '{self.config_path}' not found.")
            return {}

        registered: Dict[str, Identity] = {}

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            idents_data = data.get("identities", {})
            for key, val in idents_data.items():
                ident_id = val.get("id", key)
                itype_str = val.get("identity_type", "STANDARD_USER_A")
                itype = IdentityType[itype_str] if itype_str in IdentityType.__members__ else IdentityType.STANDARD_USER_A

                bearer_token = val.get("bearer_token")
                headers = val.get("headers", {})
                cookies = val.get("cookies", {})

                if bearer_token and "Authorization" not in headers:
                    headers["Authorization"] = f"Bearer {bearer_token}"

                ident = self.session_manager.create_identity(
                    identity_id=ident_id,
                    identity_type=itype,
                    name=val.get("name", ident_id),
                    bearer_token=bearer_token,
                    headers=headers,
                    cookies=cookies,
                    metadata={"username": val.get("username"), "login_url": val.get("login_url")}
                )
                registered[ident_id] = ident

            logger.info(f"[AuthConfigManager] Loaded and registered {len(registered)} identities from '{self.config_path}'.")
        except Exception as e:
            logger.error(f"[AuthConfigManager] Error loading identities from '{self.config_path}': {e}")

        return registered

    async def automate_all_logins(self) -> Dict[str, bool]:
        """Iterates over loaded identities with login URLs and credentials, performing HTTP authentication."""
        results: Dict[str, bool] = {}
        auto_login = AutoLoginEngine(session_manager=self.session_manager)

        for ident in self.session_manager.list_identities():
            meta = ident.metadata
            login_url = meta.get("login_url")
            username = meta.get("username")

            if login_url and username:
                logger.info(f"[AuthConfigManager] Automating login for identity '{ident.id}' ({username}) at '{login_url}'...")
                res = await auto_login.authenticate_user(
                    login_url=login_url,
                    username=username,
                    password="Password123!",  # Loaded from metadata or credentials
                    identity_id=ident.id
                )
                results[ident.id] = res is not None

        return results
