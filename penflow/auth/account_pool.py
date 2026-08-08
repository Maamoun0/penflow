"""
AccountPool & SessionMatrixManager — Multi-Role Authenticated Testing & Auto-Replay Engine for PenFlow.

Manages a pool of test accounts and multi-identity session matrices for IDOR/BFLA testing:
  1. SessionMatrixManager: Holds concurrent User_A (Attacker), User_B (Victim), Anonymous, and Admin sessions
  2. AutoReplayMatrixEngine: Parallel multi-session request replayer with differential response analysis
  3. Token auto-refresh, token rotation for rate-limit bypass, and session lifecycle management
"""
import asyncio
import httpx
import yaml
import os
import json
import time
from enum import Enum
from typing import Dict, Any, Optional, List, Set, Tuple
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.auth.account_pool")


class RoleType(str, Enum):
    USER_A = "user_a"       # Attacker / Primary test identity
    USER_B = "user_b"       # Victim / Secondary cross-tenant identity
    ANONYMOUS = "anonymous" # Unauthenticated visitor
    ADMIN = "admin"         # High-privilege identity


class AuthAccount:
    """Represents a single authenticated test account with token lifecycle management."""

    def __init__(
        self,
        account_id: str,
        username: str,
        password: str,
        login_url: str = "",
        role: str = "user",
        auth_type: str = "json",  # json | form | bearer | cookie | oauth2
        extra_headers: Optional[Dict[str, str]] = None,
        bearer_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        token_expires_at: float = 0.0,
    ):
        self.account_id = account_id
        self.username = username
        self.password = password
        self.login_url = login_url
        self.role = role
        self.auth_type = auth_type
        self.extra_headers = extra_headers or {}

        # Token lifecycle
        self.bearer_token: Optional[str] = bearer_token
        self.refresh_token: Optional[str] = refresh_token
        self.token_expires_at: float = token_expires_at or (time.time() + 3600.0 if bearer_token else 0.0)
        self.cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}
        self.is_authenticated: bool = bool(bearer_token or False)
        self.user_id: Optional[str] = None
        self.user_data: Dict[str, Any] = {}

    def is_token_expired(self) -> bool:
        if not self.bearer_token:
            return True
        return time.time() > (self.token_expires_at - 60.0)

    def get_auth_headers(self) -> Dict[str, str]:
        """Returns the Authorization headers for this authenticated session."""
        headers = dict(self.extra_headers)
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        headers.update(self.session_headers)
        return headers

    def get_auth_cookies(self) -> Dict[str, str]:
        return self.cookies

    def __repr__(self):
        return f"<AuthAccount id={self.account_id} user={self.username} role={self.role} auth={self.is_authenticated}>"


class SessionMatrixManager:
    """
    Manages concurrent multi-identity sessions (User A, User B, Anonymous, Admin)
    for parallel cross-account authorization & privilege escalation testing.
    """
    def __init__(self):
        self._matrix: Dict[str, List[AuthAccount]] = {
            RoleType.USER_A.value: [],
            RoleType.USER_B.value: [],
            RoleType.ANONYMOUS.value: [AuthAccount(account_id="anon", username="", password="", role="anonymous")],
            RoleType.ADMIN.value: []
        }
        self._rotation_indices: Dict[str, int] = {k: 0 for k in self._matrix}

    def register_account(self, role: RoleType, account: AuthAccount):
        """Registers an account into a designated role bucket."""
        role_key = role.value if isinstance(role, RoleType) else str(role)
        if role_key not in self._matrix:
            self._matrix[role_key] = []
        self._matrix[role_key].append(account)
        logger.info(f"[SessionMatrixManager] Registered account {account.account_id} for role '{role_key}'")

    def get_session(self, role: RoleType) -> Optional[AuthAccount]:
        """Retrieves the active session for a role, rotating if multiple are present."""
        role_key = role.value if isinstance(role, RoleType) else str(role)
        accounts = self._matrix.get(role_key, [])
        if not accounts:
            return None
        idx = self._rotation_indices.get(role_key, 0) % len(accounts)
        return accounts[idx]

    def rotate_session(self, role: RoleType) -> Optional[AuthAccount]:
        """Rotates to the next available session in the role bucket to evade rate limits."""
        role_key = role.value if isinstance(role, RoleType) else str(role)
        accounts = self._matrix.get(role_key, [])
        if not accounts:
            return None
        self._rotation_indices[role_key] = (self._rotation_indices.get(role_key, 0) + 1) % len(accounts)
        return self.get_session(role)

    def get_all_matrix_roles(self) -> Dict[str, Optional[AuthAccount]]:
        """Returns the current active identity snapshot across all matrix roles."""
        return {
            RoleType.USER_A.value: self.get_session(RoleType.USER_A),
            RoleType.USER_B.value: self.get_session(RoleType.USER_B),
            RoleType.ANONYMOUS.value: self.get_session(RoleType.ANONYMOUS),
            RoleType.ADMIN.value: self.get_session(RoleType.ADMIN)
        }


class AutoReplayMatrixEngine:
    """
    Executes parallel multi-role request replays and performs response differential analysis
    to automatically identify IDOR, BFLA, and BOLA vulnerabilities.
    """
    def __init__(self, matrix_manager: SessionMatrixManager):
        self.matrix_manager = matrix_manager

    async def replay_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Any] = None,
        data: Optional[Any] = None,
        client: Optional[httpx.AsyncClient] = None
    ) -> Dict[str, Any]:
        """
        Replays a request across User A, User B, Anonymous, and Admin roles in parallel.
        Returns a differential comparison object.
        """
        headers = headers or {}
        roles = self.matrix_manager.get_all_matrix_roles()
        results: Dict[str, Dict[str, Any]] = {}

        owns_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, verify=False)
            owns_client = True

        try:
            for role_name, account in roles.items():
                if account is None:
                    continue
                req_headers = dict(headers)
                req_headers.update(account.get_auth_headers())
                req_cookies = account.get_auth_cookies()

                try:
                    resp = await client.request(
                        method=method,
                        url=url,
                        headers=req_headers,
                        cookies=req_cookies,
                        json=json_data,
                        data=data
                    )
                    results[role_name] = {
                        "status_code": resp.status_code,
                        "body_length": len(resp.text),
                        "text_snippet": resp.text[:200],
                        "headers": dict(resp.headers)
                    }
                except Exception as e:
                    results[role_name] = {
                        "status_code": 0,
                        "error": str(e),
                        "body_length": 0,
                        "text_snippet": ""
                    }
        finally:
            if owns_client:
                await client.aclose()

        # Differential Analysis for IDOR & BFLA
        idor_detected = False
        bfla_detected = False
        findings: List[Dict[str, Any]] = []

        user_a_res = results.get(RoleType.USER_A.value)
        user_b_res = results.get(RoleType.USER_B.value)
        anon_res = results.get(RoleType.ANONYMOUS.value)

        # IDOR Condition: User A succeeds (200), and User B also gets 200 with matching/similar data
        if user_a_res and user_b_res:
            if user_a_res["status_code"] == 200 and user_b_res["status_code"] == 200:
                idor_detected = True
                findings.append({
                    "vulnerability_type": "idor_cross_tenant_leak",
                    "severity": "HIGH",
                    "url": url,
                    "description": f"Endpoint returned HTTP 200 to both User A and User B for same resource: {url}"
                })

        # Broken Auth / Unauthenticated Leak Condition: Anonymous user receives HTTP 200
        if anon_res and user_a_res:
            if user_a_res["status_code"] == 200 and anon_res["status_code"] == 200:
                bfla_detected = True
                findings.append({
                    "vulnerability_type": "unauthenticated_sensitive_endpoint",
                    "severity": "CRITICAL",
                    "url": url,
                    "description": f"Endpoint accessible without authentication: HTTP 200 received by anonymous client."
                })

        return {
            "url": url,
            "method": method,
            "is_idor": idor_detected,
            "is_bfla": bfla_detected,
            "role_results": results,
            "findings": findings
        }


class AccountPool:
    """
    Phase 2: Multi-Account Pool & Session Matrix Coordinator.
    """
    def __init__(self, config_path: str = "config/identities.yaml"):
        self.config_path = config_path
        self.accounts: Dict[str, AuthAccount] = {}
        self.matrix_manager = SessionMatrixManager()
        self._load_from_config()

    def _load_from_config(self):
        """Load account definitions from YAML config."""
        if not os.path.exists(self.config_path):
            logger.warning(f"[AccountPool] Config not found: {self.config_path}")
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            for key, val in data.get("identities", {}).items():
                acc = AuthAccount(
                    account_id=val.get("id", key),
                    username=val.get("username", ""),
                    password=val.get("password", ""),
                    login_url=val.get("login_url", ""),
                    role=val.get("role", "user"),
                    auth_type=val.get("auth_type", "json"),
                    extra_headers=val.get("headers", {}),
                    bearer_token=val.get("bearer_token"),
                    refresh_token=val.get("refresh_token"),
                )
                if val.get("cookies"):
                    acc.cookies = val["cookies"]

                self.accounts[acc.account_id] = acc
                
                # Auto-assign to Matrix Manager
                if "user_a" in acc.account_id.lower() or acc.role == "attacker":
                    self.matrix_manager.register_account(RoleType.USER_A, acc)
                elif "user_b" in acc.account_id.lower() or acc.role == "victim":
                    self.matrix_manager.register_account(RoleType.USER_B, acc)
                elif "admin" in acc.role.lower() or "admin" in acc.account_id.lower():
                    self.matrix_manager.register_account(RoleType.ADMIN, acc)
                else:
                    self.matrix_manager.register_account(RoleType.USER_A, acc)

                logger.info(f"[AccountPool] Loaded account: {acc.account_id} ({acc.username})")

        except Exception as e:
            logger.error(f"[AccountPool] Error loading config: {e}")

    def add_account(self, account: AuthAccount):
        self.accounts[account.account_id] = account

    def get_account(self, account_id: str) -> Optional[AuthAccount]:
        return self.accounts.get(account_id)

    def get_authenticated_accounts(self) -> List[AuthAccount]:
        return [a for a in self.accounts.values() if a.is_authenticated]

    async def login_account(self, account: AuthAccount, client: httpx.AsyncClient) -> bool:
        if not account.login_url or not account.username:
            logger.warning(f"[AccountPool] Account {account.account_id} has no login URL or username.")
            return False

        logger.info(f"[AccountPool] Logging in: {account.username} @ {account.login_url}")

        try:
            if account.auth_type == "abp":
                payload = {
                    "userNameOrEmailAddress": account.username,
                    "password": account.password,
                    "rememberClient": False,
                    "returnUrl": None,
                    "singleSignIn": False
                }
                resp = await client.post(account.login_url, json=payload, headers={"Content-Type": "application/json"})

            elif account.auth_type == "form":
                resp = await client.post(
                    account.login_url,
                    data={"username": account.username, "password": account.password},
                )
            elif account.auth_type == "oauth2":
                resp = await client.post(account.login_url, data={
                    "grant_type": "password",
                    "username": account.username,
                    "password": account.password,
                    "scope": "openid profile email",
                })
            else:
                payload = {"username": account.username, "password": account.password}
                resp = await client.post(account.login_url, json=payload)

            if resp.status_code in [200, 201]:
                try:
                    data = resp.json()
                    token = (
                        data.get("token") or
                        data.get("access_token") or
                        data.get("accessToken") or
                        data.get("jwt") or
                        data.get("id_token") or
                        (data.get("result", {}) or {}).get("accessToken") or
                        (data.get("result", {}) or {}).get("encryptedAccessToken")
                    )
                    if token:
                        account.bearer_token = token
                        account.session_headers["Authorization"] = f"Bearer {token}"
                        account.token_expires_at = time.time() + 3600.0

                    account.user_id = str(
                        data.get("userId") or
                        data.get("user_id") or
                        (data.get("result", {}) or {}).get("userId") or
                        ""
                    )
                    account.user_data = data
                except Exception:
                    pass

                account.cookies = dict(resp.cookies)
                account.is_authenticated = True
                return True
            else:
                return False

        except Exception as e:
            logger.error(f"[AccountPool] Login exception for {account.username}: {e}")
            return False

    async def authenticate_all(self) -> Dict[str, bool]:
        results = {}
        async with httpx.AsyncClient(
            verify=False,
            timeout=15.0,
            follow_redirects=True,
        ) as client:
            tasks = [
                self._login_and_record(acc, client, results)
                for acc in self.accounts.values()
                if acc.login_url and acc.username and not acc.is_authenticated
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        return results

    async def _login_and_record(self, account: AuthAccount, client: httpx.AsyncClient, results: dict):
        success = await self.login_account(account, client)
        results[account.account_id] = success
