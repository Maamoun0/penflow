"""
AccountPool — Phase 2: Authenticated Testing Engine for PenFlow.

Manages a pool of test accounts for multi-identity IDOR/BFLA testing.
Handles:
  - Loading credentials from config/identities.yaml
  - Automatic HTTP/OAuth2 login with token extraction
  - Session validation and token refresh
  - ABP (ASP.NET Boilerplate) framework login support (rcm.motors.abb.com.cn)
  - Generic JSON API login support
  - Cookie-based session support
"""
import asyncio
import httpx
import yaml
import os
import json
from typing import Dict, Any, Optional, List
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.auth.account_pool")


class AuthAccount:
    """Represents a single authenticated test account."""

    def __init__(
        self,
        account_id: str,
        username: str,
        password: str,
        login_url: str,
        role: str = "user",
        auth_type: str = "json",  # json | form | bearer | cookie
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.account_id = account_id
        self.username = username
        self.password = password
        self.login_url = login_url
        self.role = role
        self.auth_type = auth_type
        self.extra_headers = extra_headers or {}

        # Set after login
        self.bearer_token: Optional[str] = None
        self.cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}
        self.is_authenticated: bool = False
        self.user_id: Optional[str] = None
        self.user_data: Dict[str, Any] = {}

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


class AccountPool:
    """
    Phase 2: Multi-Account Pool Manager.

    Manages multiple authenticated sessions for cross-account authorization testing.
    Supports ABP framework, generic JSON APIs, and form-based login.
    """

    def __init__(self, config_path: str = "config/identities.yaml"):
        self.config_path = config_path
        self.accounts: Dict[str, AuthAccount] = {}
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
                )
                # Pre-load static tokens if provided
                if val.get("bearer_token"):
                    acc.bearer_token = val["bearer_token"]
                    acc.is_authenticated = True
                if val.get("cookies"):
                    acc.cookies = val["cookies"]

                self.accounts[acc.account_id] = acc
                logger.info(f"[AccountPool] Loaded account: {acc.account_id} ({acc.username})")

        except Exception as e:
            logger.error(f"[AccountPool] Error loading config: {e}")

    def add_account(self, account: AuthAccount):
        """Manually add an account to the pool."""
        self.accounts[account.account_id] = account

    def get_account(self, account_id: str) -> Optional[AuthAccount]:
        return self.accounts.get(account_id)

    def get_authenticated_accounts(self) -> List[AuthAccount]:
        return [a for a in self.accounts.values() if a.is_authenticated]

    async def login_account(self, account: AuthAccount, client: httpx.AsyncClient) -> bool:
        """
        Perform HTTP login for a single account.
        Supports: JSON API, ABP Framework, Form-based, OAuth2 Password Grant.
        """
        if not account.login_url or not account.username:
            logger.warning(f"[AccountPool] Account {account.account_id} has no login URL or username.")
            return False

        logger.info(f"[AccountPool] Logging in: {account.username} @ {account.login_url}")

        try:
            if account.auth_type == "abp":
                # ABP (ASP.NET Boilerplate) — used by rcm.motors.abb.com.cn
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
                # Default: JSON body
                payload = {"username": account.username, "password": account.password}
                resp = await client.post(account.login_url, json=payload)

            # Extract token from response
            if resp.status_code in [200, 201]:
                try:
                    data = resp.json()
                    # Try common token field names
                    token = (
                        data.get("token") or
                        data.get("access_token") or
                        data.get("accessToken") or
                        data.get("jwt") or
                        data.get("id_token") or
                        # ABP framework nests the token
                        (data.get("result", {}) or {}).get("accessToken") or
                        (data.get("result", {}) or {}).get("encryptedAccessToken")
                    )
                    if token:
                        account.bearer_token = token
                        account.session_headers["Authorization"] = f"Bearer {token}"

                    # Extract user ID if available
                    account.user_id = str(
                        data.get("userId") or
                        data.get("user_id") or
                        (data.get("result", {}) or {}).get("userId") or
                        ""
                    )
                    account.user_data = data
                except Exception:
                    pass

                # Capture cookies
                account.cookies = dict(resp.cookies)
                account.is_authenticated = True

                logger.info(
                    f"[AccountPool] ✓ Login successful: {account.username} "
                    f"(token={'YES' if account.bearer_token else 'NO'}, "
                    f"cookies={list(account.cookies.keys())})"
                )
                return True
            else:
                logger.warning(
                    f"[AccountPool] ✗ Login failed: {account.username} → HTTP {resp.status_code}"
                )
                logger.debug(f"[AccountPool] Response body: {resp.text[:300]}")
                return False

        except Exception as e:
            logger.error(f"[AccountPool] Login exception for {account.username}: {e}")
            return False

    async def authenticate_all(self) -> Dict[str, bool]:
        """Login all accounts in the pool that have credentials."""
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

        authenticated = sum(1 for v in results.values() if v)
        logger.info(f"[AccountPool] Authentication complete: {authenticated}/{len(results)} accounts logged in.")
        return results

    async def _login_and_record(self, account: AuthAccount, client: httpx.AsyncClient, results: dict):
        success = await self.login_account(account, client)
        results[account.account_id] = success
