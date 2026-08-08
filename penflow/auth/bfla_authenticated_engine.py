"""
BFLAAuthenticatedEngine — Phase 2: Authenticated BFLA Testing Engine for PenFlow.

Tests Broken Function Level Authorization with real authenticated sessions:
  - Standard user trying admin functions
  - HTTP Method Tampering with real credentials
  - Privilege Escalation via Mass Assignment
  - Role parameter injection in requests
"""
import asyncio
import httpx
import json
from typing import Dict, Any, Optional, List, Tuple
from penflow.auth.account_pool import AccountPool, AuthAccount
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.auth.bfla_authenticated_engine")

# Endpoints that typically indicate admin functionality
ADMIN_ENDPOINT_PATTERNS = [
    "/admin", "/manage", "/management", "/console",
    "/users", "/user/delete", "/user/create",
    "/roles", "/role/assign", "/permissions",
    "/config", "/settings/global", "/system",
    "/export", "/import", "/bulk",
    "/api/services/app/User/GetAll",
    "/api/services/app/Role/GetAll",
    "/api/services/app/Permission/UpdatePermission",
    "/api/services/app/Permission/GetAllPermissionsByRoleId",
]

# Mass assignment payloads to inject into user profile updates
MASS_ASSIGNMENT_PAYLOADS = [
    {"role": "admin"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"userType": "ADMIN"},
    {"user_type": "admin"},
    {"privilege": "admin"},
    {"roleId": 1},
    {"role_id": 1},
    {"permissions": ["*"]},
    {"scope": "admin:read admin:write"},
    {"__abp": True, "isAdmin": True},  # ABP framework specific
]


class BFLAAuthenticatedEngine:
    """
    Phase 2: Authenticated BFLA Testing Engine.

    Tests authorization boundaries using real credentials:
    1. Standard user → Admin endpoint (direct BFLA)
    2. HTTP Verb Tampering with real auth tokens
    3. Mass Assignment via profile update injection
    4. Role parameter injection
    """

    def __init__(self, account_pool: Optional[AccountPool] = None, timeout: float = 10.0):
        self.account_pool = account_pool or AccountPool()
        self.timeout = timeout

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        account: AuthAccount,
        method: str,
        url: str,
        json_data: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> Tuple[int, str, Dict]:
        """Make authenticated request."""
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            **account.get_auth_headers(),
            **(extra_headers or {})
        }
        try:
            resp = await client.request(
                method, url,
                headers=headers,
                cookies=account.get_auth_cookies(),
                json=json_data,
                follow_redirects=True
            )
            try:
                body_json = resp.json()
            except Exception:
                body_json = {}
            return resp.status_code, resp.text[:1000], body_json
        except Exception as e:
            return 0, str(e), {}

    async def test_bfla_direct(
        self,
        client: httpx.AsyncClient,
        standard_user: AuthAccount,
        url: str,
    ) -> Optional[Dict[str, Any]]:
        """Test if standard user can access admin/restricted endpoint directly."""
        status, body_text, body_json = await self._make_request(client, standard_user, "GET", url)

        if status == 200:
            # Admin endpoint accessible with standard user credentials — BFLA!
            return {
                "type": "BFLA_DIRECT_ACCESS",
                "url": url,
                "is_vulnerable": True,
                "confidence": 0.93,
                "reasoning": f"Standard user '{standard_user.username}' accessed restricted endpoint: HTTP {status}",
                "evidence": {
                    "method": "GET",
                    "status": status,
                    "response_preview": body_text[:300]
                }
            }
        return None

    async def test_verb_tampering(
        self,
        client: httpx.AsyncClient,
        standard_user: AuthAccount,
        url: str,
    ) -> Optional[Dict[str, Any]]:
        """Test HTTP Method Tampering on restricted endpoints."""
        # First verify endpoint exists (should return 403/405 for standard user)
        base_status, _, _ = await self._make_request(client, standard_user, "GET", url)
        if base_status not in [401, 403, 405]:
            return None  # Not a restricted endpoint

        for method in ["POST", "PUT", "PATCH", "DELETE"]:
            status, body_text, body_json = await self._make_request(
                client, standard_user, method, url, json_data={"test": "bfla_verb_tamper"}
            )
            if status in [200, 201, 204]:
                return {
                    "type": "BFLA_VERB_TAMPERING",
                    "url": url,
                    "is_vulnerable": True,
                    "confidence": 0.91,
                    "reasoning": f"HTTP {method} bypassed authorization on restricted endpoint (was {base_status} on GET)",
                    "evidence": {
                        "original_method": "GET",
                        "original_status": base_status,
                        "bypass_method": method,
                        "bypass_status": status,
                        "response_preview": body_text[:300]
                    }
                }

        # Also test X-HTTP-Method-Override header
        for override_method in ["DELETE", "PUT"]:
            status, body_text, _ = await self._make_request(
                client, standard_user, "POST", url,
                json_data={},
                extra_headers={
                    "X-HTTP-Method-Override": override_method,
                    "X-Method-Override": override_method,
                    "_method": override_method
                }
            )
            if status in [200, 201, 204]:
                return {
                    "type": "BFLA_VERB_OVERRIDE",
                    "url": url,
                    "is_vulnerable": True,
                    "confidence": 0.88,
                    "reasoning": f"X-HTTP-Method-Override: {override_method} bypassed authorization",
                    "evidence": {
                        "override_header": override_method,
                        "bypass_status": status,
                        "response_preview": body_text[:300]
                    }
                }
        return None

    async def test_mass_assignment(
        self,
        client: httpx.AsyncClient,
        standard_user: AuthAccount,
        profile_url: str,
    ) -> Optional[Dict[str, Any]]:
        """Test Mass Assignment via injecting privilege fields into profile update."""
        # First get current profile
        status, _, current_body = await self._make_request(client, standard_user, "GET", profile_url)
        if status != 200:
            return None

        for payload in MASS_ASSIGNMENT_PAYLOADS:
            status, body_text, resp_json = await self._make_request(
                client, standard_user, "PUT", profile_url, json_data=payload
            )
            if status in [200, 201]:
                # Check if the privileged field was accepted in the response
                resp_str = json.dumps(resp_json).lower()
                for key, value in payload.items():
                    if str(value).lower() in resp_str:
                        return {
                            "type": "MASS_ASSIGNMENT",
                            "url": profile_url,
                            "is_vulnerable": True,
                            "confidence": 0.88,
                            "reasoning": f"Mass Assignment accepted: {payload} — privilege field reflected in response",
                            "evidence": {
                                "payload_sent": payload,
                                "response_preview": body_text[:300]
                            }
                        }
        return None

    async def run_bfla_scan(
        self,
        base_url: str,
        endpoints: List[str],
        profile_endpoints: Optional[List[str]] = None,
        standard_user_id: str = "authenticated_user_b",
    ) -> Dict[str, Any]:
        """Run full BFLA scan with authenticated standard user account."""
        await self.account_pool.authenticate_all()

        standard_user = self.account_pool.get_account(standard_user_id)
        if not standard_user or not standard_user.is_authenticated:
            return {
                "error": f"Standard user account not authenticated: {standard_user_id}",
                "findings": []
            }

        logger.info(f"[BFLAEngine] Starting BFLA scan: {base_url} as '{standard_user.username}'")

        all_findings = []
        semaphore = asyncio.Semaphore(5)

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            # Test 1: Direct BFLA
            async def direct_test(ep):
                async with semaphore:
                    url = f"{base_url}{ep}"
                    return await self.test_bfla_direct(client, standard_user, url)

            direct_results = await asyncio.gather(*[direct_test(ep) for ep in endpoints])
            all_findings.extend([r for r in direct_results if r])

            # Test 2: Verb Tampering (only on admin-pattern endpoints)
            admin_eps = [ep for ep in endpoints if any(p in ep.lower() for p in ["admin", "delete", "role", "permission", "create"])]
            async def verb_test(ep):
                async with semaphore:
                    url = f"{base_url}{ep}"
                    return await self.test_verb_tampering(client, standard_user, url)

            verb_results = await asyncio.gather(*[verb_test(ep) for ep in admin_eps[:20]])
            all_findings.extend([r for r in verb_results if r])

            # Test 3: Mass Assignment
            if profile_endpoints:
                for profile_ep in profile_endpoints[:5]:
                    result = await self.test_mass_assignment(client, standard_user, f"{base_url}{profile_ep}")
                    if result:
                        all_findings.append(result)

        vulnerable = [f for f in all_findings if f.get("is_vulnerable")]
        logger.info(f"[BFLAEngine] Complete: {len(vulnerable)} BFLA findings from {len(endpoints)} endpoints")

        return {
            "base_url": base_url,
            "endpoints_tested": len(endpoints),
            "standard_user": standard_user.username,
            "findings": all_findings,
            "vulnerable_findings": vulnerable,
            "total_vulnerable": len(vulnerable),
        }
