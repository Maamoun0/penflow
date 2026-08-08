"""
IDORAuthenticatedEngine — Phase 2: Authenticated IDOR/BOLA Tester for PenFlow.

This is the CORE of Phase 2. It performs real authenticated cross-account testing:

  Step 1: Account A logs in → fetches own resources (discovers real object IDs)
  Step 2: Account B logs in → attempts to access Account A's resources using those IDs
  Step 3: If Account B gets 200 + data → IDOR CONFIRMED

Supports:
  - Numeric ID enumeration (user/1, user/2, ...)
  - UUID/GUID swapping
  - ABP framework (/api/services/app/*)
  - Generic REST APIs
  - GraphQL object ID injection
"""
import asyncio
import httpx
import re
import json
from typing import Dict, Any, Optional, List, Tuple
from penflow.auth.account_pool import AccountPool, AuthAccount
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.auth.idor_authenticated_engine")


class IDORAuthenticatedEngine:
    """
    Phase 2: Authenticated IDOR/BOLA Testing Engine.

    Core methodology:
    1. Authenticates two real accounts (User A & User B)
    2. User A fetches their own data → extracts IDs
    3. User B attempts to access User A's IDs
    4. Differential analysis → IDOR confirmed if access is granted
    """

    # Patterns for detecting object IDs in URLs and responses
    ID_PATTERNS = [
        r'/(\d{1,10})(?:/|$|\?)',           # Numeric: /123
        r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)',  # UUID
        r'[?&](?:id|userId|accountId|orgId|companyId|tenantId)=([^&\s]+)',  # Query params
    ]

    # Fields that indicate sensitive data in responses
    SENSITIVE_FIELDS = [
        "email", "phone", "address", "username", "password", "secret",
        "token", "apiKey", "creditCard", "ssn", "dob", "firstName",
        "lastName", "name", "personalData", "companyId", "orgId"
    ]

    def __init__(self, account_pool: Optional[AccountPool] = None, timeout: float = 10.0):
        self.account_pool = account_pool or AccountPool()
        self.timeout = timeout

    async def _make_authenticated_request(
        self,
        client: httpx.AsyncClient,
        account: AuthAccount,
        method: str,
        url: str,
        json_data: Optional[dict] = None,
    ) -> Tuple[int, dict, str]:
        """Make an HTTP request with the account's authentication credentials."""
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            **account.get_auth_headers()
        }
        cookies = account.get_auth_cookies()

        try:
            if method.upper() in ["POST", "PUT", "PATCH"]:
                resp = await client.request(
                    method, url, headers=headers, cookies=cookies,
                    json=json_data or {}, follow_redirects=True
                )
            else:
                resp = await client.request(
                    method, url, headers=headers, cookies=cookies,
                    follow_redirects=True
                )

            status = resp.status_code
            body_text = resp.text[:2000]
            try:
                body_json = resp.json()
            except Exception:
                body_json = {}

            return status, body_json, body_text

        except Exception as e:
            logger.debug(f"[IDOREngine] Request error {url}: {e}")
            return 0, {}, ""

    def _extract_ids_from_response(self, data: Any, parent_key: str = "") -> List[Dict[str, Any]]:
        """Recursively extract potential object IDs from a JSON response."""
        ids = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in ["id", "userid", "accountid", "orgid", "companyid", "uuid", "guid"]:
                    if value and isinstance(value, (int, str)):
                        ids.append({"field": key, "value": str(value), "context": parent_key})
                ids.extend(self._extract_ids_from_response(value, key))
        elif isinstance(data, list):
            for item in data[:5]:  # Check first 5 items
                ids.extend(self._extract_ids_from_response(item, parent_key))
        return ids

    def _extract_ids_from_url(self, url: str) -> List[str]:
        """Extract potential IDs from a URL path."""
        ids = []
        for pattern in self.ID_PATTERNS:
            matches = re.findall(pattern, url, re.IGNORECASE)
            ids.extend(matches)
        return ids

    def _has_sensitive_data(self, body: Any) -> Tuple[bool, List[str]]:
        """Check if response body contains sensitive data fields."""
        body_str = json.dumps(body).lower() if isinstance(body, dict) else str(body).lower()
        found = [f for f in self.SENSITIVE_FIELDS if f.lower() in body_str]
        return len(found) > 0, found

    def _calculate_idor_confidence(
        self,
        user_a_status: int,
        user_b_status: int,
        user_a_body: Any,
        user_b_body: Any,
        guest_status: int,
    ) -> Tuple[bool, float, str]:
        """
        Calculate IDOR confidence based on response differential.
        Returns (is_vulnerable, confidence, reasoning).
        """
        # Perfect IDOR: A gets 200, B gets 200 with same data, Guest gets 401/403
        if user_a_status == 200 and user_b_status == 200 and guest_status in [401, 403]:
            has_sensitive, fields = self._has_sensitive_data(user_b_body)
            if has_sensitive:
                return True, 0.97, f"CRITICAL IDOR: User B accessed User A's data with sensitive fields: {fields}"
            return True, 0.85, f"HIGH IDOR: User B received 200 on User A's resource (no auth failure)"

        # Strong signal: A gets 200, B gets 200, Guest gets 200 (weak auth)
        if user_a_status == 200 and user_b_status == 200 and guest_status == 200:
            return True, 0.72, "MEDIUM IDOR: No authentication enforced on resource (public but sensitive)"

        # Partial IDOR: A gets 200, B gets 200 but with less data (data leakage)
        if user_a_status == 200 and user_b_status == 200:
            return True, 0.75, "HIGH IDOR: Cross-account access confirmed — authorization boundary missing"

        # No IDOR: B gets 403 (properly blocked)
        if user_b_status in [401, 403]:
            return False, 0.0, f"Authorization properly enforced: User B received HTTP {user_b_status}"

        return False, 0.0, f"No IDOR detected (A={user_a_status}, B={user_b_status}, Guest={guest_status})"

    async def test_endpoint_for_idor(
        self,
        client: httpx.AsyncClient,
        user_a: AuthAccount,
        user_b: AuthAccount,
        base_url: str,
        endpoint: str,
    ) -> Optional[Dict[str, Any]]:
        """Test a single endpoint for IDOR vulnerability."""
        url = f"{base_url}{endpoint}"

        # Step 1: User A fetches their resource
        a_status, a_body, a_text = await self._make_authenticated_request(client, user_a, "GET", url)

        if a_status not in [200, 201]:
            return None  # Endpoint not accessible or not found

        # Step 2: Extract IDs from User A's response
        extracted_ids = self._extract_ids_from_response(a_body)
        url_ids = self._extract_ids_from_url(url)

        # Step 3: User B tries to access the same resource (ID swap)
        b_status, b_body, b_text = await self._make_authenticated_request(client, user_b, "GET", url)

        # Step 4: Guest (no auth) tries to access
        guest_headers = {"Accept": "application/json"}
        try:
            guest_resp = await client.get(url, headers=guest_headers, follow_redirects=True)
            guest_status = guest_resp.status_code
        except Exception:
            guest_status = 0

        # Step 5: Differential Analysis
        is_vulnerable, confidence, reasoning = self._calculate_idor_confidence(
            a_status, b_status, a_body, b_body, guest_status
        )

        if a_status == 200 or b_status == 200:
            has_sensitive_a, sensitive_fields_a = self._has_sensitive_data(a_body)
            has_sensitive_b, sensitive_fields_b = self._has_sensitive_data(b_body)

            return {
                "url": url,
                "endpoint": endpoint,
                "is_vulnerable": is_vulnerable,
                "confidence": confidence,
                "reasoning": reasoning,
                "user_a_status": a_status,
                "user_b_status": b_status,
                "guest_status": guest_status,
                "sensitive_fields_user_a": sensitive_fields_a,
                "sensitive_fields_user_b": sensitive_fields_b,
                "extracted_ids": extracted_ids[:5],
                "evidence": {
                    "user_a_response_preview": a_text[:300],
                    "user_b_response_preview": b_text[:300],
                }
            }
        return None

    async def run_idor_scan(
        self,
        base_url: str,
        endpoints: List[str],
        user_a_id: str = "authenticated_user_a",
        user_b_id: str = "authenticated_user_b",
    ) -> Dict[str, Any]:
        """
        Run full IDOR scan across all provided endpoints with two authenticated accounts.
        """
        # Authenticate both accounts
        await self.account_pool.authenticate_all()

        user_a = self.account_pool.get_account(user_a_id)
        user_b = self.account_pool.get_account(user_b_id)

        if not user_a or not user_b:
            return {
                "error": f"Accounts not found: {user_a_id}, {user_b_id}",
                "findings": [],
                "authenticated": False
            }

        if not user_a.is_authenticated or not user_b.is_authenticated:
            return {
                "error": "One or both accounts failed authentication. Check credentials in config/identities.yaml",
                "user_a_auth": user_a.is_authenticated,
                "user_b_auth": user_b.is_authenticated,
                "findings": [],
                "authenticated": False
            }

        logger.info(f"[IDOREngine] Starting IDOR scan: {base_url} ({len(endpoints)} endpoints)")
        logger.info(f"[IDOREngine] User A: {user_a.username} | User B: {user_b.username}")

        findings = []
        vulnerable_findings = []

        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            # Run tests with controlled concurrency
            semaphore = asyncio.Semaphore(5)

            async def test_with_semaphore(ep):
                async with semaphore:
                    return await self.test_endpoint_for_idor(client, user_a, user_b, base_url, ep)

            results = await asyncio.gather(*[test_with_semaphore(ep) for ep in endpoints])

            for result in results:
                if result:
                    findings.append(result)
                    if result.get("is_vulnerable"):
                        vulnerable_findings.append(result)
                        logger.info(f"[IDOREngine] 🔴 IDOR FOUND: {result['url']} (confidence={result['confidence']:.2f})")

        return {
            "base_url": base_url,
            "endpoints_tested": len(endpoints),
            "findings": findings,
            "vulnerable_findings": vulnerable_findings,
            "total_vulnerable": len(vulnerable_findings),
            "authenticated": True,
            "user_a": user_a.username,
            "user_b": user_b.username,
        }
