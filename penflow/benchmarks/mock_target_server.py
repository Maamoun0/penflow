import json
from typing import Dict, Any, Tuple
import httpx

class MockTargetServer:
    """
    In-memory Mock Target Server simulating real-world target APIs for benchmark testing.
    Exposes endpoints vulnerable to:
    - IDOR / BOLA (/api/v1/invoices/<id>)
    - BFLA (/api/v1/admin/users)
    - Mass Assignment (/api/v1/user/profile)
    - GraphQL Schema Introspection & Query Batching (/graphql)
    - Race Conditions (/api/v1/coupon/redeem)
    """

    def __init__(self):
        self.user_database = {
            "alice": {"id": "100", "user_id": "alice", "balance": 5000, "role": "standard"},
            "bob": {"id": "201", "user_id": "bob", "balance": 150, "role": "standard"},
        }
        self.coupons_redeemed = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url_path = request.url.path
        method = request.method.upper()
        auth_header = request.headers.get("Authorization", "")
        body_text = request.read().decode("utf-8") if request.stream else ""

        # 1. IDOR / BOLA Vulnerable Endpoint
        if "/api/v1/invoices/" in url_path and method == "GET":
            # Vulnerable: returns invoice regardless of Bearer token owner
            inv_id = url_path.split("/")[-1]
            return httpx.Response(200, json={
                "invoice_id": inv_id,
                "owner_email": "victim_alice@target.com",
                "secret_ssn": "999-00-1234",
                "amount_usd": 9500
            })

        # 2. BFLA Vulnerable Endpoint
        if "/api/v1/admin/" in url_path:
            if method == "GET" and "admin" not in auth_header:
                return httpx.Response(403, json={"error": "Admin access required"})
            elif method in ["POST", "PUT", "DELETE"]:
                # Vulnerable: POST/PUT/DELETE bypasses auth check!
                return httpx.Response(200, json={"status": "success", "action": f"admin_action_{method}"})

        # 3. Mass Assignment Endpoint
        if "/api/v1/user/profile" in url_path:
            try:
                data = json.loads(body_text) if body_text else {}
            except Exception:
                data = {}
            # Vulnerable: reflects all injected keys directly
            response_data = {"name": "Test User", "status": "updated"}
            response_data.update(data)
            return httpx.Response(200, json=response_data)

        # 4. GraphQL Endpoint
        if "/graphql" in url_path:
            if "__schema" in body_text:
                return httpx.Response(200, json={
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [{"name": "User"}, {"name": "Invoice"}, {"name": "Admin"}]
                        }
                    }
                })
            elif body_text.startswith("["):
                # Query Batching
                return httpx.Response(200, json=[{"data": {"status": "ok"}}, {"data": {"status": "ok"}}])
            return httpx.Response(200, json={"data": {"user": "alice"}})

        # 5. Race Condition Endpoint
        if "/api/v1/coupon/redeem" in url_path:
            self.coupons_redeemed += 1
            return httpx.Response(200, json={"status": "redeemed", "total_redemptions": self.coupons_redeemed})

        return httpx.Response(404, json={"error": "Not Found"})

    def get_mock_transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle_request)
