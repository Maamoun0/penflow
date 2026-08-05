from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import json

from penflow.core.plugin_manager import BaseDetector
from penflow.network.http_client import HttpClient
from penflow.scanner.response_differ import ResponseDiffer

class IDORDetector(BaseDetector):
    @property
    def supported_types(self):
        return ["IDOR", "BOLA"]

    def name(self) -> str:
        return "idor_detector"
        
    def version(self) -> str:
        return "2.0.0"

    async def run(self, context: dict) -> dict:
        pass # Not used directly

    async def detect(self, endpoint: dict, http_client: HttpClient, config: dict = None) -> List[Dict[str, Any]]:
        """
        Test for Insecure Direct Object Reference (IDOR / BOLA).
        Handles both:
        1. Single-session numeric/UUID ID parameter manipulation.
        2. Cross-session (User A / User B) Authorization Header swapping for high-confidence BOLA.
        """
        findings = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET")
        params = config.get("focus_params", []) if config else []
        auth_manager = config.get("auth_manager") if config else None
        
        differ = ResponseDiffer()

        # -------------------------------------------------------------
        # TEST MODE 1: Dual-Account Cross-Session Authorization Swapping
        # -------------------------------------------------------------
        if auth_manager and auth_manager.get_profile("user_a") and auth_manager.get_profile("user_b"):
            user_a_headers = auth_manager.get_headers_for("user_a")
            user_b_headers = auth_manager.get_headers_for("user_b")

            # 1. Fetch resource using User A (Authorized owner)
            res_user_a = await http_client.request(method, url, headers=user_a_headers)
            
            if res_user_a and res_user_a.status == 200:
                # 2. Fetch the exact same resource using User B's token (Unauthorized tenant)
                res_user_b = await http_client.request(method, url, headers=user_b_headers)
                
                if res_user_b and res_user_b.status == 200:
                    diff = differ.compare(res_user_a, res_user_b)
                    
                    # If User B gets status 200 and the content is virtually identical to User A's response,
                    # this means User B has unauthorized access to User A's object (BOLA / IDOR)
                    if diff.deviation_score < 0.2:
                        findings.append({
                            "vuln_type": "BOLA_CROSS_SESSION",
                            "url": url,
                            "method": method,
                            "param": "Authorization",
                            "payload": "Swapped User A session with User B session token",
                            "confidence": 0.95,
                            "raw_request": f"{method} {url} (Authenticated as User B)",
                            "raw_response": f"Status: {res_user_b.status}\nBody Similarity: {100 - int(diff.deviation_score*100)}%"
                        })
                        return findings  # Highest confidence finding discovered

        # -------------------------------------------------------------
        # TEST MODE 2: Parameter Manipulation (URL Query & Path Params)
        # -------------------------------------------------------------
        if not params:
            return findings

        # Establish baseline request
        baseline_res = await http_client.request(method, url)
        if not baseline_res or baseline_res.status >= 400:
            return findings

        parsed_url = urlparse(url)
        query_params = dict(parse_qsl(parsed_url.query))

        for param in params:
            if param in query_params:
                original_val = query_params[param]
                test_val = self._generate_test_value(original_val)
                if test_val == original_val:
                    continue

                test_query = query_params.copy()
                test_query[param] = test_val
                new_query_string = urlencode(test_query)
                new_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query_string, parsed_url.fragment
                ))

                payload_res = await http_client.request(method, new_url)
                if not payload_res:
                    continue

                diff = differ.compare(baseline_res, payload_res)

                if payload_res.status == 200 and diff.deviation_score > 0.1 and not diff.diffs.get("sql_errors"):
                    if "auth" not in payload_res.url and "login" not in payload_res.url:
                        findings.append({
                            "vuln_type": "IDOR",
                            "url": url,
                            "method": method,
                            "param": param,
                            "payload": str(test_val),
                            "confidence": 0.7,
                            "raw_request": f"{method} {new_url}",
                            "raw_response": f"Status: {payload_res.status}\nBody length: {len(payload_res.body)}"
                        })

        return findings

    def _generate_test_value(self, original: str) -> str:
        """Generate a test value based on the original value's type."""
        if original.isdigit():
            num = int(original)
            return str(num + 1) if num > 0 else "1"
        elif "-" in original and len(original) == 36:
            import uuid
            return str(uuid.uuid4())
        else:
            return original
