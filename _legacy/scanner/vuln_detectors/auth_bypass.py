from typing import List, Dict, Any

from penflow.core.plugin_manager import BaseDetector
from penflow.network.http_client import HttpClient
from penflow.scanner.response_differ import ResponseDiffer
from penflow.utils.logger import get_logger

logger = get_logger("penflow.scanner.auth_bypass")

class AuthBypassDetector(BaseDetector):
    @property
    def supported_types(self):
        return ["AUTH_BYPASS"]

    def name(self) -> str:
        return "auth_bypass_detector"
        
    def version(self) -> str:
        return "1.0.0"

    async def run(self, context: dict) -> dict:
        pass

    async def detect(self, endpoint: dict, http_client: HttpClient, config: dict = None) -> List[Dict[str, Any]]:
        """
        Test for Authentication and Authorization bypasses.
        Attempts accessing protected endpoints with missing, invalid, or manipulated auth tokens.
        """
        findings = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET")
        
        # 1. Baseline with normal auth (if provided in http_client session)
        baseline_res = await http_client.request(method, url)
        
        if not baseline_res or baseline_res.status not in (200, 201, 204):
            # If baseline is not successful, it means we don't have valid auth to begin with
            # or the endpoint is broken.
            return findings
            
        differ = ResponseDiffer()
        
        # Test 1: Completely missing auth header/cookie
        # (Assuming http_client injects auth normally, we bypass it)
        no_auth_headers = {k: v for k, v in baseline_res.headers.items() 
                           if k.lower() not in ('authorization', 'cookie')}
                           
        payload_res = await http_client.request(method, url, headers=no_auth_headers)
        
        if payload_res:
            diff = differ.compare(baseline_res, payload_res)
            # If we get a 200 and the content is similar to authenticated baseline, it's a bypass
            if payload_res.status == baseline_res.status and diff.deviation_score < 0.2:
                findings.append({
                    "vuln_type": "AUTH_BYPASS",
                    "url": url,
                    "method": method,
                    "param": "headers",
                    "payload": "Removed Authorization/Cookie headers",
                    "confidence": 0.8,
                    "raw_request": f"{method} {url} (No Auth Headers)",
                    "raw_response": f"Status: {payload_res.status}\nDiff Score: {diff.deviation_score}"
                })
                
        # Test 2: Method override (e.g. GET -> POST -> PUT) for RBAC bypass
        methods_to_test = ["POST", "PUT", "DELETE", "PATCH"]
        methods_to_test.remove(method.upper()) if method.upper() in methods_to_test else None
        
        for m in methods_to_test:
            # Send with another method
            m_res = await http_client.request(m, url)
            if m_res and m_res.status in (200, 201, 204) and m_res.status != 405: # Not Method Not Allowed
                findings.append({
                    "vuln_type": "AUTH_BYPASS_METHOD",
                    "url": url,
                    "method": m,
                    "param": "method",
                    "payload": f"Changed method to {m}",
                    "confidence": 0.6,
                    "raw_request": f"{m} {url}",
                    "raw_response": f"Status: {m_res.status}"
                })

        return findings
