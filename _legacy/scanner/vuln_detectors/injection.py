from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from penflow.core.plugin_manager import BaseDetector
from penflow.network.http_client import HttpClient
from penflow.scanner.response_differ import ResponseDiffer

class InjectionDetector(BaseDetector):
    @property
    def supported_types(self):
        return ["SQLI", "XSS", "SSTI"]

    def name(self) -> str:
        return "injection_detector"
        
    def version(self) -> str:
        return "1.0.0"

    async def run(self, context: dict) -> dict:
        pass

    async def detect(self, endpoint: dict, http_client: HttpClient, config: dict = None) -> List[Dict[str, Any]]:
        findings = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET")
        vuln_type = config.get("vuln_type", "SQLI") if config else "SQLI"
        params = config.get("focus_params", []) if config else []
        
        if not params:
            return findings

        payloads = self._get_payloads(vuln_type)
        differ = ResponseDiffer()
        
        parsed_url = urlparse(url)
        query_params = dict(parse_qsl(parsed_url.query))
        
        # 1. Baseline
        baseline_res = await http_client.request(method, url)
        if not baseline_res: return findings
        
        for param in params:
            if param in query_params:
                for payload in payloads:
                    # Inject payload
                    test_query = query_params.copy()
                    test_query[param] = test_query[param] + payload
                    new_query_string = urlencode(test_query)
                    new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query_string, parsed_url.fragment))
                    
                    payload_res = await http_client.request(method, new_url)
                    if not payload_res: continue
                    
                    diff = differ.compare(baseline_res, payload_res, payload=payload)
                    
                    if vuln_type == "SQLI" and diff.diffs.get("sql_errors"):
                        findings.append(self._create_finding("SQLI_ERROR", url, method, param, payload, 0.9, payload_res))
                        break # Stop testing this param for SQLi if error found
                        
                    elif vuln_type == "XSS" and diff.diffs.get("reflection"):
                        findings.append(self._create_finding("XSS_REFLECTED", url, method, param, payload, 0.7, payload_res))
                        
                    elif vuln_type == "SSTI":
                        # Look for computed result (49 for 7*7)
                        if "49" in payload_res.body and "49" not in baseline_res.body:
                            findings.append(self._create_finding("SSTI", url, method, param, payload, 0.95, payload_res))
                            break

        return findings

    def _get_payloads(self, vuln_type: str) -> List[str]:
        if vuln_type == "SQLI":
            return ["'", "\"", "') OR 1=1--", "' OR '1'='1"]
        elif vuln_type == "XSS":
            return ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"]
        elif vuln_type == "SSTI":
            return ["{{7*7}}", "${7*7}"]
        return []

    def _create_finding(self, vtype: str, url: str, method: str, param: str, payload: str, conf: float, response) -> dict:
        return {
            "vuln_type": vtype,
            "url": url,
            "method": method,
            "param": param,
            "payload": payload,
            "confidence": conf,
            "raw_request": f"{method} payload in param {param}",
            "raw_response": f"Status: {response.status}\nLength: {len(response.body)}"
        }
