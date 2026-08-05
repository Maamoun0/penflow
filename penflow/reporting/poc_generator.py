import json
from typing import Dict, Any, Optional
from penflow.traffic.models import TrafficRequest, TrafficExchange
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.reporting.poc_generator")

class PoCGenerator:
    """
    Automated Proof-of-Concept (PoC) Artifact Generator.
    Converts verified evidence bundles and HTTP exchanges into standalone,
    reproducible cURL commands and executable Python scripts.
    """

    def generate_curl_command(self, exchange: TrafficExchange) -> str:
        req = exchange.request
        if not req:
            return "# Error: Incomplete request trace"

        cmd_parts = ["curl -i -s -k"]
        cmd_parts.append(f"-X {req.method.upper()}")

        # Add headers
        for k, v in req.headers.items():
            cmd_parts.append(f'-H "{k}: {v}"')

        # Add body or json
        if req.json_data is not None:
            json_str = json.dumps(req.json_data)
            cmd_parts.append(f"-H \"Content-Type: application/json\"")
            cmd_parts.append(f"--data '{json_str}'")
        elif req.body:
            cmd_parts.append(f"--data '{req.body}'")

        cmd_parts.append(f'"{req.url}"')
        return " \\\n  ".join(cmd_parts)

    def generate_python_script(self, exchange: TrafficExchange, vulnerability_title: str = "Vulnerability") -> str:
        req = exchange.request
        if not req:
            return "# Error: Incomplete request trace"

        url = req.url
        method = req.method.upper()
        headers = req.headers
        json_data = req.json_data

        script = f'''# ============================================================
# PenFlow Automated Security Proof-of-Concept (PoC)
# Target Vulnerability: {vulnerability_title}
# Target URL: {url}
# ============================================================

import requests

url = "{url}"
headers = {json.dumps(headers, indent=4)}
json_data = {json.dumps(json_data, indent=4) if json_data is not None else "None"}

print(f"[*] Executing PoC request against {{url}}...")
response = requests.request(
    method="{method}",
    url=url,
    headers=headers,
    json=json_data,
    verify=False
)

print(f"[+] Response Status Code: {{response.status_code}}")
print("[+] Response Headers:")
for k, v in response.headers.items():
    print(f"    {{k}}: {{v}}")

print("\\n[+] Response Body Snippet:")
print(response.text[:1000])
'''
        return script
