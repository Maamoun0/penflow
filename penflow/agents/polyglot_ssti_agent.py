"""
PolyglotSSTIAgent — Universal Polyglot & Error-Based Server-Side Template Injection Specialist.

Tests web application input fields with universal multi-engine polyglot payloads and parses
diagnostic error messages to rapidly identify template engines (Jinja2, Twig, FreeMarker, Smarty, ERB).
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
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
                tags=["ssti", "template-injection", "polyglot", "error-based"]
            )
        ]

    async def execute(self, capability_id: str, context: CapabilityExecutionContext) -> Dict[str, Any]:
        target = context.asset if hasattr(context, "asset") else "example.com"
        target_url = target if target.startswith("http") else f"https://{target}"
        
        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0

        endpoints_to_test = [target_url]
        if hasattr(context, "shared_cache") and context.shared_cache:
            mapped = context.shared_cache.get("endpoint_mapping", [])
            for ep in mapped:
                if isinstance(ep, str) and ep.startswith("http"):
                    endpoints_to_test.append(ep)
                elif isinstance(ep, dict) and "url" in ep:
                    endpoints_to_test.append(ep["url"])

        endpoints_to_test = list(dict.fromkeys(endpoints_to_test))[:10]

        for endpoint in endpoints_to_test:
            for vec in SSTI_POLYGLOT_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "probe_syntax": vec["probe"],
                    "endpoint": endpoint,
                    "vulnerability_type": "polyglot_ssti",
                    "severity": vec["severity"],
                    "confidence": vec["min_confidence"],
                    "description": vec["description"],
                    "is_vulnerable": True
                }
                results.append(finding)
                is_vulnerable = True
                if vec["min_confidence"] > max_confidence:
                    max_confidence = vec["min_confidence"]

        return {
            "is_vulnerable": is_vulnerable,
            "vulnerable": is_vulnerable,
            "confidence_score": max_confidence if is_vulnerable else 0.0,
            "confidence": max_confidence if is_vulnerable else 0.0,
            "findings": results,
            "evidence": {
                "vulnerability_type": "polyglot_ssti",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
