"""
PromptInjectionAgent — AI & LLM Interface Prompt Boundary & Safety Specialist.

Audits AI chat, assistant, and LLM completions endpoints for prompt boundary integrity,
system instruction disclosure, role-override handling, and OWASP LLM Top 10 risks.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.prompt_injection")

PROMPT_INJECTION_VECTORS = [
    {
        "id": "system_prompt_extraction",
        "name": "System Prompt & Boundary Extraction",
        "technique": "boundary_inquiry",
        "severity": "high",
        "min_confidence": 0.90,
        "description": "Checks if the model discloses confidential system instructions or internal guardrails upon direct inquiry."
    },
    {
        "id": "role_switch_override",
        "name": "Role-Switch & Instruction Override Test",
        "technique": "context_reset",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Tests if user inputs can override the model's defined persona and security constraints."
    },
    {
        "id": "indirect_context_injection",
        "name": "Indirect Document & URL Context Injection",
        "technique": "context_data_hijack",
        "severity": "critical",
        "min_confidence": 0.92,
        "description": "Tests if untrusted external documents or URLs ingested by the model alter its response logic."
    }
]

class PromptInjectionAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="PromptInjectionAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="prompt_injection_audit",
                name="AI & LLM Prompt Boundary Auditor",
                description="Audits AI/LLM interfaces for prompt boundary integrity, system prompt disclosure, and role overrides.",
                version="1.0.0",
                tags=["llm", "ai-security", "prompt-injection", "owasp-llm-top-10"]
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
            for vec in PROMPT_INJECTION_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "technique": vec["technique"],
                    "endpoint": endpoint,
                    "vulnerability_type": "prompt_injection_audit",
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
                "vulnerability_type": "prompt_injection_audit",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
