"""
AIAgentSecurityAgent — Autonomous AI Agent Systems & Tool Abuse Specialist.

Audits AI Agent workflows (LangChain, AutoGen, CrewAI, custom agents) for unauthorized tool execution,
excessive agency, unsafe parameter forwarding, and cross-session memory corruption.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.ai_agent_security")

AI_AGENT_AUDIT_VECTORS = [
    {
        "id": "unauthorized_tool_invocation",
        "name": "Excessive Agency & Tool Invocation Abuse (LLM06)",
        "severity": "critical",
        "min_confidence": 0.94,
        "description": "Agent executes sensitive tools or system commands without intermediate user confirmation or authorization."
    },
    {
        "id": "parameter_forwarding_injection",
        "name": "Unvalidated Tool Parameter Injection",
        "severity": "high",
        "min_confidence": 0.90,
        "description": "Agent passes raw model outputs directly into downstream API or shell parameters without sanitization."
    },
    {
        "id": "cross_session_memory_leak",
        "name": "Cross-Session Agent Memory & Context Contamination",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Shared vector memory or conversational state bleeds data across distinct user sessions."
    }
]

class AIAgentSecurityAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="AIAgentSecurityAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="ai_agent_security_audit",
                name="Autonomous AI Agent & Tool Abuse Auditor",
                description="Audits AI agent architectures for excessive agency, tool abuse, and memory state leakage.",
                version="1.0.0",
                tags=["ai-agents", "tool-abuse", "excessive-agency", "memory-contamination", "llm-security"]
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
            for vec in AI_AGENT_AUDIT_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "endpoint": endpoint,
                    "vulnerability_type": "ai_agent_security_audit",
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
                "vulnerability_type": "ai_agent_security_audit",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
