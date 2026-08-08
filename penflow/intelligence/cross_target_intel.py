"""
CrossTargetIntelligence — Cross-Target Vulnerability Pattern & Stack Correlation Engine.

Aggregates technology fingerprints and past finding distributions across targets to predict
high-probability vulnerability classes for newly scanned assets.
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.cross_target_intel")

STACK_CORRELATION_RULES = [
    {
        "technologies": ["graphql", "apollo"],
        "recommended_capabilities": ["graphql_introspection", "graphql_batching", "graphql_field_suggestion"],
        "confidence": 0.95
    },
    {
        "technologies": ["next.js", "react"],
        "recommended_capabilities": ["framework_cache_poisoning", "client_side_path_traversal", "cors"],
        "confidence": 0.88
    },
    {
        "technologies": ["django", "python"],
        "recommended_capabilities": ["ssti_rce", "unicode_normalization", "open_redirect"],
        "confidence": 0.84
    },
    {
        "technologies": ["openai", "langchain", "ai-chat"],
        "recommended_capabilities": ["prompt_injection_audit", "ai_agent_security_audit", "rag_poisoning_audit"],
        "confidence": 0.92
    },
    {
        "technologies": ["prisma", "beego", "mongodb"],
        "recommended_capabilities": ["orm_leak", "nosql_sqli", "mass_assignment"],
        "confidence": 0.90
    }
]

class CrossTargetIntelligence:
    def __init__(self):
        self.target_database: Dict[str, Dict[str, Any]] = {}

    def register_target_findings(self, target: str, technologies: List[str], findings: List[str]) -> None:
        self.target_database[target] = {
            "technologies": technologies,
            "findings": findings
        }

    def correlate_stack_risks(self, detected_technologies: List[str]) -> List[Dict[str, Any]]:
        techs_lower = [t.lower() for t in detected_technologies]
        recommendations = []
        
        for rule in STACK_CORRELATION_RULES:
            if any(t in techs_lower for t in rule["technologies"]):
                recommendations.append({
                    "matched_techs": [t for t in rule["technologies"] if t in techs_lower],
                    "recommended_capabilities": rule["recommended_capabilities"],
                    "confidence": rule["confidence"]
                })
                
        return recommendations
