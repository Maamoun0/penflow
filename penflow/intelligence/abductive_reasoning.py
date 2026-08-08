"""
AbductiveReasoningEngine — Abductive Security Inference & Hypothesis Chaining.

Infers non-obvious vulnerability hypotheses from endpoint names, URL parameters, and response structures
(e.g., /api/v1/export -> CSV Formula Injection + IDOR; /api/checkout -> Race Condition + Negative Value Tampering).
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.abductive_reasoning")

ABDUCTIVE_RULES = [
    {
        "endpoint_pattern": "export",
        "hypotheses": [
            {"capability": "idor", "rationale": "Data export endpoints frequently leak other tenant records via object ID manipulation."},
            {"capability": "info_disclosure", "rationale": "Export files frequently contain internal metadata or unsanitized fields."}
        ]
    },
    {
        "endpoint_pattern": "checkout|order|pay|transfer",
        "hypotheses": [
            {"capability": "race_condition", "rationale": "Financial and checkout workflows are susceptible to concurrent state race conditions."},
            {"capability": "mass_assignment", "rationale": "Payment bodies may allow overriding amount, discount, or currency fields."}
        ]
    },
    {
        "endpoint_pattern": "invite|collaborator|team|member",
        "hypotheses": [
            {"capability": "bfla", "rationale": "Membership and invite APIs often exhibit Broken Function Level Authorization."},
            {"capability": "account_takeover", "rationale": "Invitation token parameters may allow account pre-hijacking."}
        ]
    },
    {
        "endpoint_pattern": "chat|ai|assistant|prompt",
        "hypotheses": [
            {"capability": "prompt_injection_audit", "rationale": "Conversational endpoints process natural language and may suffer prompt boundary violations."},
            {"capability": "ai_agent_security_audit", "rationale": "AI chat interfaces often connect to tool-calling agents."}
        ]
    }
]

class AbductiveReasoningEngine:
    def __init__(self):
        pass

    def infer_hypotheses(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        inferred = []
        for ep in endpoints:
            ep_lower = ep.lower()
            for rule in ABDUCTIVE_RULES:
                patterns = rule["endpoint_pattern"].split("|")
                if any(p in ep_lower for p in patterns):
                    for hyp in rule["hypotheses"]:
                        inferred.append({
                            "endpoint": ep,
                            "recommended_capability": hyp["capability"],
                            "rationale": hyp["rationale"]
                        })
        return inferred
