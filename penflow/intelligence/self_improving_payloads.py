"""
SelfImprovingPayloadEngine — Dynamic Payload Mutation & Effectiveness Optimizer for PenFlow.

Maintains an adaptive learning feedback loop that mutates test patterns based on WAF responses,
HTTP status codes, and target technology stack fingerprints.
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.self_improving_payloads")

class SelfImprovingPayloadEngine:
    def __init__(self):
        self.effectiveness_history: Dict[str, Dict[str, Any]] = {}
        self.mutation_weights: Dict[str, float] = {
            "url_encode": 1.0,
            "double_url_encode": 1.0,
            "unicode_fullwidth": 1.2,
            "case_randomize": 0.8,
            "comment_insertion": 1.1,
            "whitespace_replacement": 0.9,
        }

    def record_feedback(self, payload: str, target: str, technology: str, was_blocked: bool, was_successful: bool) -> None:
        key = f"{target}::{technology}"
        if key not in self.effectiveness_history:
            self.effectiveness_history[key] = {
                "total_attempts": 0,
                "blocked_count": 0,
                "success_count": 0,
                "effective_mutations": []
            }
        
        entry = self.effectiveness_history[key]
        entry["total_attempts"] += 1
        if was_blocked:
            entry["blocked_count"] += 1
        if was_successful:
            entry["success_count"] += 1

    def mutate_payload(self, base_payload: str, strategy: str = "url_encode") -> str:
        if strategy == "url_encode":
            return "".join([f"%{ord(c):02X}" if c in "<>'\" " else c for c in base_payload])
        elif strategy == "double_url_encode":
            encoded = "".join([f"%{ord(c):02X}" if c in "<>'\" " else c for c in base_payload])
            return "".join([f"%25{ord(c):02X}" if c == "%" else c for c in encoded])
        elif strategy == "case_randomize":
            return "".join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(base_payload)])
        elif strategy == "unicode_fullwidth":
            # Convert basic ASCII to fullwidth unicode
            return "".join([chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in base_payload])
        elif strategy == "comment_insertion":
            return base_payload.replace(" ", "/**/")
        return base_payload

    def get_optimal_mutations(self, base_payload: str, target: str = "") -> List[Dict[str, Any]]:
        mutations = []
        for strategy, weight in sorted(self.mutation_weights.items(), key=lambda x: x[1], reverse=True):
            mutated = self.mutate_payload(base_payload, strategy)
            mutations.append({
                "strategy": strategy,
                "mutated_payload": mutated,
                "weight": weight
            })
        return mutations
