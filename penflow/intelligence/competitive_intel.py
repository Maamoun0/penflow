"""
CompetitiveIntelligenceModule — Bug Bounty Market & Category Saturation Analyzer.

Prioritizes unsaturated, high-yield vulnerability categories by analyzing disclosure trends
and guiding research toward areas competitors overlook (e.g., SSRF, Race Conditions, AI Endpoints).
"""
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.competitive_intel")

CATEGORY_MARKET_SATURATION = {
    "xss": {"saturation": "very_high", "priority_weight": 0.5},
    "info_disclosure": {"saturation": "high", "priority_weight": 0.6},
    "open_redirect": {"saturation": "high", "priority_weight": 0.6},
    "ssrf": {"saturation": "low", "priority_weight": 1.5},
    "race_condition": {"saturation": "low", "priority_weight": 1.6},
    "business_logic": {"saturation": "low", "priority_weight": 1.5},
    "prompt_injection_audit": {"saturation": "minimal", "priority_weight": 2.0},
    "ai_agent_security_audit": {"saturation": "minimal", "priority_weight": 2.0},
    "parser_differential": {"saturation": "minimal", "priority_weight": 1.8},
    "unicode_normalization": {"saturation": "low", "priority_weight": 1.7},
}

class CompetitiveIntelligenceModule:
    def __init__(self):
        pass

    def prioritize_capabilities(self, candidate_capabilities: List[str]) -> List[Dict[str, Any]]:
        ranked = []
        for cap in candidate_capabilities:
            info = CATEGORY_MARKET_SATURATION.get(cap, {"saturation": "medium", "priority_weight": 1.0})
            ranked.append({
                "capability": cap,
                "saturation": info["saturation"],
                "priority_weight": info["priority_weight"]
            })
        
        # Sort by highest priority weight descending
        ranked.sort(key=lambda x: x["priority_weight"], reverse=True)
        return ranked
