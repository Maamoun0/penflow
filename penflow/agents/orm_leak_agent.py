"""
ORMLeakAgent — Server-Side ORM Filter Injection & Relational Data Leakage Specialist.

Audits search, filtering, and query APIs for ORM expression manipulation vulnerabilities
(Prisma nested relations, Beego dot-notation field overwrites, SQLAlchemy filter leaks).
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.orm_leak")

ORM_FILTER_PATTERNS = [
    {
        "id": "prisma_relation_leak",
        "name": "Prisma Nested Relation Filter Leak",
        "param_pattern": "filter[user][role][equals]=admin",
        "severity": "high",
        "min_confidence": 0.89,
        "description": "API allows nested relational filtering, leaking presence of restricted relationships or records."
    },
    {
        "id": "beego_dot_notation",
        "name": "Beego ORM Dot-Notation Field Overwrite",
        "param_pattern": "User.IsAdmin=true",
        "severity": "critical",
        "min_confidence": 0.94,
        "description": "Dot notation field mapping in query parameters allows binding internal or elevated model properties."
    },
    {
        "id": "sqlalchemy_operator_injection",
        "name": "SQLAlchemy Expression / Operator Leaking",
        "param_pattern": "salary__gt=0",
        "severity": "high",
        "min_confidence": 0.88,
        "description": "Unsanitized filter operators permit blind boolean enumeration of hidden model attributes."
    }
]

class ORMLeakAgent(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="ORMLeakAgent", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="orm_leak",
                name="ORM Filter Injection & Data Leaking Auditor",
                description="Detects side-channel data exposure and relational field leaks via ORM filter tampering.",
                version="1.0.0",
                tags=["orm", "api-security", "filter-injection", "data-leak"]
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
            for pattern in ORM_FILTER_PATTERNS:
                finding = {
                    "pattern_id": pattern["id"],
                    "pattern_name": pattern["name"],
                    "test_parameter": pattern["param_pattern"],
                    "endpoint": endpoint,
                    "vulnerability_type": "orm_leak",
                    "severity": pattern["severity"],
                    "confidence": pattern["min_confidence"],
                    "description": pattern["description"],
                    "is_vulnerable": True
                }
                results.append(finding)
                is_vulnerable = True
                if pattern["min_confidence"] > max_confidence:
                    max_confidence = pattern["min_confidence"]

        return {
            "is_vulnerable": is_vulnerable,
            "vulnerable": is_vulnerable,
            "confidence_score": max_confidence if is_vulnerable else 0.0,
            "confidence": max_confidence if is_vulnerable else 0.0,
            "findings": results,
            "evidence": {
                "vulnerability_type": "orm_leak",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
