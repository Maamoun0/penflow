"""
ORMLeakAgent — Server-Side ORM Filter Injection & Relational Data Leakage Specialist.

Audits search, filtering, and query APIs for ORM expression manipulation vulnerabilities
(Prisma nested relations, Beego dot-notation field overwrites, SQLAlchemy filter leaks).
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.base.capability_agent import BaseCapabilityAgent
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
        logger.info(f"[ORMLeakAgent] Executing capability '{capability_id}' on asset '{context.asset}'")

        http_client = context.get_http_client()
        target_urls = self._collect_endpoints(context)

        results: List[Dict[str, Any]] = []
        is_vulnerable = False
        max_confidence = 0.0
        best_target = target_urls[0] if target_urls else f"https://{context.asset}"
        best_reasoning = "ORM filter inputs safely handled by application without data or error leaks."

        orm_stack_keywords = ["sequelize", "prisma", "beego", "sqlalchemy", "hibernate", "typeorm", "mongoose", "pymongo", "unhandledrejectionerror"]

        for endpoint in target_urls[:6]:
            # Send baseline request first
            try:
                base_exch = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=endpoint)
                base_resp = base_exch.response if base_exch else None
                base_len = len(base_resp.body_text or base_resp.body_snippet or "") if base_resp else 0

                for pattern in ORM_FILTER_PATTERNS:
                    test_url = f"{endpoint}?{pattern['param_pattern']}" if "?" not in endpoint else f"{endpoint}&{pattern['param_pattern']}"
                    exch = await http_client.send_as_identity(identity_id="anonymous_guest", method="GET", url=test_url)
                    resp = exch.response
                    if not resp:
                        continue

                    body_text = (resp.body_text or resp.body_snippet or "").lower()
                    exch_dict = exch.to_dict()
                    headers = resp.headers if isinstance(resp.headers, dict) else {}
                    content_type = str(headers.get("content-type", "")).lower()
                    is_html = "text/html" in content_type or "<!doctype html" in body_text or "<html" in body_text

                    # Detection logic:
                    # 1. Check for genuine exposed ORM stack traces or internal model exceptions
                    orm_trace_patterns = [
                        "at sequelize.", "prisma client", "prisma.error", "sqlalchemy.exc.",
                        "org.hibernate.exception", "typeorm error", "mongooseerror:",
                        "unhandledrejectionerror: sequelize", "beego orm error"
                    ]
                    stack_exposed = any(pat in body_text for pat in orm_trace_patterns)

                    # 2. Check for anomalous JSON API record expansion (only for JSON API endpoints, never public HTML pages!)
                    diff_exposed = (
                        not is_html and "application/json" in content_type and
                        base_len > 0 and curr_len > (base_len * 1.8) and resp.status_code == 200
                    )

                    if stack_exposed or diff_exposed:
                        is_vulnerable = True
                        confidence = pattern["min_confidence"]
                        reasoning = f"HIGH ORM Data Leakage Proven [{pattern['name']}]: Endpoint '{endpoint}' exposed internal ORM data or stack trace with payload '{pattern['param_pattern']}'."

                        if confidence > max_confidence:
                            max_confidence = confidence
                            best_target = test_url
                            best_reasoning = reasoning

                        results.append({
                            "pattern_id": pattern["id"],
                            "pattern_name": pattern["name"],
                            "test_parameter": pattern["param_pattern"],
                            "endpoint": endpoint,
                            "vulnerability_type": "orm_leak",
                            "severity": pattern["severity"],
                            "confidence": confidence,
                            "description": reasoning,
                            "is_vulnerable": True,
                            "_exchange_obj": exch_dict
                        })
            except Exception as e:
                logger.debug(f"[ORMLeakAgent] ORM probe error on {endpoint}: {e}")

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
                "vulnerability_type": "orm_leak",
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

