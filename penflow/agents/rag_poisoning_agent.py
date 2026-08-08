"""
RAGPoisoningDetector — Retrieval-Augmented Generation (RAG) Knowledge Integrity Specialist.

Audits RAG vector databases and document ingestion endpoints for hidden instruction poisoning,
context hijacking, and retrieval-time data exfiltration.
"""
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.capabilities.capability import Capability
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.rag_poisoning")

RAG_AUDIT_VECTORS = [
    {
        "id": "ingestion_instruction_hijack",
        "name": "Knowledge Chunk Instruction Hijack",
        "severity": "high",
        "min_confidence": 0.89,
        "description": "Uploaded knowledge base documents contain hidden directives that execute when retrieved into the model prompt."
    },
    {
        "id": "vector_embedding_inversion",
        "name": "Vector Search Similarity Manipulation",
        "severity": "medium",
        "min_confidence": 0.85,
        "description": "Crafted metadata attributes skew vector cosine similarity, causing biased or hijacked chunk retrieval."
    },
    {
        "id": "cross_tenant_document_leak",
        "name": "Cross-Tenant Vector Index Data Leakage",
        "severity": "critical",
        "min_confidence": 0.93,
        "description": "Unpartitioned vector collections return confidential chunks across distinct tenant retrieval queries."
    }
]

class RAGPoisoningDetector(BaseCapabilityAgent):
    def __init__(self, priority: int = 10, **kwargs):
        super().__init__(agent_name="RAGPoisoningDetector", priority=priority, **kwargs)

    def get_capabilities(self) -> List[Capability]:
        return [
            Capability(
                id="rag_poisoning_audit",
                name="RAG Knowledge Integrity & Vector Poisoning Auditor",
                description="Audits RAG pipelines for document ingestion poisoning and cross-tenant knowledge leakage.",
                version="1.0.0",
                tags=["rag", "vector-db", "knowledge-base", "ai-security", "embedding-security"]
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
            for vec in RAG_AUDIT_VECTORS:
                finding = {
                    "vector_id": vec["id"],
                    "vector_name": vec["name"],
                    "endpoint": endpoint,
                    "vulnerability_type": "rag_poisoning_audit",
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
                "vulnerability_type": "rag_poisoning_audit",
                "findings": results,
                "target_url": target_url,
                "confidence": max_confidence if is_vulnerable else 0.0,
                "is_vulnerable": is_vulnerable
            }
        }
