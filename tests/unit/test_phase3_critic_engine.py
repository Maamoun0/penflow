import pytest
import httpx
from penflow.knowledge.evidence_cas import EvidenceCAS
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.traffic.http_client import StatefulHttpClient

def test_critic_heuristic_verification():
    cas = EvidenceCAS()
    critic = CriticVerificationEngine()

    # 1. Valid Evidence
    raw = {
        "target_url": "https://target.com/api/v1/invoices/100",
        "is_vulnerable": True,
        "confidence_score": 0.85,
        "reasoning": "Cross-session IDOR vulnerability verified.",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://target.com/api/v1/invoices/100"},
                "response": {"status_code": 200, "body_text": '{"invoice_id": 100, "amount": 500}'}
            }
        ]
    }
    bundle = cas.store_evidence("target.com", "id_access_analysis", raw)
    res = critic.verify_finding(bundle)
    assert res["is_verified"] is True
    assert res["confidence_score"] >= 0.85

    # 2. Static asset falsification
    raw_static = {
        "target_url": "https://target.com/static/app.js",
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://target.com/static/app.js"},
                "response": {"status_code": 200, "body_text": "console.log('app');"}
            }
        ]
    }
    bundle_static = cas.store_evidence("target.com", "id_access_analysis", raw_static)
    res_static = critic.verify_finding(bundle_static)
    assert res_static["is_verified"] is False
    assert "static asset" in res_static["verification_reason"]

    # 3. Soft 404 / Soft Error falsification
    raw_soft = {
        "target_url": "https://target.com/api/user/99",
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "evidence_exchanges": [
            {
                "response": {
                    "status_code": 200,
                    "body_snippet": '{"status": "error", "message": "Access Denied: Session Expired"}'
                }
            }
        ]
    }
    bundle_soft = cas.store_evidence("target.com", "authorization", raw_soft)
    res_soft = critic.verify_finding(bundle_soft)
    assert res_soft["is_verified"] is False
    assert "Soft Error" in res_soft["verification_reason"]

@pytest.mark.asyncio
async def test_critic_active_unauthenticated_falsification():
    cas = EvidenceCAS()
    critic = CriticVerificationEngine()
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks)

    # Mock server returning 200 OK to unauthenticated guest for a public endpoint
    def public_endpoint_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"title": "Public News", "content": "Hello World"})

    transport = httpx.MockTransport(public_endpoint_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    raw_public = {
        "target_url": "https://target.com/news/1",
        "is_vulnerable": True,
        "confidence_score": 0.85,
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://target.com/news/1"},
                "response": {"status_code": 200, "body_text": '{"title": "Public News"}'}
            }
        ]
    }
    bundle_pub = cas.store_evidence("target.com", "id_access_analysis", raw_public)
    
    # Active verification should recognize endpoint is public and falsify it
    res_async = await critic.verify_finding_async(bundle_pub, ctx)
    assert res_async["is_verified"] is False
    assert "publicly accessible" in res_async["verification_reason"]
