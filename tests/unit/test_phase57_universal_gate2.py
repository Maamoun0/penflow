import pytest
import pytest_asyncio
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.knowledge.evidence_cas import EvidenceCAS
from penflow.agents import (
    IDORCapabilityAgent,
    BFLACapabilityAgent,
    OAuthJWTCapabilityAgent,
    XXECapabilityAgent,
    RaceConditionCapabilityAgent,
    WebCachePoisoningCapabilityAgent,
    BusinessLogicCapabilityAgent
)

@pytest.mark.asyncio
async def test_critic_preserves_exchange_obj_for_gate2(monkeypatch):
    cas = EvidenceCAS()
    critic = CriticVerificationEngine()
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])

    class MockResponse:
        status_code = 200
        text = "verified"

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)

    # Test raw traces containing evidence_exchanges or _exchange_obj
    raw_traces = {
        "target_url": "https://example.com/api/v1/user/100",
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "_exchange_obj": {
            "request": {"method": "GET", "url": "https://example.com/api/v1/user/100"},
            "response": {"status_code": 200, "body_snippet": "profile_data"}
        }
    }

    bundle = cas.store_evidence("example.com", "id_access_analysis", raw_traces)
    verified = critic.verify_finding(bundle)
    assert verified["is_verified"] is True
    assert "_exchange_obj" in verified

    # Pass through Quality Gate
    admitted = await gate.filter_findings([verified])
    assert len(admitted) == 1
