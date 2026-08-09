import pytest
import pytest_asyncio
from penflow.agents import (
    PrototypePollutionCapabilityAgent,
    AccountTakeoverCapabilityAgent,
    SecurityConfigCapabilityAgent,
    ParameterDiscoveryCapabilityAgent
)
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.validation.quality_gate import PreReportQualityGate

@pytest.mark.asyncio
async def test_prototype_pollution_strengthened(monkeypatch):
    class MockResponse:
        status_code = 200
        text = '{"polluted_flag": "penflow_pp_test"}'

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_request)
    monkeypatch.setattr("httpx.AsyncClient.get", mock_request)

    ks = KnowledgeStore()
    ks.observations.record_observation("example.com", "endpoint_discovered", {"url": "https://example.com/api/v1/user/profile"})
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=ks)
    agent = PrototypePollutionCapabilityAgent()
    res = await agent.execute("prototype_pollution", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["_exchange_obj"] is not None

@pytest.mark.asyncio
async def test_account_takeover_strengthened(monkeypatch):
    class MockResponse:
        status_code = 200
        text = 'evil-attacker-site.com'

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = AccountTakeoverCapabilityAgent()
    res = await agent.execute("password_reset_poisoning", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) >= 1

@pytest.mark.asyncio
async def test_security_config_strengthened():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = SecurityConfigCapabilityAgent()
    res = await agent.execute("security_config_audit", ctx)

    assert res["status"] == "COMPLETED"
    assert res["_exchange_obj"] is not None

@pytest.mark.asyncio
async def test_parameter_discovery_strengthened(monkeypatch):
    class MockResponse:
        status_code = 200
        text = 'role=admin'

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = ParameterDiscoveryCapabilityAgent()
    res = await agent.execute("parameter_discovery", ctx)

    assert res["status"] == "COMPLETED"
    assert res["_exchange_obj"] is not None

@pytest.mark.asyncio
async def test_phase1_gate2_quality_gate_integration(monkeypatch):
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])

    class MockResponse:
        status_code = 200
        text = "verified"

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)

    finding = {
        "vulnerability_type": "prototype_pollution",
        "confidence": 0.95,
        "target_url": "https://example.com/api/v1/user/profile",
        "is_vulnerable": True,
        "_exchange_obj": {
            "request": {"method": "POST", "url": "https://example.com/api/v1/user/profile"},
            "response": {"status_code": 200, "body_snippet": "polluted"}
        }
    }

    admitted = await gate.filter_findings([finding])
    assert len(admitted) == 1
