import pytest
import pytest_asyncio
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.infrastructure.oob_server import OOBCallbackServer
from penflow.agents.business_logic_agent import BusinessLogicCapabilityAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_gate_2_poc_verification_active(monkeypatch):
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])
    
    # Mock httpx AsyncClient request to simulate reproducible PoC response
    class MockResponse:
        status_code = 200
        text = "metadata"

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)

    finding = {
        "vulnerability_type": "ssrf_metadata_exfiltration",
        "confidence": 0.95,
        "target_url": "https://example.com/api/fetch",
        "is_vulnerable": True,
        "_exchange_obj": {
            "request": {"method": "GET", "url": "https://example.com/api/fetch"},
            "response": {"status_code": 200, "body_snippet": "metadata"}
        }
    }

    admitted = await gate.filter_findings([finding])
    assert len(admitted) == 1

@pytest.mark.asyncio
async def test_live_oob_server_interactsh_configuration():
    server = OOBCallbackServer.get_instance()
    server.configure_interactsh("https://oob.interactsh.com")
    assert server._interactsh_enabled is True
    assert server.base_domain == "oob.interactsh.com"
    token = server.generate_token("testagent", "scan123")
    url = server.get_callback_url(token, protocol="http")
    assert "oob.interactsh.com" in url

@pytest.mark.asyncio
async def test_business_logic_dynamic_discovery():
    ks = KnowledgeStore()
    ks.observations.record_observation(
        asset_id="store.example.com",
        obs_type="endpoint_discovered",
        data={"url": "https://store.example.com/shop/v2/cart_checkout"}
    )
    ctx = CapabilityExecutionContext(asset="store.example.com", knowledge_store=ks)
    agent = BusinessLogicCapabilityAgent()
    endpoints = agent._discover_logic_endpoints(ctx)
    assert "checkout" in endpoints
    assert "https://store.example.com/shop/v2/cart_checkout" in endpoints["checkout"]
