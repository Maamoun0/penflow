import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from penflow.agents import (
    SAMLBypassCapabilityAgent,
    HTTP2ConnectCapabilityAgent,
    MultipartParserBypassCapabilityAgent,
    CL0SmugglingCapabilityAgent,
    PDOSQLiAgent,
    DoubleClickjackingAgent,
    MCPServerAgent,
    AISupplyChainAgent
)
from penflow.intelligence.auto_learning import AutoLearningEngine
from penflow.intelligence.semantic_dedup import SemanticDuplicateDetector
from penflow.validation.playwright_verifier import PlaywrightBrowserVerifier
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_saml_bypass_agent(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "SAML SSO admin token verified"
        headers = {"location": ""}

    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = SAMLBypassCapabilityAgent()
    res = await agent.execute("saml_auth_bypass", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["_exchange_obj"] is not None

@pytest.mark.asyncio
async def test_http2_connect_agent():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.body_text = "HTTP/2 Tunnel Established"
    mock_resp.body_snippet = mock_resp.body_text
    mock_exch = MagicMock()
    mock_exch.response = mock_resp
    mock_exch.to_dict.return_value = {"request": {}, "response": {"status_code": 200}}
    mock_client.send_as_identity = AsyncMock(return_value=mock_exch)
    ctx.get_http_client = MagicMock(return_value=mock_client)

    agent = HTTP2ConnectCapabilityAgent()
    res = await agent.execute("http2_connect_tunnel", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_multipart_and_cl0_agents(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "shell.php uploaded successfully"

    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = MultipartParserBypassCapabilityAgent()
    res = await agent.execute("multipart_parser_bypass", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_mcp_and_ai_supply_chain_agents(monkeypatch):
    class MockResponse:
        status_code = 200
        text = '{"jsonrpc": "2.0", "tools": [{"name": "read_file"}]}'

    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = MCPServerAgent()
    res = await agent.execute("mcp_server_vulnerability", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_phase4_intelligence_and_quality():
    auto_learner = AutoLearningEngine()
    techniques = auto_learner.extract_techniques_from_text("Discovered /api/v1/users/update with __proto__ pollution")
    assert "__proto__" in techniques

    dedup = SemanticDuplicateDetector()
    f1 = {"vulnerability_type": "sqli", "target_url": "https://example.com/api/search", "parameter": "q"}
    res1 = dedup.check_duplicate(f1)
    assert res1["is_duplicate"] is False

    res2 = dedup.check_duplicate(f1)
    assert res2["is_duplicate"] is True

    verifier = PlaywrightBrowserVerifier()
    v_res = verifier.verify_xss_execution("https://example.com")
    assert "verified" in v_res
