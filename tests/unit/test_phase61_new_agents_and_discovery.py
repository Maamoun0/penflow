import pytest
import pytest_asyncio
from penflow.agents import (
    DifferentialTimingAgent,
    CRLFInjectionAgent,
    MultipartParserBypassCapabilityAgent,
    PDOSQLiAgent,
    CL0SmugglingCapabilityAgent,
    DoubleClickjackingAgent,
    MCPServerAgent,
    WebAuthnBypassCapabilityAgent
)
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_differential_timing_dynamic_discovery(monkeypatch):
    class MockResponse:
        status_code = 401
        text = "Unauthorized"

    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ks = KnowledgeStore()
    ks.observations.record_observation("example.com", "endpoint_discovered", {"url": "https://example.com/custom/login"})

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=ks)
    agent = DifferentialTimingAgent()
    res = await agent.execute("differential_timing", ctx)

    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_crlf_injection_dynamic_discovery(monkeypatch):
    class MockResponse:
        status_code = 200
        headers = {"Set-Cookie": "penflow_crlf=1"}
        text = "ok"

    async def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ks = KnowledgeStore()
    ks.observations.record_observation("example.com", "endpoint_discovered", {"url": "https://example.com/custom/redirect"})

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=ks)
    agent = CRLFInjectionAgent()
    res = await agent.execute("crlf_injection", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_multipart_dynamic_discovery(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "shell.php uploaded successfully"

    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ks = KnowledgeStore()
    ks.observations.record_observation("example.com", "endpoint_discovered", {"url": "https://example.com/custom/upload"})

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=ks)
    agent = MultipartParserBypassCapabilityAgent()
    res = await agent.execute("multipart_parser_bypass", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_pdo_sqli_dynamic_discovery(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "PDOException SQLSTATE error"

    async def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ks = KnowledgeStore()
    ks.observations.record_observation("example.com", "endpoint_discovered", {"url": "https://example.com/custom/search"})

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=ks)
    agent = PDOSQLiAgent()
    res = await agent.execute("pdo_sqli_vulnerability", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_cl0_smuggling_dynamic_discovery(monkeypatch):
    class MockResponse:
        status_code = 403
        text = "Admin access forbidden"

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)
    monkeypatch.setattr("httpx.AsyncClient.get", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = CL0SmugglingCapabilityAgent()
    res = await agent.execute("cl0_smuggling", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_double_clickjacking_dynamic_discovery(monkeypatch):
    class MockResponse:
        status_code = 200
        headers = {}
        text = "Content page"

    async def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = DoubleClickjackingAgent()
    res = await agent.execute("double_clickjacking", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_mcp_server_agent(monkeypatch):
    class MockResponse:
        status_code = 200
        text = '{"jsonrpc": "2.0", "tools": [{"name": "exec"}]}'

    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = MCPServerAgent()
    res = await agent.execute("mcp_server_vulnerability", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_webauthn_bypass_agent(monkeypatch):
    class MockResponse:
        status_code = 200
        text = '{"token": "webauthn_jwt_session"}'

    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = WebAuthnBypassCapabilityAgent()
    res = await agent.execute("webauthn_passkey_bypass", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["_exchange_obj"] is not None
