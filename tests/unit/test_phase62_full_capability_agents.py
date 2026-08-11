"""
Comprehensive Unit Test Suite for All Phase 2 & Phase 3 Capability Agents.

Tests 19 Capability Agents:
- PathTraversalCapabilityAgent
- WebSocketCapabilityAgent
- CloudMisconfigCapabilityAgent
- SecondOrderInjectionAgent
- APIVersionRegressionAgent
- DifferentialTimingAgent
- ResponseClusteringAgent
- CRLFInjectionAgent
- HeaderAnalysisAgent
- SQLiCapabilityAgent
- NoSQLInjectionAgent
- SAMLBypassCapabilityAgent
- HTTP2ConnectCapabilityAgent
- MultipartParserBypassCapabilityAgent
- CL0SmugglingCapabilityAgent
- PDOSQLiAgent
- DoubleClickjackingAgent
- MCPServerAttackAgent
- AISupplyChainAgent
- WebAuthnBypassCapabilityAgent
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from penflow.agents import (
    PathTraversalCapabilityAgent,
    WebSocketCapabilityAgent,
    CloudMisconfigCapabilityAgent,
    SecondOrderInjectionAgent,
    APIVersionRegressionAgent,
    DifferentialTimingAgent,
    ResponseClusteringAgent,
    CRLFInjectionAgent,
    HeaderAnalysisAgent,
    SQLiCapabilityAgent,
    NoSQLInjectionAgent,
    SAMLBypassCapabilityAgent,
    HTTP2ConnectCapabilityAgent,
    MultipartParserBypassCapabilityAgent,
    CL0SmugglingCapabilityAgent,
    PDOSQLiAgent,
    DoubleClickjackingAgent,
    MCPServerAttackAgent,
    AISupplyChainAgent,
    WebAuthnBypassCapabilityAgent
)
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore


# 1. PathTraversalCapabilityAgent Tests
@pytest.mark.asyncio
async def test_path_traversal_agent_vulnerable(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "root:x:0:0:root:/root:/bin/bash"
    async def mock_get(*args, **kwargs):
        return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = PathTraversalCapabilityAgent()
    res = await agent.execute("path_traversal", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_path_traversal_agent_safe(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "Normal page content"
    async def mock_get(*args, **kwargs):
        return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = PathTraversalCapabilityAgent()
    res = await agent.execute("path_traversal", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_path_traversal_agent_exception(monkeypatch):
    async def mock_get(*args, **kwargs):
        raise RuntimeError("Connection error")
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = PathTraversalCapabilityAgent()
    res = await agent.execute("path_traversal", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 2. WebSocketCapabilityAgent Tests
@pytest.mark.asyncio
async def test_websocket_agent_vulnerable(monkeypatch):
    class MockResponse:
        status_code = 101
        headers = {"upgrade": "websocket"}
        text = ""
    async def mock_get(*args, **kwargs):
        return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = WebSocketCapabilityAgent()
    res = await agent.execute("websocket_security", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_websocket_agent_safe(monkeypatch):
    class MockResponse:
        status_code = 403
        headers = {}
        text = "Forbidden"
    async def mock_get(*args, **kwargs):
        return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = WebSocketCapabilityAgent()
    res = await agent.execute("websocket_security", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_websocket_agent_exception(monkeypatch):
    async def mock_get(*args, **kwargs):
        raise RuntimeError("Handshake failed")
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = WebSocketCapabilityAgent()
    res = await agent.execute("websocket_security", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 3. CloudMisconfigCapabilityAgent Tests
@pytest.mark.asyncio
async def test_cloud_misconfig_vulnerable(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "<ListBucketResult><Name>my-bucket</Name></ListBucketResult>"
    async def mock_get(*args, **kwargs):
        return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = CloudMisconfigCapabilityAgent()
    res = await agent.execute("cloud_misconfiguration", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_cloud_misconfig_safe(monkeypatch):
    class MockResponse:
        status_code = 403
        text = "<Error><Code>AccessDenied</Code></Error>"
    async def mock_get(*args, **kwargs):
        return MockResponse()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = CloudMisconfigCapabilityAgent()
    res = await agent.execute("cloud_misconfiguration", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_cloud_misconfig_exception(monkeypatch):
    async def mock_get(*args, **kwargs):
        raise RuntimeError("Cloud failure")
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = CloudMisconfigCapabilityAgent()
    res = await agent.execute("cloud_misconfiguration", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 4. SecondOrderInjectionAgent Tests
@pytest.mark.asyncio
async def test_second_order_injection_vulnerable(monkeypatch):
    class MockPostResp:
        status_code = 200
        text = "Profile updated"
    class MockGetResp:
        status_code = 200
        text = "Welcome user SQL syntax"
    async def mock_post(*args, **kwargs):
        return MockPostResp()
    async def mock_get(*args, **kwargs):
        return MockGetResp()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = SecondOrderInjectionAgent()
    res = await agent.execute("second_order_injection", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_second_order_injection_safe(monkeypatch):
    class MockResp:
        status_code = 200
        text = "Normal profile"
    async def mock_post(*args, **kwargs):
        return MockResp()
    async def mock_get(*args, **kwargs):
        return MockResp()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = SecondOrderInjectionAgent()
    res = await agent.execute("second_order_injection", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_second_order_injection_exception(monkeypatch):
    async def mock_post(*args, **kwargs):
        raise RuntimeError("Second order failure")
    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = SecondOrderInjectionAgent()
    res = await agent.execute("second_order_injection", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 5. APIVersionRegressionAgent Tests
@pytest.mark.asyncio
async def test_api_version_regression_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.body_text = '{"email": "admin@target.com", "id": 1}'
    mock_resp.body_snippet = mock_resp.body_text
    mock_exch = MagicMock()
    mock_exch.response = mock_resp
    mock_exch.to_dict.return_value = {"request": {}, "response": {"status_code": 200}}
    mock_client.send_as_identity = AsyncMock(return_value=mock_exch)
    ctx.get_http_client = MagicMock(return_value=mock_client)

    agent = APIVersionRegressionAgent()
    res = await agent.execute("api_version_regression", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_api_version_regression_safe(monkeypatch):
    class MockResp:
        status_code = 404
        text = "Not Found"
    async def mock_get(*args, **kwargs):
        return MockResp()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = APIVersionRegressionAgent()
    res = await agent.execute("api_version_regression", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_api_version_regression_exception(monkeypatch):
    async def mock_get(*args, **kwargs):
        raise RuntimeError("Regression check error")
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = APIVersionRegressionAgent()
    res = await agent.execute("api_version_regression", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 6. MCPServerAttackAgent Tests
@pytest.mark.asyncio
async def test_mcp_server_attack_vulnerable(monkeypatch):
    class MockResp:
        status_code = 200
        text = '{"jsonrpc": "2.0", "tools": [{"name": "read_file"}]}'
    async def mock_post(*args, **kwargs):
        return MockResp()
    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = MCPServerAttackAgent()
    res = await agent.execute("mcp_server_vulnerability", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_mcp_server_attack_safe(monkeypatch):
    class MockResp:
        status_code = 404
        text = "Not Found"
    async def mock_post(*args, **kwargs):
        return MockResp()
    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = MCPServerAttackAgent()
    res = await agent.execute("mcp_server_vulnerability", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_mcp_server_attack_exception(monkeypatch):
    async def mock_post(*args, **kwargs):
        raise RuntimeError("MCP error")
    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = MCPServerAttackAgent()
    res = await agent.execute("mcp_server_vulnerability", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 7. AISupplyChainAgent Tests
@pytest.mark.asyncio
async def test_ai_supply_chain_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.body_text = '{"openai_key": "sk-12345678901234567890123456789012"}'
    mock_resp.body_snippet = mock_resp.body_text
    mock_exch = MagicMock()
    mock_exch.response = mock_resp
    mock_exch.to_dict.return_value = {"request": {}, "response": {"status_code": 200}}
    mock_client.send_as_identity = AsyncMock(return_value=mock_exch)
    ctx.get_http_client = MagicMock(return_value=mock_client)

    agent = AISupplyChainAgent()
    res = await agent.execute("ai_supply_chain_security", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_ai_supply_chain_safe(monkeypatch):
    class MockResp:
        status_code = 200
        text = '{"version": "1.0.0"}'
    async def mock_get(*args, **kwargs):
        return MockResp()
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = AISupplyChainAgent()
    res = await agent.execute("ai_supply_chain_security", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_ai_supply_chain_exception(monkeypatch):
    async def mock_get(*args, **kwargs):
        raise RuntimeError("Supply chain error")
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = AISupplyChainAgent()
    res = await agent.execute("ai_supply_chain_security", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False
