import pytest
import pytest_asyncio
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
    NoSQLInjectionAgent
)
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.validation.quality_gate import PreReportQualityGate

@pytest.mark.asyncio
async def test_path_traversal_agent(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "root:x:0:0:root:/root:/bin/bash"

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = PathTraversalCapabilityAgent()
    res = await agent.execute("path_traversal", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["_exchange_obj"] is not None

@pytest.mark.asyncio
async def test_websocket_agent(monkeypatch):
    class MockResponse:
        status_code = 101
        headers = {"Sec-WebSocket-Accept": "dGhlIHNhbXBsZSBub25jZQ=="}
        text = ""

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = WebSocketCapabilityAgent()
    res = await agent.execute("cswsh_vulnerability", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_cloud_misconfig_agent(monkeypatch):
    class MockResponse:
        status_code = 200
        text = "<ListBucketResult><Contents><Key>backup.zip</Key></Contents></ListBucketResult>"

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = CloudMisconfigCapabilityAgent()
    res = await agent.execute("cloud_misconfig", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_second_order_injection_agent(monkeypatch):
    class MockResponsePost:
        status_code = 200
        text = "ok"

    class MockResponseGet:
        status_code = 200
        text = "SQL syntax error in bio"

    async def mock_post(*args, **kwargs):
        return MockResponsePost()

    async def mock_get(*args, **kwargs):
        return MockResponseGet()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)
    monkeypatch.setattr("httpx.AsyncClient.get", mock_get)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = SecondOrderInjectionAgent()
    res = await agent.execute("second_order_injection", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_api_version_regression_agent(monkeypatch):
    class MockResponse:
        status_code = 200
        text = '{"user_id": 100, "email": "admin@target.com"}'

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.get", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = APIVersionRegressionAgent()
    res = await agent.execute("api_version_regression", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_sqli_and_nosql_agents(monkeypatch):
    class MockResponse:
        status_code = 200
        text = '{"token": "admin_jwt_token"}'

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.post", mock_request)

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    agent = NoSQLInjectionAgent()
    res = await agent.execute("nosql_injection", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_phase2_gate2_quality_gate_integration(monkeypatch):
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])

    class MockResponse:
        status_code = 200
        text = "verified"

    async def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_request)

    finding = {
        "vulnerability_type": "path_traversal",
        "confidence": 0.95,
        "target_url": "https://example.com/download?file=../../../etc/passwd",
        "is_vulnerable": True,
        "_exchange_obj": {
            "request": {"method": "GET", "url": "https://example.com/download?file=../../../etc/passwd"},
            "response": {"status_code": 200, "body_snippet": "root:x:0:0"}
        }
    }

    admitted = await gate.filter_findings([finding])
    assert len(admitted) == 1
