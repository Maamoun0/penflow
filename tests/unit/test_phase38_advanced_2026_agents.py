import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.agents import (
    UnicodeNormalizationAgent,
    ParserDifferentialAgent,
    ORMLeakAgent,
    NovelSSRFRedirectAgent,
    XSLeakAgent,
    FrameworkCachePoisoningAgent,
    PolyglotSSTIAgent,
    ClientSidePathTraversalAgent,
)


def _mock_vulnerable_ctx(body="root:x:0:0:root", status_code=200):
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.body_text = body
    mock_resp.body_snippet = body
    mock_resp.headers = {"etag": "\"123456\""}
    mock_exch = MagicMock()
    mock_exch.response = mock_resp
    mock_exch.to_dict.return_value = {"request": {}, "response": {"status_code": status_code}}
    mock_client.send_as_identity = AsyncMock(return_value=mock_exch)
    ctx.get_http_client = MagicMock(return_value=mock_client)
    return ctx


@pytest.mark.asyncio
async def test_unicode_normalization_agent():
    agent = UnicodeNormalizationAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "unicode_normalization"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("unicode_normalization", ctx)
    assert isinstance(res, dict)
    assert res["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_parser_differential_agent():
    agent = ParserDifferentialAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "parser_differential"

    ctx = _mock_vulnerable_ctx("Welcome admin! System internal details.")
    res = await agent.execute("parser_differential", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_orm_leak_agent():
    agent = ORMLeakAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "orm_leak"

    ctx = _mock_vulnerable_ctx("UnhandledRejectionError: SequelizeDatabaseError")
    res = await agent.execute("orm_leak", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_novel_ssrf_redirect_agent():
    agent = NovelSSRFRedirectAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "ssrf_redirect_chain"

    ctx = _mock_vulnerable_ctx("ami-id: ami-12345678")
    res = await agent.execute("ssrf_redirect_chain", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_xs_leak_agent():
    agent = XSLeakAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "xs_leak"

    ctx = _mock_vulnerable_ctx("", status_code=304)
    res = await agent.execute("xs_leak", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_framework_cache_poisoning_agent():
    agent = FrameworkCachePoisoningAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "framework_cache_poisoning"

    ctx = _mock_vulnerable_ctx("Served from cache evil-example.com")
    res = await agent.execute("framework_cache_poisoning", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_polyglot_ssti_agent():
    agent = PolyglotSSTIAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "polyglot_ssti"

    ctx = _mock_vulnerable_ctx("Result: 7777777")
    res = await agent.execute("polyglot_ssti", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True


@pytest.mark.asyncio
async def test_client_side_path_traversal_agent():
    agent = ClientSidePathTraversalAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "client_side_path_traversal"

    ctx = _mock_vulnerable_ctx("root:x:0:0:root")
    res = await agent.execute("client_side_path_traversal", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True

