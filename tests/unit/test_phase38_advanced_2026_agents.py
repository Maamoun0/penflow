import pytest
import pytest_asyncio
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

@pytest.mark.asyncio
async def test_unicode_normalization_agent():
    agent = UnicodeNormalizationAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "unicode_normalization"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("unicode_normalization", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_parser_differential_agent():
    agent = ParserDifferentialAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "parser_differential"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("parser_differential", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_orm_leak_agent():
    agent = ORMLeakAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "orm_leak"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("orm_leak", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_novel_ssrf_redirect_agent():
    agent = NovelSSRFRedirectAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "ssrf_redirect_chain"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("ssrf_redirect_chain", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_xs_leak_agent():
    agent = XSLeakAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "xs_leak"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("xs_leak", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_framework_cache_poisoning_agent():
    agent = FrameworkCachePoisoningAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "framework_cache_poisoning"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("framework_cache_poisoning", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_polyglot_ssti_agent():
    agent = PolyglotSSTIAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "polyglot_ssti"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("polyglot_ssti", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_client_side_path_traversal_agent():
    agent = ClientSidePathTraversalAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "client_side_path_traversal"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("client_side_path_traversal", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0
