"""
Phase 36 Unit Tests — Week 2 Elite Capability Agents.
Verifies execution of:
  1. WebCachePoisoningCapabilityAgent
  2. PrototypePollutionCapabilityAgent
  3. BusinessLogicCapabilityAgent
  4. XXECapabilityAgent
  5. AccountTakeoverCapabilityAgent
"""
import pytest
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.agents import (
    WebCachePoisoningCapabilityAgent,
    PrototypePollutionCapabilityAgent,
    BusinessLogicCapabilityAgent,
    XXECapabilityAgent,
    AccountTakeoverCapabilityAgent
)


@pytest.mark.asyncio
async def test_cache_poisoning_agent():
    agent = WebCachePoisoningCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("cache_poisoning", ctx)
    assert res["capability_id"] == "cache_poisoning"
    assert isinstance(res["is_vulnerable"], bool)


@pytest.mark.asyncio
async def test_prototype_pollution_agent():
    agent = PrototypePollutionCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("prototype_pollution", ctx)
    assert res["capability_id"] == "prototype_pollution"
    assert isinstance(res["is_vulnerable"], bool)


@pytest.mark.asyncio
async def test_business_logic_agent():
    agent = BusinessLogicCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("business_logic_bypass", ctx)
    assert res["capability_id"] == "business_logic_bypass"
    assert isinstance(res["is_vulnerable"], bool)


@pytest.mark.asyncio
async def test_xxe_agent():
    agent = XXECapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("xxe_injection", ctx)
    assert res["capability_id"] == "xxe_injection"
    assert isinstance(res["is_vulnerable"], bool)


@pytest.mark.asyncio
async def test_account_takeover_agent():
    agent = AccountTakeoverCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("account_takeover", ctx)
    assert res["capability_id"] == "account_takeover"
    assert isinstance(res["is_vulnerable"], bool)
