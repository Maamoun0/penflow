import pytest
import pytest_asyncio
from penflow.agents.injection.xxe_agent import XXECapabilityAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.infrastructure.oob_server import OOBCallbackServer

@pytest.mark.asyncio
async def test_xxe_agent_inband():
    agent = XXECapabilityAgent()
    ctx = CapabilityExecutionContext(asset="xml.example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("xxe_injection", ctx)
    assert res["status"] == "COMPLETED"
    assert "capability_id" in res

@pytest.mark.asyncio
async def test_xxe_agent_oob():
    agent = XXECapabilityAgent()
    oob = OOBCallbackServer.get_instance()
    ctx = CapabilityExecutionContext(asset="oobxml.example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("oob_xxe", ctx)
    assert res["status"] == "COMPLETED"
    assert "is_vulnerable" in res
