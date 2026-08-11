import pytest
import pytest_asyncio
from penflow.agents.modern.cspt_agent import ClientSidePathTraversalAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_cspt_agent_execution():
    agent = ClientSidePathTraversalAgent()
    ctx = CapabilityExecutionContext(asset="spa.example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("client_side_path_traversal", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "cspt_to_dom_xss_sink" for f in findings)
    assert any("target_sink" in f for f in findings)
