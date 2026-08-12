import pytest
import pytest_asyncio
from penflow.agents.modern.cspt_agent import ClientSidePathTraversalAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

import httpx
from penflow.traffic.http_client import StatefulHttpClient

@pytest.mark.asyncio
async def test_cspt_agent_execution():
    agent = ClientSidePathTraversalAgent()
    ctx = CapabilityExecutionContext(asset="spa.example.com", knowledge_store=KnowledgeStore())

    def mock_handler(req: httpx.Request) -> httpx.Response:
        url_str = str(req.url)
        if "/../../public/user_content.json" in url_str:
            return httpx.Response(302, headers={"location": "https://spa.example.com/settings"})
        return httpx.Response(200, text="Normal Page")

    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["spa.example.com"],
        custom_transport=httpx.MockTransport(mock_handler),
        rate_limit_rps=100.0
    )

    res = await agent.execute("client_side_path_traversal", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "cspt_to_dom_xss_sink" for f in findings)
    assert any("target_sink" in f for f in findings)
