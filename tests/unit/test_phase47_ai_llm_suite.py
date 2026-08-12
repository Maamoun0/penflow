import pytest
import pytest_asyncio
from penflow.agents.ai.prompt_injection_agent import PromptInjectionAgent
from penflow.agents.ai.ai_agent_security_agent import AIAgentSecurityAgent
from penflow.agents.ai.rag_poisoning_agent import RAGPoisoningDetector
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

import httpx
from penflow.traffic.http_client import StatefulHttpClient

@pytest.mark.asyncio
async def test_prompt_injection_agent_execution():
    agent = PromptInjectionAgent()
    ctx = CapabilityExecutionContext(asset="ai.example.com", knowledge_store=KnowledgeStore())

    def mock_handler(req: httpx.Request) -> httpx.Response:
        url_str = str(req.url)
        content = req.read().decode("utf-8")
        if "PENFLOW_CONFIRMED_OVERRIDE" in content:
            return httpx.Response(200, json={"response": "PENFLOW_CONFIRMED_OVERRIDE"})
        return httpx.Response(200, json={"response": "Normal LLM Output"})

    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["ai.example.com"],
        custom_transport=httpx.MockTransport(mock_handler),
        rate_limit_rps=100.0
    )

    res = await agent.execute("prompt_injection_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "role_switch_override" for f in findings)

@pytest.mark.asyncio
async def test_ai_agent_security_agent():
    agent = AIAgentSecurityAgent()
    ctx = CapabilityExecutionContext(asset="agent.example.com", knowledge_store=KnowledgeStore())

    def mock_handler(req: httpx.Request) -> httpx.Response:
        content = req.read().decode("utf-8")
        if "AI_AGENT_TOOL_EXEC_CONFIRMED" in content:
            return httpx.Response(200, json={"result": "AI_AGENT_TOOL_EXEC_CONFIRMED"})
        return httpx.Response(200, json={"result": "Tool denied"})

    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["agent.example.com"],
        custom_transport=httpx.MockTransport(mock_handler),
        rate_limit_rps=100.0
    )

    res = await agent.execute("ai_agent_security_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "unauthorized_tool_invocation" for f in findings)

@pytest.mark.asyncio
async def test_rag_poisoning_detector():
    agent = RAGPoisoningDetector()
    ctx = CapabilityExecutionContext(asset="rag.example.com", knowledge_store=KnowledgeStore())

    def mock_handler(req: httpx.Request) -> httpx.Response:
        content = req.read().decode("utf-8")
        if "PENFLOW_RAG_POISON_VERIFIED" in content:
            return httpx.Response(200, json={"output": "PENFLOW_RAG_POISON_VERIFIED"})
        return httpx.Response(200, json={"output": "Safe knowledge context"})

    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["rag.example.com"],
        custom_transport=httpx.MockTransport(mock_handler),
        rate_limit_rps=100.0
    )

    res = await agent.execute("rag_poisoning_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "ingestion_instruction_hijack" for f in findings)
