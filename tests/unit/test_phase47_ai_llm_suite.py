import pytest
import pytest_asyncio
from penflow.agents.prompt_injection_agent import PromptInjectionAgent
from penflow.agents.ai_agent_security_agent import AIAgentSecurityAgent
from penflow.agents.rag_poisoning_agent import RAGPoisoningDetector
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_prompt_injection_agent_execution():
    agent = PromptInjectionAgent()
    ctx = CapabilityExecutionContext(asset="ai.example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("prompt_injection_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "markdown_image_data_exfiltration" for f in findings)
    assert any(f["vector_id"] == "unicode_tag_char_injection" for f in findings)

@pytest.mark.asyncio
async def test_ai_agent_security_agent():
    agent = AIAgentSecurityAgent()
    ctx = CapabilityExecutionContext(asset="agent.example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("ai_agent_security_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "unauthorized_tool_invocation" for f in findings)

@pytest.mark.asyncio
async def test_rag_poisoning_detector():
    agent = RAGPoisoningDetector()
    ctx = CapabilityExecutionContext(asset="rag.example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("rag_poisoning_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "cross_tenant_document_leak" for f in findings)
