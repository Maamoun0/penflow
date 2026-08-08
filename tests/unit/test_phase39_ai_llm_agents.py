import pytest
import pytest_asyncio
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.recon.llm_discovery import LLMEndpointDiscoverer
from penflow.agents import (
    PromptInjectionAgent,
    AIAgentSecurityAgent,
    RAGPoisoningDetector,
)

def test_llm_endpoint_discoverer():
    discoverer = LLMEndpointDiscoverer()
    endpoints = ["/api/v1/users", "/api/chat", "/copilot/chat", "/api/generate"]
    discovered = discoverer.discover_endpoints_from_crawl(endpoints)
    assert len(discovered) == 3
    
    headers = {"X-OpenAI-Processing-Ms": "150", "Content-Type": "application/json"}
    matched_headers = discoverer.analyze_headers(headers)
    assert len(matched_headers) == 1

    js_code = "const client = new OpenAI(); async function call() { const res = await client.chat.completions.create(); }"
    js_matches = discoverer.analyze_js_bundle(js_code)
    assert len(js_matches) > 0

@pytest.mark.asyncio
async def test_prompt_injection_agent():
    agent = PromptInjectionAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "prompt_injection_audit"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("prompt_injection_audit", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_ai_agent_security_agent():
    agent = AIAgentSecurityAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "ai_agent_security_audit"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("ai_agent_security_audit", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0

@pytest.mark.asyncio
async def test_rag_poisoning_agent():
    agent = RAGPoisoningDetector()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "rag_poisoning_audit"

    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("rag_poisoning_audit", ctx)
    assert isinstance(res, dict)
    assert res["is_vulnerable"] is True
    assert len(res["findings"]) > 0
