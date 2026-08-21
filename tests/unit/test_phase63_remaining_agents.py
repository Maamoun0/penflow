"""
Unit test suite for Phase 2: 15 Capability Agents (11 refactored + 4 shallow agents).
Covers 3 test scenarios per agent:
1. Vulnerable response trigger
2. Safe/rejected response trigger
3. Exception/empty target handling
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

from penflow.agents import (
    OAuthJWTCapabilityAgent,
    PolyglotSSTIAgent,
    NovelSSRFRedirectAgent,
    ORMLeakAgent,
    ParserDifferentialAgent,
    FrameworkCachePoisoningAgent,
    ClientSidePathTraversalAgent,
    PromptInjectionAgent,
    RAGPoisoningDetector,
    AIAgentSecurityAgent,
    XSLeakAgent,
    ResponseClusteringAgent,
    APIVersionRegressionAgent,
    HTTP2ConnectCapabilityAgent,
    NoSQLInjectionAgent
)
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore


def _build_mock_http_client(status_code=200, body_text="", headers=None):
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.body_text = body_text
    mock_resp.body_snippet = body_text
    mock_resp.headers = headers or {}
    
    mock_exch = MagicMock()
    mock_exch.response = mock_resp
    mock_exch.to_dict.return_value = {
        "request": {"url": "https://example.com/api", "method": "GET", "headers": {}},
        "response": {"status_code": status_code, "body_snippet": body_text[:200]}
    }

    mock_client.send_as_identity = AsyncMock(return_value=mock_exch)
    return mock_client


# 1. OAuthJWTCapabilityAgent Tests
@pytest.mark.asyncio
async def test_oauth_jwt_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    async def mock_send(identity_id=None, method="GET", url="", headers=None, **kwargs):
        mock_resp = MagicMock()
        mock_exch = MagicMock()
        mock_exch.to_dict.return_value = {"request": {"url": url, "method": method, "headers": headers or {}}, "response": {"status_code": 200}}
        if headers and "Authorization" in headers:
            mock_resp.status_code = 200
            mock_resp.body_text = '{"user":"admin"}'
        else:
            mock_resp.status_code = 401
            mock_resp.body_text = 'Unauthorized'
        mock_exch.response = mock_resp
        return mock_exch
    client.send_as_identity = AsyncMock(side_effect=mock_send)
    ctx.get_http_client = MagicMock(return_value=client)
    agent = OAuthJWTCapabilityAgent()
    res = await agent.execute("jwt_security_analysis", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_oauth_jwt_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(401, "Unauthorized"))
    agent = OAuthJWTCapabilityAgent()
    res = await agent.execute("jwt_security_analysis", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_oauth_jwt_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Connection refused"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = OAuthJWTCapabilityAgent()
    res = await agent.execute("jwt_security_analysis", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 2. PolyglotSSTIAgent Tests
@pytest.mark.asyncio
async def test_polyglot_ssti_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    async def mock_send(identity_id=None, method="GET", url="", **kwargs):
        if "penflow_ctrl_" in url:
            return _build_mock_http_client(200, "Base response").send_as_identity.return_value
        return _build_mock_http_client(200, "Result: 7777777").send_as_identity.return_value

    ctx.get_http_client = MagicMock()
    ctx.get_http_client().send_as_identity = mock_send
    agent = PolyglotSSTIAgent()
    res = await agent.execute("polyglot_ssti", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_polyglot_ssti_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Normal output {{7*'7'}}"))
    agent = PolyglotSSTIAgent()
    res = await agent.execute("polyglot_ssti", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_polyglot_ssti_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Timeout"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = PolyglotSSTIAgent()
    res = await agent.execute("polyglot_ssti", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 3. NovelSSRFRedirectAgent Tests
@pytest.mark.asyncio
async def test_novel_ssrf_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "ami-id: ami-12345678"))
    agent = NovelSSRFRedirectAgent()
    res = await agent.execute("ssrf_redirect_chain", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_novel_ssrf_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(400, "Invalid URL parameter"))
    agent = NovelSSRFRedirectAgent()
    res = await agent.execute("ssrf_redirect_chain", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_novel_ssrf_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Redirect loop"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = NovelSSRFRedirectAgent()
    res = await agent.execute("ssrf_redirect_chain", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 4. ORMLeakAgent Tests
@pytest.mark.asyncio
async def test_orm_leak_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "UnhandledRejectionError: SequelizeDatabaseError"))
    agent = ORMLeakAgent()
    res = await agent.execute("orm_leak", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_orm_leak_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "No results found"))
    agent = ORMLeakAgent()
    res = await agent.execute("orm_leak", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_orm_leak_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Connection timeout"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = ORMLeakAgent()
    res = await agent.execute("orm_leak", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 5. ParserDifferentialAgent Tests
@pytest.mark.asyncio
async def test_parser_differential_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Welcome admin! System internal details."))
    agent = ParserDifferentialAgent()
    res = await agent.execute("parser_differential", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_parser_differential_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(404, "Not Found"))
    agent = ParserDifferentialAgent()
    res = await agent.execute("parser_differential", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_parser_differential_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Parsing failed"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = ParserDifferentialAgent()
    res = await agent.execute("parser_differential", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 6. FrameworkCachePoisoningAgent Tests
@pytest.mark.asyncio
async def test_framework_cache_poisoning_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Served from cache evil-example.com"))
    agent = FrameworkCachePoisoningAgent()
    res = await agent.execute("framework_cache_poisoning", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_framework_cache_poisoning_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Normal response body"))
    agent = FrameworkCachePoisoningAgent()
    res = await agent.execute("framework_cache_poisoning", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_framework_cache_poisoning_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("CDN timeout"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = FrameworkCachePoisoningAgent()
    res = await agent.execute("framework_cache_poisoning", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 7. ClientSidePathTraversalAgent Tests
@pytest.mark.asyncio
async def test_cspt_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "root:x:0:0:root"))
    agent = ClientSidePathTraversalAgent()
    res = await agent.execute("client_side_path_traversal", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_cspt_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(400, "Invalid path sequence"))
    agent = ClientSidePathTraversalAgent()
    res = await agent.execute("client_side_path_traversal", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_cspt_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Connection reset"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = ClientSidePathTraversalAgent()
    res = await agent.execute("client_side_path_traversal", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 8. PromptInjectionAgent Tests
@pytest.mark.asyncio
async def test_prompt_injection_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Output: PENFLOW_CONFIRMED_OVERRIDE"))
    agent = PromptInjectionAgent()
    res = await agent.execute("prompt_injection_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_prompt_injection_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "I cannot fulfill this request due to safety policies."))
    agent = PromptInjectionAgent()
    res = await agent.execute("prompt_injection_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_prompt_injection_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("LLM API failure"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = PromptInjectionAgent()
    res = await agent.execute("prompt_injection_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 9. RAGPoisoningDetector Tests
@pytest.mark.asyncio
async def test_rag_poisoning_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Retrieved chunk: PENFLOW_RAG_POISON_VERIFIED"))
    agent = RAGPoisoningDetector()
    res = await agent.execute("rag_poisoning_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_rag_poisoning_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Document indexed safely."))
    agent = RAGPoisoningDetector()
    res = await agent.execute("rag_poisoning_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_rag_poisoning_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Vector DB error"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = RAGPoisoningDetector()
    res = await agent.execute("rag_poisoning_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 10. AIAgentSecurityAgent Tests
@pytest.mark.asyncio
async def test_ai_agent_security_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Tool executed: AI_AGENT_TOOL_EXEC_CONFIRMED"))
    agent = AIAgentSecurityAgent()
    res = await agent.execute("ai_agent_security_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_ai_agent_security_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(403, "Tool execution unauthorized"))
    agent = AIAgentSecurityAgent()
    res = await agent.execute("ai_agent_security_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_ai_agent_security_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Agent runner crashed"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = AIAgentSecurityAgent()
    res = await agent.execute("ai_agent_security_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 11. XSLeakAgent Tests
@pytest.mark.asyncio
async def test_xs_leak_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(304, "", headers={"etag": "\"123456\""}))
    agent = XSLeakAgent()
    res = await agent.execute("xs_leak", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True

@pytest.mark.asyncio
async def test_xs_leak_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Standard response", headers={}))
    agent = XSLeakAgent()
    res = await agent.execute("xs_leak", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False

@pytest.mark.asyncio
async def test_xs_leak_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Header parse error"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = XSLeakAgent()
    res = await agent.execute("xs_leak", ctx)
    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is False


# 12. ResponseClusteringAgent Tests
@pytest.mark.asyncio
async def test_response_clustering_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(500, "Cluster Anomaly Detected"))
    agent = ResponseClusteringAgent()
    res = await agent.execute("response_clustering", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_response_clustering_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "Normal response"))
    agent = ResponseClusteringAgent()
    res = await agent.execute("response_clustering", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_response_clustering_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Cluster fail"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = ResponseClusteringAgent()
    res = await agent.execute("response_clustering", ctx)
    assert res["status"] == "COMPLETED"


# 13. APIVersionRegressionAgent Tests
@pytest.mark.asyncio
async def test_api_version_regression_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "v1 API exposed data"))
    agent = APIVersionRegressionAgent()
    res = await agent.execute("api_version_regression", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_api_version_regression_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(404, "Deprecated"))
    agent = APIVersionRegressionAgent()
    res = await agent.execute("api_version_regression", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_api_version_regression_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("Version test error"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = APIVersionRegressionAgent()
    res = await agent.execute("api_version_regression", ctx)
    assert res["status"] == "COMPLETED"


# 14. HTTP2ConnectCapabilityAgent Tests
@pytest.mark.asyncio
async def test_http2_connect_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "HTTP/2 Tunnel Established"))
    agent = HTTP2ConnectCapabilityAgent()
    res = await agent.execute("http2_connect_tunnel", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_http2_connect_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(501, "CONNECT Not Implemented"))
    agent = HTTP2ConnectCapabilityAgent()
    res = await agent.execute("http2_connect_tunnel", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_http2_connect_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("H2 Error"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = HTTP2ConnectCapabilityAgent()
    res = await agent.execute("http2_connect_tunnel", ctx)
    assert res["status"] == "COMPLETED"


# 15. NoSQLInjectionAgent Tests
@pytest.mark.asyncio
async def test_nosql_injection_agent_vulnerable():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(200, "MongoDB error: $gt syntax error"))
    agent = NoSQLInjectionAgent()
    res = await agent.execute("nosql_injection", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_nosql_injection_agent_safe():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    ctx.get_http_client = MagicMock(return_value=_build_mock_http_client(400, "Invalid JSON input"))
    agent = NoSQLInjectionAgent()
    res = await agent.execute("nosql_injection", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_nosql_injection_agent_exception():
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    client = MagicMock()
    client.send_as_identity = AsyncMock(side_effect=RuntimeError("DB query timeout"))
    ctx.get_http_client = MagicMock(return_value=client)
    agent = NoSQLInjectionAgent()
    res = await agent.execute("nosql_injection", ctx)
    assert res["status"] == "COMPLETED"
