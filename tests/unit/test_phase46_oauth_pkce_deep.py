import pytest
import pytest_asyncio
import httpx
from penflow.agents.auth.oauth_jwt_agent import OAuthJWTCapabilityAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.traffic.http_client import StatefulHttpClient

@pytest.mark.asyncio
async def test_oauth_jwt_agent_capabilities():
    agent = OAuthJWTCapabilityAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 4
    cap_ids = [c.id for c in caps]
    assert "oauth_pkce_deep_audit" in cap_ids
    assert "jwt_alg_confusion_and_jwks" in cap_ids

@pytest.mark.asyncio
async def test_pkce_downgrade_and_redirect_traversal():
    agent = OAuthJWTCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())

    def mock_handler(req: httpx.Request) -> httpx.Response:
        url_str = str(req.url)
        if "code_challenge_method=plain" in url_str:
            return httpx.Response(200, text="OAuth Code Issued")
        if "/../../attacker" in url_str:
            return httpx.Response(302, headers={"location": "https://example.com/callback/../../attacker?code=12345"})
        return httpx.Response(400, text="Bad Request")

    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["example.com"],
        custom_transport=httpx.MockTransport(mock_handler),
        rate_limit_rps=100.0
    )

    res = await agent.execute("oauth_pkce_deep_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vulnerability_type"] == "oauth_pkce_downgrade" for f in findings)
    assert any(f["vulnerability_type"] == "oauth_redirect_uri_traversal" for f in findings)

@pytest.mark.asyncio
async def test_jwt_alg_confusion_and_jwks_spoofing():
    agent = OAuthJWTCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())

    def mock_handler(req: httpx.Request) -> httpx.Response:
        auth_hdr = req.headers.get("Authorization", "")
        if "Bearer " in auth_hdr and len(auth_hdr) > 15:
            return httpx.Response(200, json={"status": "authenticated", "user": "admin"})
        return httpx.Response(401, json={"error": "unauthorized"})

    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["example.com"],
        custom_transport=httpx.MockTransport(mock_handler),
        rate_limit_rps=100.0
    )

    res = await agent.execute("jwt_alg_confusion_and_jwks", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vulnerability_type"] == "jwt_algorithm_confusion" for f in findings)
    assert any(f["vulnerability_type"] == "jwt_jwks_uri_spoofing" for f in findings)
