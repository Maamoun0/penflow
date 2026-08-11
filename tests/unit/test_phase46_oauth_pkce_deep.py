import pytest
import pytest_asyncio
from penflow.agents.auth.oauth_jwt_agent import OAuthJWTCapabilityAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

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
    res = await agent.execute("oauth_pkce_deep_audit", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vulnerability_type"] == "oauth_pkce_downgrade" for f in findings)
    assert any(f["vulnerability_type"] == "oauth_redirect_uri_traversal" for f in findings)

@pytest.mark.asyncio
async def test_jwt_alg_confusion_and_jwks_spoofing():
    agent = OAuthJWTCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("jwt_alg_confusion_and_jwks", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vulnerability_type"] == "jwt_algorithm_confusion" for f in findings)
    assert any(f["vulnerability_type"] == "jwt_jwks_uri_spoofing" for f in findings)
