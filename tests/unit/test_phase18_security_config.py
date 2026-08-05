import pytest
from penflow.recon.security_headers_audit import SecurityHeadersAuditor
from penflow.validation.csp_analyzer import CSPPolicyAnalyzer
from penflow.agents.security_config_agent import SecurityConfigCapabilityAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_security_headers_auditor():
    auditor = SecurityHeadersAuditor(timeout=2.0)
    res = await auditor.audit_url("https://example.com")
    assert "url" in res
    assert "headers" in res
    assert "findings" in res

def test_csp_policy_analyzer():
    analyzer = CSPPolicyAnalyzer()
    res = analyzer.analyze_csp("script-src 'self' 'unsafe-inline' *;")
    assert len(res["findings"]) >= 2
    assert any(f["issue"] == "csp_unsafe_inline" for f in res["findings"])
    assert any(f["issue"] == "csp_wildcard_script" for f in res["findings"])

@pytest.mark.asyncio
async def test_security_config_capability_agent():
    agent = SecurityConfigCapabilityAgent()
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=ks)
    res = await agent.execute("security_config_audit", ctx)
    assert res["status"] == "COMPLETED"
    assert "evidence" in res
