import pytest
import pytest_asyncio
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.intelligence.exploit_chainer import ExploitChainer, VulnerabilityChain
from penflow.agents.recon.open_redirect_agent import OpenRedirectCapabilityAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_quality_gate_pipeline_integration():
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])
    findings = [
        {"vulnerability_type": "ssrf_metadata_exfiltration", "confidence": 0.95, "target_url": "https://example.com/api/fetch", "is_vulnerable": True},
        {"vulnerability_type": "open_redirect", "confidence": 0.60, "target_url": "https://example.com/redirect", "is_vulnerable": True}
    ]
    admitted = await gate.filter_findings(findings)
    assert len(admitted) == 1
    assert admitted[0]["vulnerability_type"] == "ssrf_metadata_exfiltration"

@pytest.mark.asyncio
async def test_exploit_chainer_ssrf_iam_theft():
    chainer = ExploitChainer()
    findings = [
        {"vulnerability_type": "ssrf_metadata_exfiltration", "confidence": 0.95, "target_url": "https://example.com/api/fetch", "description": "Cloud metadata 169.254.169.254 IAM credentials accessible", "is_vulnerable": True}
    ]
    chains = chainer.construct_chains(findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "CHAIN_SSRF_IAM_THEFT"
    assert chains[0].composite_severity == "CRITICAL"

@pytest.mark.asyncio
async def test_open_redirect_poc_generation():
    agent = OpenRedirectCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("open_redirect", ctx)
    assert res["status"] == "COMPLETED"
