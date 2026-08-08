import pytest
import pytest_asyncio
from penflow.reporting.poc_generator import PoCGenerator
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.agents.business_logic_agent import BusinessLogicCapabilityAgent
from penflow.agents.cache_poisoning_agent import WebCachePoisoningCapabilityAgent
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

def test_poc_generator_curl_and_steps():
    gen = PoCGenerator()
    curl_cmd = "curl -X POST https://example.com/api/v1/checkout -H 'Content-Type: application/json' -d '{\"price\": 0.01}'"
    steps = gen.generate_reproduction_steps("Price Tampering", "https://example.com/api/v1/checkout", curl_cmd)
    assert len(steps) == 4
    assert "Price Tampering" in steps[3]

@pytest.mark.asyncio
async def test_pre_report_quality_gate():
    gate = PreReportQualityGate(min_confidence=0.85, scope_domains=["example.com"])
    
    # Valid high confidence finding
    good_finding = {
        "vulnerability_type": "ssrf_metadata_exfiltration",
        "confidence": 0.95,
        "target_url": "https://example.com/api/fetch",
        "is_vulnerable": True
    }
    res_good = await gate.evaluate_finding(good_finding)
    assert res_good["passed"] is True
    assert res_good["quality_score"] == 100.0

    # Low confidence finding
    bad_finding = {
        "vulnerability_type": "open_redirect",
        "confidence": 0.60,
        "target_url": "https://example.com/redirect",
        "is_vulnerable": True
    }
    res_bad = await gate.evaluate_finding(bad_finding)
    assert res_bad["passed"] is False
    assert any("Gate 1" in g for g in res_bad["failed_gates"])

@pytest.mark.asyncio
async def test_upgraded_business_logic_agent():
    agent = BusinessLogicCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("business_logic_bypass", ctx)
    assert res["status"] == "COMPLETED"

@pytest.mark.asyncio
async def test_upgraded_cache_poisoning_agent():
    agent = WebCachePoisoningCapabilityAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("cache_poisoning", ctx)
    assert res["status"] == "COMPLETED"
