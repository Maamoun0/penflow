import pytest
from penflow.intelligence.self_improving_payloads import SelfImprovingPayloadEngine
from penflow.intelligence.cross_target_intel import CrossTargetIntelligence
from penflow.intelligence.curiosity_explorer import CuriosityDrivenExplorer
from penflow.intelligence.abductive_reasoning import AbductiveReasoningEngine
from penflow.intelligence.competitive_intel import CompetitiveIntelligenceModule

def test_self_improving_payload_engine():
    engine = SelfImprovingPayloadEngine()
    base = "<script>alert(1)</script>"
    mutations = engine.get_optimal_mutations(base, "example.com")
    assert len(mutations) >= 5
    
    engine.record_feedback(base, "example.com", "Cloudflare", was_blocked=True, was_successful=False)
    assert "example.com::Cloudflare" in engine.effectiveness_history
    assert engine.effectiveness_history["example.com::Cloudflare"]["blocked_count"] == 1

def test_cross_target_intelligence():
    intel = CrossTargetIntelligence()
    techs = ["React", "Next.js", "Apollo", "GraphQL"]
    recs = intel.correlate_stack_risks(techs)
    assert len(recs) >= 2
    
    intel.register_target_findings("targetA.com", ["Django"], ["ssti_rce"])
    assert "targetA.com" in intel.target_database

def test_curiosity_driven_explorer():
    explorer = CuriosityDrivenExplorer(baseline_latency_ms=100.0, baseline_size_bytes=500)
    
    # Latency spike test
    anomaly = explorer.evaluate_response_anomaly(
        endpoint="https://example.com/search",
        latency_ms=450.0,
        response_size=400,
        headers={"Content-Type": "text/html"},
        status_code=200
    )
    assert anomaly is not None
    assert anomaly["anomaly_count"] >= 1
    assert any(a["type"] == "latency_spike" for a in anomaly["anomalies"])

    # Normal response test (no anomaly)
    normal = explorer.evaluate_response_anomaly(
        endpoint="https://example.com/home",
        latency_ms=80.0,
        response_size=450,
        headers={"Content-Type": "text/html"},
        status_code=200
    )
    assert normal is None

def test_abductive_reasoning_engine():
    reasoner = AbductiveReasoningEngine()
    endpoints = ["/api/v1/export/users", "/api/checkout/pay", "/api/chat/assistant"]
    hypotheses = reasoner.infer_hypotheses(endpoints)
    assert len(hypotheses) >= 3

def test_competitive_intelligence_module():
    comp = CompetitiveIntelligenceModule()
    candidates = ["xss", "ssrf", "prompt_injection_audit", "info_disclosure"]
    ranked = comp.prioritize_capabilities(candidates)
    assert len(ranked) == 4
    # Highest priority should be prompt_injection_audit or ssrf
    assert ranked[0]["priority_weight"] >= ranked[-1]["priority_weight"]
