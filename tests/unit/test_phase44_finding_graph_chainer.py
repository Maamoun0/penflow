import pytest
from penflow.intelligence.finding_graph import FindingContextGraph
from penflow.intelligence.exploit_chainer import ExploitChainer, ImpactAmplifier, VulnerabilityChain

def test_finding_context_graph():
    graph = FindingContextGraph()
    n1 = graph.add_node("node_cors", "finding", "CORS Misconfig")
    n2 = graph.add_node("node_redirect", "finding", "Open Redirect")
    n3 = graph.add_node("node_ato", "impact", "Account Takeover")

    graph.add_edge("node_cors", "node_redirect", "COMBINES_WITH")
    graph.add_edge("node_redirect", "node_ato", "ESCALATES_TO")

    paths = graph.find_exploit_paths("node_cors")
    assert len(paths) >= 2
    assert paths[1] == ["node_cors", "node_redirect", "node_ato"]

    exported = graph.export_graph()
    assert exported["total_nodes"] == 3
    assert exported["total_edges"] == 2

def test_impact_amplifier():
    amp = ImpactAmplifier()
    assert amp.amplify_severity(["CRITICAL", "LOW"]) == "CRITICAL"
    assert amp.amplify_severity(["HIGH", "HIGH"]) == "CRITICAL"
    assert amp.amplify_severity(["MEDIUM", "MEDIUM"]) == "HIGH"
    assert amp.amplify_severity(["LOW"]) == "LOW"

def test_exploit_chainer_cors_redirect_ato():
    chainer = ExploitChainer()
    findings = [
        {"vulnerability_type": "cors_misconfig_check", "confidence_score": 0.9},
        {"vulnerability_type": "open_redirect", "target_url": "https://example.com/oauth/callback"}
    ]
    chains = chainer.construct_chains(findings)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.chain_id == "CHAIN_CORS_REDIRECT_ATO"
    assert chain.composite_severity == "CRITICAL"
    assert "Account Takeover" in chain.title

def test_exploit_chainer_xxe_ssrf_pivot():
    chainer = ExploitChainer()
    findings = [
        {"vulnerability_type": "xxe_injection", "target_url": "https://example.com/xml"},
        {"vulnerability_type": "ssrf_redirect_chain", "description": "cloud metadata 169.254.169.254"}
    ]
    chains = chainer.construct_chains(findings)
    assert len(chains) >= 1
    chain_ids = [c.chain_id for c in chains]
    assert "CHAIN_XXE_SSRF_INTERNAL_PIVOT" in chain_ids or "CHAIN_SSRF_IAM_THEFT" in chain_ids
