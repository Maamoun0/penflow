import pytest
from penflow.intelligence.writeup_miner import WriteupMiner, SecurityWriteup
from penflow.intelligence.experience_layer import ExperienceLayer
from penflow.knowledge.knowledge_store import KnowledgeStore

def test_writeup_miner_pattern_extraction():
    miner = WriteupMiner()
    sample_text = """
    In this writeup, I discovered a critical BOLA / IDOR vulnerability in an GraphQL endpoint.
    By visiting /api/v1/users/100?id=100 and swapping the Authorization Bearer token, I was able to access
    another account's profile data. The target technology was Node.js with Express.
    """
    writeup = miner.parse_writeup_text("Critical BOLA in GraphQL API", sample_text, source_url="https://hackerone.com/reports/123")

    assert writeup.id is not None
    assert "idor" in writeup.detected_vulnerabilities
    assert "graphql" in writeup.detected_vulnerabilities
    assert writeup.target_technology == "graphql, node, express"
    assert len(writeup.extracted_patterns) > 0

def test_experience_layer_stats_and_absorb():
    layer = ExperienceLayer()

    # 1. Record empirical scan results
    layer.record_scan_result("id_access_analysis", is_verified=True)
    layer.record_scan_result("id_access_analysis", is_verified=True)
    layer.record_scan_result("id_access_analysis", is_verified=False)

    stats = layer.get_all_stats()
    assert "id_access_analysis" in stats
    assert stats["id_access_analysis"]["total_attempts"] == 3
    assert stats["id_access_analysis"]["successful_verifications"] == 2
    assert stats["id_access_analysis"]["confidence_weight"] > 0.80

    # 2. Absorb mined writeup
    miner = WriteupMiner()
    wu = miner.parse_writeup_text("Mass Assignment Admin Bypass", "Detailed explanation of Mass Assignment vulnerability in user update.")
    layer.absorb_writeup(wu)

    stats_after = layer.get_all_stats()
    assert "mass_assignment" in stats_after
    assert layer.get_priority_multiplier("mass_assignment") > 1.0

def test_knowledge_store_experience_integration():
    ks = KnowledgeStore()
    assert hasattr(ks, "experience")
    assert isinstance(ks.experience, ExperienceLayer)

    ks.experience.record_scan_result("schema_introspection", is_verified=True)
    assert ks.experience.get_priority_multiplier("schema_introspection") >= 1.0
