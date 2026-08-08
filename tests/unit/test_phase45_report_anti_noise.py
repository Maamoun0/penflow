import pytest
from penflow.reporting.evidence_quality import (
    EvidenceQualityEngine,
    DuplicateDetectionEngine,
    BusinessImpactScorer
)

def test_duplicate_detection_engine():
    engine = DuplicateDetectionEngine()
    f1 = {"vulnerability_type": "idor", "target_url": "https://example.com/api/user/123", "parameter": "id"}
    f2 = {"vulnerability_type": "idor", "target_url": "https://example.com/api/user/123", "parameter": "id"}
    f3 = {"vulnerability_type": "idor", "target_url": "https://example.com/api/user/456", "parameter": "id"}

    assert engine.is_duplicate(f1) is False
    assert engine.is_duplicate(f2) is True  # Duplicate suppressed
    assert engine.is_duplicate(f3) is False

def test_cve_pattern_matching():
    engine = DuplicateDetectionEngine()
    matched = engine.match_known_cve("Apollo Router encountered CVE-2025-32032 query complexity")
    assert matched is not None
    assert "CVE-2025-32032" in matched

def test_business_impact_scorer():
    scorer = BusinessImpactScorer()
    res = scorer.calculate_business_risk("idor_cross_tenant_leak", "HIGH", is_eu_target=True)
    assert res["data_exposure_level"] == "High"
    assert res["gdpr_compliance_risk"] is True
    assert res["gdpr_severity_multiplier"] == 1.3
    assert "GDPR Art. 32" in res["regulatory_violation_risk"]

def test_evidence_quality_minimized_curl():
    engine = EvidenceQualityEngine()
    curl = engine.generate_minimized_curl(
        method="POST",
        url="https://victim.com/api/v1/update",
        headers={"Authorization": "Bearer abc", "User-Agent": "Noise", "Content-Type": "application/json"},
        data='{"admin": true}'
    )
    assert "User-Agent" not in curl  # Stripped noisy header
    assert "Authorization: Bearer abc" in curl
    assert "--data-raw" in curl

def test_triage_pack_anti_noise_suppression():
    engine = EvidenceQualityEngine()
    f = {"vulnerability_type": "ssrf", "target_url": "https://example.com/fetch", "severity": "CRITICAL"}
    
    pack1 = engine.format_triage_pack(f, is_eu_target=False)
    assert pack1 is not None
    assert pack1["severity"] == "CRITICAL"
    
    pack2 = engine.format_triage_pack(f, is_eu_target=False)
    assert pack2 is None  # Suppressed due to duplicate
