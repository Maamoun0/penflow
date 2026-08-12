"""
Golden Negative Regression Test Suite for PenFlow Grounding Engine.

Tests the CriticVerificationEngine and HackerOneReportExporter against known
golden negative cases (false positives) to guarantee 0% false-positive admission.
"""
import pytest
from penflow.knowledge.evidence_cas import EvidenceBundle
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.reporting.hackerone_exporter import HackerOneReportExporter
from penflow.reporting.impact_scorer import ImpactScorer


@pytest.fixture
def critic_engine():
    return CriticVerificationEngine()


@pytest.fixture
def h1_exporter():
    return HackerOneReportExporter()


def test_golden_negative_1_cspt_cloudfront_edge_redirect(critic_engine):
    """Golden Negative 1: CSPT on CloudFront 301 redirect must be falsified."""
    bundle = EvidenceBundle(
        hash_id="test_cspt_cf",
        vulnerability_type="cspt",
        target="prod-api.example.com",
        raw_traces={
            "target_url": "https://prod-api.example.com/redirect?url=/v1",
            "is_vulnerable": True,
            "confidence_score": 0.90,
            "reasoning": "Query string parameter reflected in 301 Location header.",
            "evidence_exchanges": [
                {
                    "request": {"method": "GET", "url": "https://prod-api.example.com/redirect?url=/v1"},
                    "response": {
                        "status_code": 301,
                        "headers": {
                            "Location": "https://prod-api.example.com/v1",
                            "Server": "CloudFront"
                        },
                        "body_text": ""
                    }
                }
            ]
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert not result["is_verified"]
    assert "cloudfront" in result["verification_reason"].lower() or "edge redirect" in result["verification_reason"].lower()


def test_golden_negative_2_missing_headers_capped_severity(critic_engine, h1_exporter):
    """Golden Negative 2: Missing security headers must be capped at Informative."""
    bundle = EvidenceBundle(
        hash_id="test_missing_hdrs",
        vulnerability_type="missing_headers",
        target="app.example.com",
        raw_traces={
            "target_url": "https://app.example.com/",
            "is_vulnerable": True,
            "confidence_score": 0.95,
            "reasoning": "Missing Strict-Transport-Security and X-Frame-Options headers.",
            "evidence_exchanges": [
                {
                    "request": {"method": "GET", "url": "https://app.example.com/"},
                    "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}}
                }
            ]
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert result["is_verified"]
    assert result["confidence"] <= 0.30  # Low confidence cap
    
    report_md = h1_exporter.export_report(result)
    assert "[INFORMATIVE]" in report_md
    assert "CWE-693" in report_md


def test_golden_negative_3_grounding_gate_empty_evidence(critic_engine):
    """Golden Negative 3: Path Traversal with empty evidence exchanges must fail Grounding Gate (Rule 0)."""
    bundle = EvidenceBundle(
        hash_id="test_empty_evidence_pt",
        vulnerability_type="path_traversal",
        target="files.example.com",
        raw_traces={
            "target_url": "https://files.example.com/download?file=../../etc/passwd",
            "is_vulnerable": True,
            "confidence_score": 0.85,
            "reasoning": "Path traversal candidate identified by agent heuristic.",
            "evidence_exchanges": []  # Empty! No HTTP exchange captured
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert not result["is_verified"]
    assert "Grounding Gate failed" in result["verification_reason"]


def test_golden_negative_4_cvss_vector_distinctiveness():
    """Golden Negative 4: CVSS vectors must be distinct and specific to vulnerability type."""
    scorer = ImpactScorer()
    
    cspt_impact = scorer.evaluate_impact({"vulnerability_type": "cspt"})
    missing_hdrs_impact = scorer.evaluate_impact({"vulnerability_type": "missing_headers"})
    idor_impact = scorer.evaluate_impact({"vulnerability_type": "idor"})
    
    # Assert vectors are not identical
    assert cspt_impact["cvss_vector"] != missing_hdrs_impact["cvss_vector"]
    assert idor_impact["cvss_vector"] != cspt_impact["cvss_vector"]
    assert cspt_impact["cwe"] == "CWE-22"
    assert missing_hdrs_impact["cwe"] == "CWE-693"
    assert idor_impact["cwe"] == "CWE-639"
