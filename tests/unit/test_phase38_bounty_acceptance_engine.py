"""
Unit tests for Bug Bounty Acceptance Engine & Impact Verification components.
"""

import pytest
from penflow.analysis.sensitive_data_exfiltrator import CORSSensitiveDataVerifier
from penflow.validation.production_scope_validator import ProductionScopeValidator
from penflow.validation.desync_waf_disambiguator import DesyncWafDisambiguator


def test_cors_sensitive_data_verifier_json_pii():
    verifier = CORSSensitiveDataVerifier()
    headers = {"Content-Type": "application/json"}
    body = '{"status": "success", "user_id": "usr_99812", "email": "victim@example.com", "bearer_token": "eyJhbGciOiJIUzI1NiJ9.test.sig"}'
    
    res = verifier.inspect_response(200, headers, body)
    assert res["has_exfiltration_impact"] is True
    assert res["data_sensitivity_score"] > 0.5
    assert "email_address" in res["detected_sensitive_categories"]


def test_cors_sensitive_data_verifier_public_html_penalty():
    verifier = CORSSensitiveDataVerifier()
    headers = {"Content-Type": "text/html"}
    body = '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>Error from cloudfront</body></html>'
    
    res = verifier.inspect_response(403, headers, body)
    assert res["has_exfiltration_impact"] is False
    assert res["is_public_html"] is True


def test_production_scope_validator_derivation():
    validator = ProductionScopeValidator()
    assert validator.derive_production_domain("uat-bugbounty.nonprod.syfe.com") == "www.syfe.com"
    assert validator.derive_production_domain("api-uat-31.nonprod.syfe.com") == "www.syfe.com"
    assert validator.derive_production_domain("www.syfe.com") is None


def test_desync_waf_disambiguator_rate_limit_429():
    disambiguator = DesyncWafDisambiguator()
    res = disambiguator.evaluate_desync_evidence(429, {}, "Too Many Requests", 500)
    assert res["is_waf_false_positive"] is True
    assert res["is_genuine_desync"] is False


def test_desync_waf_disambiguator_valid_connection_close():
    disambiguator = DesyncWafDisambiguator()
    res = disambiguator.evaluate_desync_evidence(400, {"Connection": "close"}, "Bad Request", 1200)
    assert res["is_waf_false_positive"] is False
    assert res["is_genuine_desync"] is True
