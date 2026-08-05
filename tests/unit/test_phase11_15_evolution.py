"""
Phase 11-15 Evolution Tests:
- Phase 11: Critical bug fixes (proxy, Optional import, critic typo)
- Phase 12: EndpointClassifier dynamic recon pipeline
- Phase 13: PayloadTemplateEngine real-world payloads
- Phase 14: SemanticResponseAnalyzer intelligent analysis
- Phase 15: CVSSCalculator v3.1 scoring + HackerOne report format
"""
import pytest
from typing import Dict, Any

# ─────────────────────────────────────────────
# Phase 12: EndpointClassifier
# ─────────────────────────────────────────────
from penflow.recon.endpoint_classifier import EndpointClassifier, ClassifiedEndpoint

class TestEndpointClassifier:

    def test_classifies_graphql_endpoint(self):
        clf = EndpointClassifier()
        crawl_data = {
            "endpoints": [{"url": "https://api.example.com/graphql", "status": 200, "content_type": "application/json"}],
            "forms": [], "js_files": []
        }
        result = clf.classify_from_crawl(crawl_data)
        assert any(ep.endpoint_type == "graphql" for ep in result)

    def test_classifies_rest_api_with_idor_param(self):
        clf = EndpointClassifier()
        crawl_data = {
            "endpoints": [{"url": "https://api.example.com/api/v1/users?user_id=123", "status": 200, "content_type": "application/json"}],
            "forms": [], "js_files": []
        }
        result = clf.classify_from_crawl(crawl_data)
        assert any("idor_candidate" in ep.tags for ep in result)

    def test_classifies_auth_endpoint(self):
        clf = EndpointClassifier()
        crawl_data = {
            "endpoints": [{"url": "https://example.com/oauth/token", "status": 200, "content_type": "application/json"}],
            "forms": [], "js_files": []
        }
        result = clf.classify_from_crawl(crawl_data)
        assert any(ep.endpoint_type == "auth" for ep in result)

    def test_skips_static_assets(self):
        clf = EndpointClassifier()
        crawl_data = {
            "endpoints": [
                {"url": "https://example.com/style.css", "status": 200, "content_type": "text/css"},
                {"url": "https://example.com/logo.png", "status": 200, "content_type": "image/png"},
            ],
            "forms": [], "js_files": []
        }
        result = clf.classify_from_crawl(crawl_data)
        assert len(result) == 0  # Static assets skipped

    def test_classifies_forms_as_mass_assignment_candidate(self):
        clf = EndpointClassifier()
        crawl_data = {
            "endpoints": [],
            "forms": [{"action": "https://example.com/profile", "method": "POST", "parameters": ["name", "email", "phone", "address"]}],
            "js_files": []
        }
        result = clf.classify_from_crawl(crawl_data)
        assert any("mass_assignment_candidate" in ep.tags for ep in result)

    def test_agent_mapping_graphql_to_graphql_caps(self):
        clf = EndpointClassifier()
        classified = [ClassifiedEndpoint(
            url="https://api.example.com/graphql",
            endpoint_type="graphql", tags=["graphql"], confidence=0.9
        )]
        mapping = clf.get_agent_mapping(classified)
        assert "graphql_introspection" in mapping
        assert "graphql_depth_analysis" in mapping

    def test_agent_mapping_ssrf_params(self):
        clf = EndpointClassifier()
        classified = [ClassifiedEndpoint(
            url="https://example.com/fetch?url=http://example.com",
            endpoint_type="parameterized", tags=[], confidence=0.6
        )]
        mapping = clf.get_agent_mapping(classified)
        assert "ssrf_analysis" in mapping

    def test_tech_hints_extract_cors(self):
        clf = EndpointClassifier()
        tech_data = {"technologies": [], "detected_headers": {"Access-Control-Allow-Origin": "*"}}
        hints = clf.classify_from_tech(tech_data)
        assert "cors_relevant" in hints

    def test_classified_endpoint_to_dict(self):
        ep = ClassifiedEndpoint(
            url="https://api.example.com/v1/users?id=1",
            endpoint_type="rest_api",
            tags=["idor_candidate"],
            confidence=0.85
        )
        d = ep.to_dict()
        assert d["url"] == "https://api.example.com/v1/users?id=1"
        assert d["type"] == "rest_api"
        assert "idor_candidate" in d["tags"]


# ─────────────────────────────────────────────
# Phase 13: PayloadTemplateEngine
# ─────────────────────────────────────────────
from penflow.testing.payload_engine import PayloadTemplateEngine

class TestPayloadEngine:

    def test_idor_sequential_payloads(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_idor_payloads("https://api.example.com/users?id=100", "id", "100")
        names = [p.name for p in payloads]
        assert any("Sequential" in n for n in names)
        assert any("Negative" in n for n in names)
        assert any("Zero" in n for n in names)

    def test_idor_path_id_swap(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_idor_payloads("https://api.example.com/users/100/profile", "id", "100")
        path_payloads = [p for p in payloads if "PathID" in p.name]
        assert len(path_payloads) >= 1

    def test_jwt_alg_none_payload(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_jwt_payloads()
        alg_none = next((p for p in payloads if p.name == "JWT_AlgNone"), None)
        assert alg_none is not None
        assert "Authorization" in alg_none.headers
        assert "Bearer" in alg_none.headers["Authorization"]
        # The header should contain alg=none
        token = alg_none.headers["Authorization"].replace("Bearer ", "")
        assert token.split(".")[-1] == ""  # Empty signature

    def test_jwt_kid_injection(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_jwt_payloads()
        kid = next((p for p in payloads if "KidSQLi" in p.name), None)
        assert kid is not None

    def test_ssrf_aws_metadata_included(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_ssrf_payloads("https://example.com/fetch?url=test", "url")
        ssrf_names = [p.name for p in payloads]
        assert "SSRF_AWS_Metadata_v1" in ssrf_names
        assert "SSRF_Localhost" in ssrf_names
        assert "SSRF_File_Proto" in ssrf_names
        assert "SSRF_Gopher_Proto" in ssrf_names

    def test_ssrf_critical_payloads(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_ssrf_payloads("https://example.com/fetch?url=test", "url")
        critical = [p for p in payloads if p.severity == "critical"]
        assert len(critical) >= 4  # AWS, GCP, Azure, File, Gopher

    def test_mass_assignment_admin_injection(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_mass_assignment_payloads("https://api.example.com/profile")
        admin_payloads = [p for p in payloads if "role" in str(p.json_data) or "admin" in str(p.json_data)]
        assert len(admin_payloads) >= 1

    def test_mass_assignment_put_and_patch(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_mass_assignment_payloads("https://api.example.com/profile")
        methods = {p.method for p in payloads}
        assert "PUT" in methods
        assert "PATCH" in methods

    def test_graphql_payloads(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_graphql_payloads("https://api.example.com/graphql")
        names = [p.name for p in payloads]
        assert "GraphQL_FullIntrospection" in names
        assert "GraphQL_DepthDoS" in names
        assert "GraphQL_BatchIDOR" in names

    def test_graphql_introspection_expected_indicator(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_graphql_payloads("https://api.example.com/graphql")
        intro = next((p for p in payloads if p.name == "GraphQL_FullIntrospection"), None)
        assert intro.expected_indicator == "__schema"

    def test_cors_payloads(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_cors_payloads("https://api.example.com/v1/data")
        assert any(p.headers.get("Origin") == "null" for p in payloads)
        assert any("Subdomain" in p.name for p in payloads)

    def test_race_condition_payloads(self):
        engine = PayloadTemplateEngine()
        payloads = engine.generate_race_condition_payloads("https://api.example.com/checkout", concurrency=15)
        assert any("15x" in p.name for p in payloads)
        assert any("LastByteSync" in p.name for p in payloads)

    def test_generate_all_for_graphql_endpoint(self):
        engine = PayloadTemplateEngine()
        endpoint = {"url": "https://api.example.com/graphql", "type": "graphql", "tags": ["graphql"], "parameters": []}
        payloads = engine.generate_all_for_endpoint(endpoint)
        assert len(payloads) > 0
        types = {p.vuln_type for p in payloads}
        assert "graphql" in types


# ─────────────────────────────────────────────
# Phase 14: SemanticResponseAnalyzer
# ─────────────────────────────────────────────
from penflow.testing.response_analyzer import SemanticResponseAnalyzer

class TestSemanticResponseAnalyzer:

    def test_detects_jwt_in_body(self):
        analyzer = SemanticResponseAnalyzer()
        body = '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.fake_signature"}'
        result = analyzer.analyze_response(200, {}, body)
        assert result["has_sensitive_data"] is True
        assert any(f["type"] == "jwt_token" for f in result["findings"])

    def test_detects_aws_access_key(self):
        analyzer = SemanticResponseAnalyzer()
        body = '{"key": "AKIAIOSFODNN7EXAMPLE"}'
        result = analyzer.analyze_response(200, {}, body)
        assert result["has_sensitive_data"] is True
        assert any(f["type"] == "aws_access_key" for f in result["findings"])

    def test_detects_sql_error(self):
        analyzer = SemanticResponseAnalyzer()
        body = "You have an error in your SQL syntax; check the manual for MySQL"
        result = analyzer.analyze_response(500, {}, body)
        assert result["has_error_disclosure"] is True
        assert any(f["type"] == "sql_error" for f in result["findings"])

    def test_detects_stack_trace(self):
        analyzer = SemanticResponseAnalyzer()
        body = 'Traceback (most recent call last):\n  File "app.py", line 42, in handler'
        result = analyzer.analyze_response(500, {}, body)
        assert result["has_error_disclosure"] is True

    def test_missing_security_headers(self):
        analyzer = SemanticResponseAnalyzer()
        result = analyzer.analyze_response(200, {}, "hello world")
        missing = [f for f in result["findings"] if f["location"] == "headers"]
        assert len(missing) >= 3  # HSTS, X-Content-Type-Options, X-Frame-Options

    def test_risk_score_critical_data(self):
        analyzer = SemanticResponseAnalyzer()
        body = '{"password": "supersecret123", "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}'
        result = analyzer.analyze_response(200, {}, body)
        assert result["risk_score"] > 0.4

    def test_json_structural_analysis(self):
        analyzer = SemanticResponseAnalyzer()
        body = '{"user": {"email": "test@example.com", "role": "admin"}, "token": "abc"}'
        result = analyzer.analyze_response(200, {}, body)
        assert result["json_analysis"]["is_json"] is True
        assert result["json_analysis"]["total_keys"] > 0

    def test_semantic_compare_identical_responses(self):
        analyzer = SemanticResponseAnalyzer()
        resp_a = {"body_text": '{"user_id": 1, "email": "alice@test.com", "balance": 1000}', "status_code": 200}
        resp_b = {"body_text": '{"user_id": 1, "email": "alice@test.com", "balance": 1000}', "status_code": 200}
        result = analyzer.compare_responses_semantic(resp_a, resp_b)
        assert result["is_potential_bypass"] is True
        assert result["confidence"] >= 0.85

    def test_semantic_compare_different_data(self):
        analyzer = SemanticResponseAnalyzer()
        resp_a = {"body_text": '{"user_id": 1, "email": "alice@test.com"}', "status_code": 200}
        resp_b = {"body_text": '{"error": "forbidden"}', "status_code": 403}
        result = analyzer.compare_responses_semantic(resp_a, resp_b)
        assert result["is_potential_bypass"] is False

    def test_detects_internal_ip(self):
        analyzer = SemanticResponseAnalyzer()
        body = '{"server": "192.168.1.10", "message": "internal server"}'
        result = analyzer.analyze_response(200, {}, body)
        assert any(f["type"] == "internal_ip" for f in result["findings"])


# ─────────────────────────────────────────────
# Phase 15: CVSSCalculator
# ─────────────────────────────────────────────
from penflow.reporting.cvss_calculator import CVSSCalculator, CVSSMetrics

class TestCVSSCalculator:

    def test_critical_score_jwt(self):
        calc = CVSSCalculator()
        metrics = calc.get_metrics_for("jwt_validation")
        result = calc.calculate_score(metrics)
        assert result["base_score"] >= 9.0
        assert result["severity"] == "Critical"

    def test_high_score_idor(self):
        calc = CVSSCalculator()
        metrics = calc.get_metrics_for("id_access_analysis")
        result = calc.calculate_score(metrics)
        assert result["base_score"] >= 6.0
        assert result["severity"] in ("High", "Critical")

    def test_medium_score_cors(self):
        calc = CVSSCalculator()
        metrics = calc.get_metrics_for("cors_misconfiguration")
        result = calc.calculate_score(metrics)
        assert result["base_score"] >= 4.0

    def test_vector_string_format(self):
        calc = CVSSCalculator()
        metrics = CVSSMetrics()
        result = calc.calculate_score(metrics)
        assert result["vector_string"].startswith("CVSS:3.1/AV:")

    def test_zero_impact_gives_zero_score(self):
        calc = CVSSCalculator()
        metrics = CVSSMetrics(
            confidentiality="N", integrity="N", availability="N"
        )
        result = calc.calculate_score(metrics)
        assert result["base_score"] == 0.0
        assert result["severity"] == "None"

    def test_ssrf_scope_changed(self):
        calc = CVSSCalculator()
        metrics = calc.get_metrics_for("ssrf_analysis")
        result = calc.calculate_score(metrics)
        assert "S:C" in result["vector_string"]
        assert result["base_score"] >= 8.0

    def test_all_profiles_are_valid(self):
        calc = CVSSCalculator()
        for vuln_type in calc.VULN_PROFILES:
            metrics = calc.get_metrics_for(vuln_type)
            result = calc.calculate_score(metrics)
            assert 0.0 <= result["base_score"] <= 10.0
            assert result["severity"] in ("None", "Low", "Medium", "High", "Critical")

    def test_bfla_scope_changed_high_impact(self):
        calc = CVSSCalculator()
        metrics = calc.get_metrics_for("bfla_analysis")
        result = calc.calculate_score(metrics)
        assert result["base_score"] >= 8.0
        assert result["severity"] in ("High", "Critical")

    def test_unknown_vuln_type_defaults(self):
        calc = CVSSCalculator()
        metrics = calc.get_metrics_for("totally_unknown_vuln")
        result = calc.calculate_score(metrics)
        # Should not raise, returns a valid score
        assert isinstance(result["base_score"], float)
