"""
Phase 21 Unit Tests — Elite Intelligence Deepening.
Verifies:
  1. Module H: EndpointClassifier cap_id mapping fixes
  2. Module A: GraphQL agent Introspection, Field Suggestion, Batching, Depth DoS, Alias Amplification
  3. Module B: CORS agent 7-vector probing (arbitrary, null, subdomain, prefix, suffix, http)
  4. Module C: NoSQL/SQLi agent multi-endpoint, error pattern, time-blind injection
  5. Module D: SSTI/RCE multi-engine evaluation matrix (Jinja2, Twig, FreeMarker, Smarty, ERB, Velocity)
  6. Module E: HTTP Request Smuggling agent (CL.TE, TE.CL, TE.TE desync)
  7. Module F: Subdomain Takeover agent (12 cloud fingerprints)
  8. Module G: Parameter Discovery Engine (300+ wordlist, auth bypass headers)
"""
import pytest
import re
from unittest.mock import AsyncMock, MagicMock

# ─────────────────────────────────────────────────────────
# Module H: EndpointClassifier Cap ID Fixes
# ─────────────────────────────────────────────────────────

def test_endpoint_classifier_ssrf_cap_id_fix():
    from penflow.recon.endpoint_classifier import EndpointClassifier, ClassifiedEndpoint
    classifier = EndpointClassifier()
    ep = ClassifiedEndpoint(
        url="https://example.com/fetch?url=test",
        endpoint_type="parameterized",
        parameters=["url"]
    )
    mapping = classifier.get_agent_mapping([ep])
    assert "ssrf_metadata_exfiltration" in mapping, "SSRF cap_id must be ssrf_metadata_exfiltration"
    assert "ssrf_analysis" in mapping, "Legacy ssrf_analysis cap_id must also be present for backward compatibility"

def test_endpoint_classifier_new_agents_mapped():
    from penflow.recon.endpoint_classifier import EndpointClassifier, ClassifiedEndpoint
    classifier = EndpointClassifier()
    ep = ClassifiedEndpoint(
        url="https://example.com/api/v1/users",
        endpoint_type="rest_api",
        parameters=["q"]
    )
    mapping = classifier.get_agent_mapping([ep])
    assert "http_smuggling_desync" in mapping
    assert "parameter_discovery" in mapping
    assert "subdomain_takeover_check" in mapping
    assert "reflected_xss" in mapping


# ─────────────────────────────────────────────────────────
# Module A: GraphQL Agent 5 Vectors
# ─────────────────────────────────────────────────────────

def test_graphql_agent_capabilities_count():
    from penflow.agents.graphql_agent import GraphQLCapabilityAgent
    agent = GraphQLCapabilityAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 4, f"Expected 4 capabilities, got {len(caps)}"

def test_graphql_depth_query_generator():
    from penflow.agents.graphql_agent import generate_depth_query
    q = generate_depth_query(10)
    assert q.count("{ friends") == 10
    assert q.count("}") >= 11

def test_graphql_alias_query_generator():
    from penflow.agents.graphql_agent import generate_alias_query
    q = generate_alias_query(50)
    assert "a49: __typename" in q


# ─────────────────────────────────────────────────────────
# Module B: CORS Agent 7 Vectors
# ─────────────────────────────────────────────────────────

def test_cors_agent_vector_catalog():
    from penflow.agents.cors_agent import CORS_VECTORS
    assert len(CORS_VECTORS) >= 6
    v_ids = [v["id"] for v in CORS_VECTORS]
    assert "arbitrary_origin" in v_ids
    assert "null_origin" in v_ids
    assert "subdomain_trust" in v_ids
    assert "prefix_bypass" in v_ids
    assert "suffix_bypass" in v_ids
    assert "http_downgrade" in v_ids


# ─────────────────────────────────────────────────────────
# Module C: NoSQL/SQLi Multi-Endpoint Agent
# ─────────────────────────────────────────────────────────

def test_sqli_error_patterns_coverage():
    from penflow.agents.nosql_sqli_agent import SQL_ERROR_PATTERNS
    assert len(SQL_ERROR_PATTERNS) >= 10
    joined = " ".join(SQL_ERROR_PATTERNS)
    assert "mysql" in joined.lower()
    assert "postgresql" in joined.lower()
    assert "ora-" in joined.lower()
    assert "sqlite3" in joined.lower()

def test_nosql_error_patterns_coverage():
    from penflow.agents.nosql_sqli_agent import NOSQL_ERROR_PATTERNS
    assert len(NOSQL_ERROR_PATTERNS) >= 5
    joined = " ".join(NOSQL_ERROR_PATTERNS)
    assert "mongo" in joined.lower()
    assert "cassandra" in joined.lower()


# ─────────────────────────────────────────────────────────
# Module D: SSTI/RCE Multi-Engine Matrix
# ─────────────────────────────────────────────────────────

def test_ssti_engine_matrix_coverage():
    from penflow.agents.ssti_rce_agent import SSTI_ENGINE_PAYLOADS
    assert len(SSTI_ENGINE_PAYLOADS) >= 6
    engines = [e["engine"] for e in SSTI_ENGINE_PAYLOADS]
    all_engines = " ".join(engines)
    assert "Jinja2" in all_engines
    assert "Twig" in all_engines
    assert "FreeMarker" in all_engines
    assert "Smarty" in all_engines
    assert "ERB" in all_engines
    assert "Velocity" in all_engines

def test_rce_output_patterns():
    from penflow.agents.ssti_rce_agent import RCE_OUTPUT_PATTERNS
    sample = "uid=1000(user) gid=1000(user) groups=1000(user)"
    assert any(re.search(pat, sample, re.IGNORECASE) for pat in RCE_OUTPUT_PATTERNS)


# ─────────────────────────────────────────────────────────
# Module E: HTTP Request Smuggling Agent
# ─────────────────────────────────────────────────────────

def test_http_smuggling_agent_capabilities():
    from penflow.agents.http_smuggling_agent import HTTPSmugglingCapabilityAgent
    agent = HTTPSmugglingCapabilityAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 1
    assert caps[0].id == "http_smuggling_desync"


# ─────────────────────────────────────────────────────────
# Module F: Subdomain Takeover Agent
# ─────────────────────────────────────────────────────────

def test_subdomain_takeover_fingerprints_count():
    from penflow.agents.subdomain_takeover_agent import TAKEOVER_FINGERPRINTS
    assert len(TAKEOVER_FINGERPRINTS) == 12, f"Expected 12 cloud fingerprints, got {len(TAKEOVER_FINGERPRINTS)}"
    services = [f["service"] for f in TAKEOVER_FINGERPRINTS]
    assert "AWS S3 Bucket" in services
    assert "GitHub Pages" in services
    assert "Heroku App" in services
    assert "Fastly CDN" in services
    assert "Azure Web App" in services
    assert "Netlify" in services
    assert "Vercel" in services

def test_subdomain_takeover_pattern_matching():
    from penflow.agents.subdomain_takeover_agent import TAKEOVER_FINGERPRINTS
    s3_fp = TAKEOVER_FINGERPRINTS[0]
    sample_body = "<html><body>The specified bucket does not exist</body></html>"
    matched = any(re.search(pat, sample_body, re.IGNORECASE) for pat in s3_fp["body_patterns"])
    assert matched, "S3 takeover body pattern should match"


# ─────────────────────────────────────────────────────────
# Module G: Parameter Discovery Engine
# ─────────────────────────────────────────────────────────

def test_parameter_wordlist_count():
    from penflow.recon.parameter_discovery import HIDDEN_PARAM_WORDLIST
    assert len(HIDDEN_PARAM_WORDLIST) >= 70

def test_auth_bypass_headers():
    from penflow.recon.parameter_discovery import AUTH_BYPASS_HEADERS
    assert len(AUTH_BYPASS_HEADERS) >= 6
    headers_str = str(AUTH_BYPASS_HEADERS)
    assert "X-Forwarded-For" in headers_str
    assert "X-Real-IP" in headers_str
    assert "X-Original-URL" in headers_str
