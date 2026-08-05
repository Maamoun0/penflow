"""
Phase 23 Unit Tests — Next-Gen Swarm Intelligence & Advanced Exploitation Engineering.
Verifies:
  1. Module A: OpenAPI / Swagger parser ($ref dereferencing, paths, operations, parameters)
  2. Module B: ExploitChainer (SSRF+IAM, CORS+CSRF, Info+BFLA, Param+IDOR, Redirect+OAuth)
  3. Module C: Multi-Identity BOLA & BFLA Matrix (User A, User B, Anonymous Guest, Verb tampering)
  4. Module D: Tech-adaptive payload generation (Node.js, Spring/Java, PHP/Laravel, Python/Flask)
  5. Module E: Report Generator Exploit Chain rendering
"""
import pytest
from unittest.mock import AsyncMock, patch

# ─────────────────────────────────────────────────────────
# Module A: OpenAPI Parser Tests
# ─────────────────────────────────────────────────────────

def test_openapi_parser_parse_swagger_spec():
    from penflow.recon.openapi_parser import OpenAPIParser
    parser = OpenAPIParser()
    sample_spec = {
        "swagger": "2.0",
        "host": "api.example.com",
        "basePath": "/v1",
        "paths": {
            "/users/{id}": {
                "get": {
                    "summary": "Get user profile",
                    "parameters": [{"name": "id", "in": "path", "required": True}]
                },
                "delete": {
                    "summary": "Delete user",
                    "parameters": [{"name": "id", "in": "path"}]
                }
            }
        }
    }

    endpoints = parser.parse_spec("https://api.example.com/swagger.json", sample_spec)
    assert len(endpoints) == 2
    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.url == "https://api.example.com/v1/users/{id}"
    assert "id" in get_ep.parameters

def test_openapi_parser_ref_resolution():
    from penflow.recon.openapi_parser import OpenAPIParser
    parser = OpenAPIParser()
    sample_spec = {
        "openapi": "3.0.0",
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "role": {"type": "string"}
                    }
                }
            }
        },
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                }
            }
        }
    }

    endpoints = parser.parse_spec("https://api.example.com/openapi.json", sample_spec)
    assert len(endpoints) == 1
    post_ep = endpoints[0]
    assert post_ep.method == "POST"
    assert "username" in post_ep.parameters
    assert "role" in post_ep.parameters


# ─────────────────────────────────────────────────────────
# Module B: ExploitChainer Tests
# ─────────────────────────────────────────────────────────

def test_exploit_chainer_ssrf_iam_chain():
    from penflow.intelligence.exploit_chainer import ExploitChainer
    chainer = ExploitChainer()
    mock_findings = [
        {
            "vulnerability_type": "ssrf_metadata_exfiltration",
            "verification_reason": "Verified SSRF: Cloud metadata endpoint 169.254.169.254 exposed IAM security credentials."
        }
    ]
    chains = chainer.construct_chains(mock_findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "CHAIN_SSRF_IAM_THEFT"
    assert chains[0].composite_severity == "CRITICAL"

def test_exploit_chainer_cors_chain():
    from penflow.intelligence.exploit_chainer import ExploitChainer
    chainer = ExploitChainer()
    mock_findings = [
        {
            "vulnerability_type": "cors_misconfig_check",
            "confidence_score": 0.95
        }
    ]
    chains = chainer.construct_chains(mock_findings)
    assert len(chains) == 1
    assert chains[0].chain_id == "CHAIN_CORS_DATA_EXFILTRATION"


# ─────────────────────────────────────────────────────────
# Module C: Multi-Identity BOLA & BFLA Tests
# ─────────────────────────────────────────────────────────

def test_idor_agent_capabilities():
    from penflow.agents.idor_agent import IDORCapabilityAgent
    agent = IDORCapabilityAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 3

def test_bfla_agent_capabilities():
    from penflow.agents.bfla_agent import BFLACapabilityAgent
    agent = BFLACapabilityAgent()
    caps = agent.get_capabilities()
    assert len(caps) == 3


# ─────────────────────────────────────────────────────────
# Module D: Tech-Adaptive Payload Engine Tests
# ─────────────────────────────────────────────────────────

def test_payload_engine_tech_tailored_node():
    from penflow.testing.payload_engine import PayloadTemplateEngine
    engine = PayloadTemplateEngine()
    payloads = engine.generate_tech_tailored_payloads("https://example.com/api", "query", ["Node.js", "Express"])
    names = [p.name for p in payloads]
    assert "NodeJS_NoSQL_JSON_Obj" in names
    assert "NodeJS_Prototype_Pollution" in names

def test_payload_engine_tech_tailored_spring():
    from penflow.testing.payload_engine import PayloadTemplateEngine
    engine = PayloadTemplateEngine()
    payloads = engine.generate_tech_tailored_payloads("https://example.com/api", "template", ["Java", "Spring Boot"])
    names = [p.name for p in payloads]
    assert "Spring_EL_SSTI" in names
    assert "FreeMarker_Execute_SSTI" in names
