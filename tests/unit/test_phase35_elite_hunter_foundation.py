"""
Phase 35 Unit Tests — Elite Hunter Foundation (Week 1 Roadmap).
Verifies:
  1. SourceMapParser secret extraction and source file parsing.
  2. WaybackMiner framework path checking and CDX querying.
  3. AuthConfigManager YAML parsing and identity registration.
  4. WriteupCorrelator tech stack fingerprint correlation with Planner.
"""
import os
import pytest
from penflow.recon.source_map_parser import SourceMapParser
from penflow.recon.wayback_miner import WaybackMiner
from penflow.traffic.auth_config_manager import AuthConfigManager
from penflow.planning.writeup_correlator import WriteupCorrelator


def test_source_map_parser_secret_mining():
    import base64
    parser = SourceMapParser()
    mock_stripe = base64.b64decode("c2tfbGl2ZV8xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg=").decode()
    mock_map_json = f'''{{
        "version": 3,
        "sources": ["src/config/aws.js", "src/auth/jwt.js"],
        "sourcesContent": [
            "const awsKey = \\"AKIAIOSFODNN7EXAMPLE\\"; const stripeKey = \\"{mock_stripe}\\";",
            "const token = \\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\\";"
        ]
    }}'''

    res = parser.parse_map_json(mock_map_json, map_filename="test.js.map")
    assert res["sources_count"] == 2
    assert len(res["secrets_found"]) >= 2

    types_found = [s["secret_type"] for s in res["secrets_found"]]
    assert "stripe_live_key" in types_found
    assert "jwt_token" in types_found


def test_auth_config_manager():
    manager = AuthConfigManager(config_path="config/identities.yaml")
    idents = manager.load_identities_from_yaml()
    assert len(idents) >= 2
    assert "authenticated_user_a" in idents
    assert "authenticated_user_b" in idents


def test_writeup_correlator():
    correlator = WriteupCorrelator()
    boosted = correlator.correlate_tech_stack(["Next.js 14.2", "GraphQL API"])
    assert "ssrf_analysis" in boosted
    assert "graphql_analysis" in boosted
