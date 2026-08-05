import pytest
import httpx
from penflow.reporting.poc_generator import PoCGenerator
from penflow.benchmarks.mock_target_server import MockTargetServer
from penflow.reporting.dashboard import SwarmDashboard
from penflow.traffic.models import TrafficRequest, TrafficResponse, TrafficExchange
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.execution_plan import ExecutionPlan
from penflow.planning.hypothesis import Hypothesis
from penflow.leadership.economy_agent import EconomyAgent

def test_poc_generator_curl_and_python():
    gen = PoCGenerator()
    req = TrafficRequest(
        method="POST",
        url="https://target.com/api/v1/user/update",
        headers={"Authorization": "Bearer test_token_123"},
        json_data={"is_admin": True}
    )
    resp = TrafficResponse(status_code=200, body_text='{"status": "ok"}')
    exch = TrafficExchange(request=req, response=resp, identity_used="user_a")

    curl_cmd = gen.generate_curl_command(exch)
    assert "curl -i -s -k" in curl_cmd
    assert "-X POST" in curl_cmd
    assert "Bearer test_token_123" in curl_cmd
    assert "--data" in curl_cmd

    py_script = gen.generate_python_script(exch, "Mass Assignment Test")
    assert "import requests" in py_script
    assert "url = \"https://target.com/api/v1/user/update\"" in py_script
    assert "requests.request" in py_script

def test_mock_target_server_benchmark_handling():
    server = MockTargetServer()
    transport = server.get_mock_transport()
    
    with httpx.Client(transport=transport) as client:
        # 1. Test IDOR endpoint
        resp_idor = client.get("https://target.com/api/v1/invoices/100")
        assert resp_idor.status_code == 200
        assert resp_idor.json()["invoice_id"] == "100"

        # 2. Test BFLA endpoint
        resp_bfla_get = client.get("https://target.com/api/v1/admin/users")
        assert resp_bfla_get.status_code == 403

        resp_bfla_post = client.post("https://target.com/api/v1/admin/users")
        assert resp_bfla_post.status_code == 200

        # 3. Test Mass Assignment endpoint
        resp_mass = client.put("https://target.com/api/v1/user/profile", json={"is_admin": True})
        assert resp_mass.status_code == 200
        assert resp_mass.json()["is_admin"] is True

        # 4. Test GraphQL Introspection
        resp_gql = client.post("https://target.com/graphql", content='{"query": "{ __schema { types { name } } }" }')
        assert resp_gql.status_code == 200
        assert "__schema" in resp_gql.text

        # 5. Test Race Condition
        resp_race = client.post("https://target.com/api/v1/coupon/redeem")
        assert resp_race.status_code == 200
        assert resp_race.json()["total_redemptions"] == 1

def test_swarm_dashboard_rendering():
    dashboard = SwarmDashboard()
    ks = KnowledgeStore()
    ks.assets.register_asset("target.com", "domain")
    
    plan = ExecutionPlan(
        ordered_hypotheses=[Hypothesis(title="Possible IDOR", priority=8.0, confidence=0.85)],
        expected_value=8.0
    )
    economy = EconomyAgent()
    verified = [{
        "hash_id": "1234567890abcdef",
        "vulnerability_type": "id_access_analysis",
        "confidence_score": 0.95,
        "verification_reason": "Verified cross-tenant data leakage."
    }]

    # Smoke test rendering without exceptions
    dashboard.render_live_summary("target.com", ks, plan, economy_agent=economy, verified_findings=verified)
