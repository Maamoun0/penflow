import pytest
import httpx
from penflow.traffic.models import (
    IdentityType,
    AuthCredentials,
    Identity,
    TrafficRequest,
    TrafficResponse,
    TrafficExchange,
)
from penflow.traffic.session_manager import SessionManager
from penflow.traffic.http_client import StatefulHttpClient
from penflow.traffic.diff_engine import DifferentialEngine
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

def test_identity_and_session_manager():
    sm = SessionManager()
    
    # Default guest identity
    guest = sm.get_identity("anonymous_guest")
    assert guest is not None
    assert guest.identity_type == IdentityType.UNAUTHENTICATED_GUEST

    # Create User A
    user_a = sm.create_identity(
        identity_id="user_alice",
        identity_type=IdentityType.STANDARD_USER_A,
        name="Alice Tester",
        bearer_token="token_alice_12345",
        cookies={"session": "alice_sess_cookie"}
    )
    assert user_a.id == "user_alice"
    assert sm.get_headers_for("user_alice")["Authorization"] == "Bearer token_alice_12345"
    assert sm.get_cookies_for("user_alice")["session"] == "alice_sess_cookie"

    # Create User B
    user_b = sm.create_identity(
        identity_id="user_bob",
        identity_type=IdentityType.STANDARD_USER_B,
        name="Bob Attacker",
        bearer_token="token_bob_67890"
    )
    assert sm.has_multi_tenant_pair() is True
    assert len(sm.list_identities()) == 3

@pytest.mark.asyncio
async def test_stateful_http_client_mock_transport():
    sm = SessionManager()
    sm.create_identity("user_a", IdentityType.STANDARD_USER_A, bearer_token="token_a")
    
    # Mock transport handler
    def custom_handler(request: httpx.Request) -> httpx.Response:
        auth_header = request.headers.get("Authorization")
        if auth_header == "Bearer token_a":
            return httpx.Response(200, json={"status": "ok", "user": "alice", "balance": 1000})
        return httpx.Response(401, json={"error": "unauthorized"})

    transport = httpx.MockTransport(custom_handler)
    client = StatefulHttpClient(
        session_manager=sm,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    # 1. In-scope authorized request
    exchange_a = await client.send_as_identity("user_a", "GET", "https://target.com/api/me")
    assert exchange_a.response is not None
    assert exchange_a.response.status_code == 200
    assert exchange_a.response.body_json["balance"] == 1000

    # 2. Out-of-scope blocked request
    exchange_out = await client.send_as_identity("user_a", "GET", "https://evil-target.com/steal")
    assert exchange_out.response is not None
    assert exchange_out.response.status_code == 403
    assert "Scope Enforcement" in exchange_out.response.body_text

def test_differential_engine_idor_detection():
    engine = DifferentialEngine()

    req_a = TrafficRequest(method="GET", url="https://target.com/api/v1/invoices/100", identity_id="user_a")
    resp_a = TrafficResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body_text='{"invoice_id": "100", "user_id": "alice_uuid_1", "amount": 500, "secret_notes": "sensitive"}',
        body_json={"invoice_id": "100", "user_id": "alice_uuid_1", "amount": 500, "secret_notes": "sensitive"},
        content_length=95
    )
    exch_a = TrafficExchange(request=req_a, response=resp_a, identity_used="user_a")

    # User B requests Alice's invoice and gets it back
    req_b = TrafficRequest(method="GET", url="https://target.com/api/v1/invoices/100", identity_id="user_b")
    resp_b = TrafficResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body_text='{"invoice_id": "100", "user_id": "alice_uuid_1", "amount": 500, "secret_notes": "sensitive"}',
        body_json={"invoice_id": "100", "user_id": "alice_uuid_1", "amount": 500, "secret_notes": "sensitive"},
        content_length=95
    )
    exch_b = TrafficExchange(request=req_b, response=resp_b, identity_used="user_b")

    diff = engine.compare_exchanges(exch_a, exch_b)
    
    assert diff.is_potential_idor is True
    assert diff.confidence_score >= 0.85
    assert diff.structural_match is True
    assert "100" in diff.leaked_identifiers

def test_differential_engine_proper_isolation():
    engine = DifferentialEngine()

    req_a = TrafficRequest(method="GET", url="https://target.com/api/v1/documents/42", identity_id="user_a")
    resp_a = TrafficResponse(status_code=200, body_text='{"doc": "my secret doc"}', content_length=24)
    exch_a = TrafficExchange(request=req_a, response=resp_a, identity_used="user_a")

    req_b = TrafficRequest(method="GET", url="https://target.com/api/v1/documents/42", identity_id="user_b")
    resp_b = TrafficResponse(status_code=403, body_text='{"error": "Access Denied"}', content_length=26)
    exch_b = TrafficExchange(request=req_b, response=resp_b, identity_used="user_b")

    diff = engine.compare_exchanges(exch_a, exch_b)
    assert diff.is_potential_idor is False
    assert diff.confidence_score == 0.0

def test_differential_engine_bfla_detection():
    engine = DifferentialEngine()

    req_guest = TrafficRequest(method="DELETE", url="https://target.com/api/v1/admin/users/99", identity_id="guest")
    resp_guest = TrafficResponse(status_code=200, body_text='{"deleted": true, "user_id": 99}', content_length=30)
    exch_guest = TrafficExchange(request=req_guest, response=resp_guest, identity_used="guest")

    diff = engine.compare_exchanges(exch_guest, exch_guest)
    assert diff.is_potential_bfla is True
    assert diff.confidence_score >= 0.90

def test_identifier_extraction():
    engine = DifferentialEngine()
    
    sample_data = {
        "user_id": 1045,
        "uuid": "123e4567-e89b-12d3-a456-426614174000",
        "mongo": "507f191e810c19729de860ea",
        "nested": {
            "account_id": "ACC_9981",
            "regular_text": "hello world"
        }
    }
    extracted = engine.extract_identifiers(sample_data)
    
    assert "1045" in extracted
    assert "123e4567-e89b-12d3-a456-426614174000" in extracted
    assert "507f191e810c19729de860ea" in extracted
    assert "ACC_9981" in extracted
    assert "hello world" not in extracted

def test_execution_context_traffic_integration():
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=ks)
    
    client = ctx.get_http_client()
    assert client is not None
    assert ctx.session_manager is not None
    assert ctx.diff_engine is not None
