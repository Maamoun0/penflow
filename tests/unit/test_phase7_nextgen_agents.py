import pytest
import httpx
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.traffic.http_client import StatefulHttpClient
from penflow.recon.js_miner import JavaScriptASTParser
from penflow.agents import (
    OAuthJWTCapabilityAgent,
    CORSCapabilityAgent,
    SSRFCapabilityAgent,
)

@pytest.mark.asyncio
async def test_oauth_jwt_agent_none_alg():
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks)

    def jwt_mock_handler(req: httpx.Request) -> httpx.Response:
        auth_hdr = req.headers.get("Authorization", "")
        # Accept unsigned alg: none token
        if "Bearer" in auth_hdr and auth_hdr.endswith("."):
            return httpx.Response(200, json={"user": "admin", "privilege": "root"})
        return httpx.Response(401, json={"error": "invalid signature"})

    transport = httpx.MockTransport(jwt_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = OAuthJWTCapabilityAgent()
    res = await agent.execute("jwt_security_analysis", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["confidence_score"] == 0.95
    assert "alg: none" in res["evidence"]["reasoning"]

@pytest.mark.asyncio
async def test_cors_agent_reflection():
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks)

    def cors_mock_handler(req: httpx.Request) -> httpx.Response:
        origin = req.headers.get("Origin", "")
        headers = {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Content-Type": "application/json"
        }
        body = '{"user": "alice", "email": "alice@target.com", "bearer_token": "eyJhbGciOiJIUzI1NiJ9.test.sig"}'
        return httpx.Response(200, headers=headers, content=body.encode())

    transport = httpx.MockTransport(cors_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = CORSCapabilityAgent()
    res = await agent.execute("cors_misconfig_check", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["evidence"]["response_acac"] == "true"

@pytest.mark.asyncio
async def test_ssrf_agent_metadata():
    ks = KnowledgeStore()
    # Provide an observation with a URL-bearing parameter so the agent finds a candidate endpoint
    obs_data = {
        "endpoints": [
            {"url": "https://target.com/api/v1/fetch?url=test", "status": 200,
             "content_type": "application/json", "depth": 0, "parameters": ["url"]}
        ],
        "forms": [],
    }
    ctx = CapabilityExecutionContext(
        asset="target.com",
        knowledge_store=ks,
        observations=[{"type": "crawl_results", "data": obs_data}],
    )

    def ssrf_mock_handler(req: httpx.Request) -> httpx.Response:
        url_str = str(req.url)
        body = ""
        try:
            body = req.read().decode("utf-8")
        except Exception:
            pass
        # Simulate AWS IMDS response when the payload contains the metadata IP
        if "169.254.169.254" in url_str or "169.254.169.254" in body:
            return httpx.Response(
                200,
                json={"ami-id": "ami-0987654321", "instance-id": "i-1234567890",
                      "hostname": "ip-10-0-1-1.us-east-1.compute.internal"}
            )
        return httpx.Response(400, json={"error": "invalid URL"})

    transport = httpx.MockTransport(ssrf_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = SSRFCapabilityAgent()
    # New capability id in Phase 20
    res = await agent.execute("ssrf_metadata_exfiltration", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["confidence_score"] >= 0.90


def test_javascript_ast_parser():
    parser = JavaScriptASTParser()
    sample_bundle = """
    function fetchUserData(userId) {
        return fetch("/api/v1/users/" + userId + "?token=secret_123");
    }
    const apiKey = "AIzaSyD1234567890abcdefghijklmnopqrstuv";
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    """

    res = parser.parse_js_content(sample_bundle, "https://target.com/assets/app.js")
    assert "/api/v1/users/" in res["discovered_endpoints"]
    assert "AIzaSyD1234567890abcdefghijklmnopqrstuv" in res["discovered_secrets"]
    assert "token" in res["discovered_parameters"]
