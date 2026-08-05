import pytest
import httpx
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.resolver import CapabilityResolver
from penflow.traffic.models import IdentityType
from penflow.traffic.http_client import StatefulHttpClient
from penflow.agents import (
    IDORCapabilityAgent,
    BFLACapabilityAgent,
    MassAssignmentCapabilityAgent,
    GraphQLCapabilityAgent,
    RaceConditionCapabilityAgent,
)

@pytest.mark.asyncio
async def test_idor_agent_cross_session_swap():
    ks = KnowledgeStore()
    ks.observations.record_observation(
        asset_id="api.target.com",
        obs_type="endpoint_discovered",
        data={"url": "https://api.target.com/api/v1/invoices/100"}
    )
    ctx = CapabilityExecutionContext(asset="api.target.com", knowledge_store=ks)
    
    # Mock transport returning Alice's invoice to whoever asks
    def idor_mock_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"invoice_id": "100", "user_id": "alice", "amount": 500})

    transport = httpx.MockTransport(idor_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = IDORCapabilityAgent()
    res = await agent.execute("id_access_analysis", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["confidence_score"] >= 0.80

@pytest.mark.asyncio
async def test_bfla_agent_method_tampering():
    ks = KnowledgeStore()
    ks.observations.record_observation(
        asset_id="target.com",
        obs_type="endpoint_discovered",
        data={"url": "https://target.com/api/v1/admin/users"}
    )
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks)

    # GET is 403 Forbidden, but POST bypasses check and returns 200
    def bfla_mock_handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return httpx.Response(403, json={"error": "Admin permission required"})
        elif req.method == "POST":
            return httpx.Response(200, json={"success": True, "created": 1})
        return httpx.Response(404)

    transport = httpx.MockTransport(bfla_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = BFLACapabilityAgent()
    res = await agent.execute("bfla_analysis", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert "bypassed" in res["evidence"]["reasoning"]

@pytest.mark.asyncio
async def test_mass_assignment_agent():
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks)

    def mass_mock_handler(req: httpx.Request) -> httpx.Response:
        body = req.read().decode("utf-8")
        if "is_admin" in body:
            return httpx.Response(200, json={"name": "PenFlow Tester", "is_admin": True, "role": "admin"})
        return httpx.Response(200, json={"name": "PenFlow Tester"})

    transport = httpx.MockTransport(mass_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = MassAssignmentCapabilityAgent()
    res = await agent.execute("mass_assignment", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert "is_admin" in res["evidence"]["reflected_fields"]
    assert "role" in res["evidence"]["reflected_fields"]

@pytest.mark.asyncio
async def test_graphql_agent_introspection():
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks)

    def gql_mock_handler(req: httpx.Request) -> httpx.Response:
        body = req.read().decode("utf-8")
        if "__schema" in body:
            return httpx.Response(200, json={
                "data": {
                    "__schema": {
                        "types": [{"name": "User"}, {"name": "Account"}, {"name": "Query"}]
                    }
                }
            })
        return httpx.Response(200, json=[{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}])

    transport = httpx.MockTransport(gql_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = GraphQLCapabilityAgent()
    res = await agent.execute("schema_introspection", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["evidence"]["introspection_enabled"] is True
    assert res["evidence"]["discovered_types_count"] == 3

@pytest.mark.asyncio
async def test_race_condition_agent_burst():
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks)

    # Server mistakenly accepts all requests in burst
    def race_mock_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"redeemed": True, "reward": 100})

    transport = httpx.MockTransport(race_mock_handler)
    ctx.http_client = StatefulHttpClient(
        session_manager=ctx.session_manager,
        scope_domains=["target.com"],
        custom_transport=transport,
        rate_limit_rps=100.0
    )

    agent = RaceConditionCapabilityAgent(burst_size=5)
    res = await agent.execute("race_condition_check", ctx)

    assert res["status"] == "COMPLETED"
    assert res["is_vulnerable"] is True
    assert res["evidence"]["success_count"] == 5

def test_full_specialist_agents_registry_and_resolver():
    registry = CapabilityRegistry()
    specialists = [
        IDORCapabilityAgent(priority=10),
        BFLACapabilityAgent(priority=10),
        MassAssignmentCapabilityAgent(priority=10),
        GraphQLCapabilityAgent(priority=10),
        RaceConditionCapabilityAgent(priority=10),
    ]

    for agent in specialists:
        for cap in agent.get_capabilities():
            registry.register_capability(cap, agent, agent.name)

    resolver = CapabilityResolver(registry)

    required = [
        "id_access_analysis",
        "bfla_analysis",
        "mass_assignment",
        "schema_introspection",
        "race_condition_check"
    ]

    resolved = resolver.resolve(required)
    assert len(resolved) == 5
    resolved_names = {agent_name for _, agent_name, _ in resolved}
    assert resolved_names == {
        "IDORCapabilityAgent",
        "BFLACapabilityAgent",
        "MassAssignmentCapabilityAgent",
        "GraphQLCapabilityAgent",
        "RaceConditionCapabilityAgent"
    }
