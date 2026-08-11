import pytest
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.resolver import CapabilityResolver
from penflow.capabilities.execution_context import ExecutionContext
from penflow.agents.recon.graphql_agent import GraphQLCapabilityAgent
from penflow.agents.authz.idor_agent import IDORCapabilityAgent
from penflow.knowledge.knowledge_store import KnowledgeStore

@pytest.mark.asyncio
async def test_capability_agents_registration_and_execution():
    registry = CapabilityRegistry()
    
    gql_agent = GraphQLCapabilityAgent(priority=10)
    idor_agent = IDORCapabilityAgent(priority=10)

    for cap in gql_agent.get_capabilities():
        registry.register_capability(cap, gql_agent, gql_agent.name)

    for cap in idor_agent.get_capabilities():
        registry.register_capability(cap, idor_agent, idor_agent.name)

    resolver = CapabilityResolver(registry)
    resolved = resolver.resolve(["graphql_analysis", "id_access_analysis"])

    assert len(resolved) == 2
    assert resolved[0][1] == "GraphQLCapabilityAgent"
    assert resolved[1][1] == "IDORCapabilityAgent"

    ks = KnowledgeStore()
    ctx = ExecutionContext(asset="api.target.com", knowledge_store=ks)

    res1 = await resolved[0][0].execute("graphql_analysis", ctx)
    res2 = await resolved[1][0].execute("id_access_analysis", ctx)

    assert res1["status"] == "COMPLETED"
    assert res2["status"] == "COMPLETED"
