import pytest
import asyncio
from typing import Dict, Any, List
from penflow.capabilities.capability import Capability
from penflow.capabilities.registry import CapabilityRegistry
from penflow.capabilities.matcher import CapabilityMatcher
from penflow.capabilities.selector import CapabilitySelector
from penflow.capabilities.constraints import CapabilityConstraintsEngine
from penflow.capabilities.resolver import CapabilityResolver
from penflow.capabilities.interfaces import ICapabilityProvider
from penflow.capabilities.exceptions import CapabilityNotFoundError, CapabilityConflictError, CapabilityDependencyError
from penflow.testing.strategy import Strategy, TestingHypothesis
from penflow.testing.strategy_builder import StrategyBuilder
from penflow.testing.strategy_executor import StrategyExecutor
from penflow.testing.strategy_scheduler import StrategyScheduler
from penflow.testing.dependencies import StrategyDependencyGraph

class MockCapabilityAgent(ICapabilityProvider):
    def __init__(self, agent_name: str, caps: List[Capability]):
        self.agent_name = agent_name
        self.caps = caps

    def get_capabilities(self) -> List[Capability]:
        return self.caps

    async def initialize(self, context: Any) -> None:
        pass

    def supports(self, capability_id: str) -> bool:
        return any(c.id == capability_id for c in self.caps)

    async def execute(self, capability_id: str, context: Any) -> Dict[str, Any]:
        return {"status": "executed", "capability": capability_id}

    async def shutdown(self) -> None:
        pass

def test_capability_framework_registration_and_resolution():
    registry = CapabilityRegistry()
    
    cap_idor = Capability(id="idor", name="IDOR Access Analysis", priority=10)
    cap_graphql = Capability(id="graphql", name="GraphQL Introspection", priority=5)

    agent_idor = MockCapabilityAgent("IDORAgent", [cap_idor])
    agent_graphql = MockCapabilityAgent("GraphQLAgent", [cap_graphql])

    registry.register_capability(cap_idor, agent_idor, "IDORAgent")
    registry.register_capability(cap_graphql, agent_graphql, "GraphQLAgent")

    resolver = CapabilityResolver(registry)
    resolved = resolver.resolve(["idor", "graphql"])
    
    assert len(resolved) == 2
    assert resolved[0][1] == "IDORAgent"
    assert resolved[1][1] == "GraphQLAgent"

def test_capability_constraints_and_conflicts():
    registry = CapabilityRegistry()
    cap_a = Capability(id="cap_a", name="Cap A", conflicts=["cap_b"])
    cap_b = Capability(id="cap_b", name="Cap B")
    cap_c = Capability(id="cap_c", name="Cap C", dependencies=["cap_d"])

    agent = MockCapabilityAgent("TestAgent", [cap_a, cap_b, cap_c])
    registry.register_capability(cap_a, agent, "TestAgent")
    registry.register_capability(cap_b, agent, "TestAgent")
    registry.register_capability(cap_c, agent, "TestAgent")

    constraints = CapabilityConstraintsEngine(registry)

    # Conflict test
    with pytest.raises(CapabilityConflictError):
        constraints.validate_constraints(["cap_a", "cap_b"])

    # Dependency test
    with pytest.raises(CapabilityDependencyError):
        constraints.validate_constraints(["cap_c"])

@pytest.mark.asyncio
async def test_testing_strategy_builder_and_scheduler():
    hypothesis = TestingHypothesis(
        target="api.target.com",
        reason="Exposed GraphQL endpoint",
        confidence=0.8,
        required_capabilities=["graphql", "idor"]
    )

    builder = StrategyBuilder()
    strat = builder.build_strategy(hypothesis)
    assert strat.title == "Testing Strategy for api.target.com"
    assert len(strat.ordered_execution_plan) == 2

    scheduler = StrategyScheduler()
    scheduler.schedule(strat)

    res = await scheduler.run_next()
    assert res is not None
    assert res["status"] == "COMPLETED"

def test_strategy_dependency_graph():
    graph = StrategyDependencyGraph()
    s1 = Strategy(id="strat_1", title="Auth Discovery")
    s2 = Strategy(id="strat_2", title="BOLA Strategy")

    graph.add_dependency(s2.id, s1.id)

    runnable1 = graph.get_runnable_strategies([s1, s2], completed_ids=set())
    assert len(runnable1) == 1
    assert runnable1[0].id == "strat_1"

    runnable2 = graph.get_runnable_strategies([s1, s2], completed_ids={"strat_1"})
    assert len(runnable2) == 1
    assert runnable2[0].id == "strat_2"
