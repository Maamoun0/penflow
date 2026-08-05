import pytest
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.planning_context import PlanningContext
from penflow.planning.hypothesis import Hypothesis
from penflow.planning.hypothesis_registry import HypothesisRegistry
from penflow.planning.reasoning import ReasoningEngine
from penflow.planning.confidence_engine import ConfidenceEngine
from penflow.planning.priority_engine import PriorityEngine
from penflow.planning.decision_engine import DecisionEngine
from penflow.planning.planning_rules import PlanningRuleEngine
from penflow.planning.hypothesis_builder import HypothesisBuilder
from penflow.planning.hypothesis_ranker import HypothesisRanker
from penflow.planning.planner import Planner
from penflow.planning.planning_pipeline import PlanningPipeline

def test_hypothesis_model_and_registry():
    h = Hypothesis(title="Possible BOLA", confidence=0.8, priority=7.5)
    registry = HypothesisRegistry()
    registry.add_hypothesis(h)

    retrieved = registry.get_hypothesis(h.id)
    assert retrieved is not None
    assert retrieved.title == "Possible BOLA"
    assert len(registry.get_active_hypotheses()) == 1

def test_reasoning_and_confidence_engine():
    reasoning = ReasoningEngine()
    chain = reasoning.build_reasoning_chain(["GraphQL introspection"], "Endpoint exposed", "GraphQL Auth Weakness")
    assert "GraphQL introspection" in chain
    assert "Implies GraphQL Auth Weakness" in chain

    h = Hypothesis(confidence=0.5)
    ce = ConfidenceEngine()
    ce.adjust_confidence(h, 0.4, "Additional endpoint evidence")
    assert h.confidence == 0.9
    assert h.status == "ACTIVE"

    ce.adjust_confidence(h, -0.85, "Contradictory evidence")
    assert h.confidence == 0.05
    assert h.status == "INVALIDATED"

def test_priority_and_decision_engine():
    pe = PriorityEngine()
    h = Hypothesis(confidence=0.8)
    p_score = pe.calculate_priority(h, business_value=8.0, asset_importance=8.0)
    assert p_score == round((0.8 * 4.0) + (8.0 * 0.6), 2)  # 3.2 + 4.8 = 8.0

    de = DecisionEngine()
    dec = de.decide(h)
    assert dec.decision_type == "CREATE_STRATEGY"
    assert "High confidence" in dec.explanation

def test_planning_rules_builder_and_ranker():
    rule_eng = PlanningRuleEngine()
    builder = HypothesisBuilder(rule_eng)

    hypotheses = builder.build_from_observation("Discovered graphql endpoint at /graphql?id=100")
    assert len(hypotheses) >= 2  # Matches static and mined rules for graphql and id=

    ranker = HypothesisRanker()
    ranked = ranker.rank(hypotheses)
    assert len(ranked) >= 2
    assert ranked[0].priority >= ranked[1].priority

def test_planner_and_pipeline_deterministic_execution():
    ks = KnowledgeStore()
    ks.observations.record_observation("api.company.com", "endpoint", {"url": "/api/v1/user?id=10", "type": "graphql"})

    pipeline = PlanningPipeline(ks)
    plan1 = pipeline.run_planning_cycle("company.com")
    plan2 = pipeline.run_planning_cycle("company.com")

    # Determinism check: Same observations produce exact same hypotheses, priorities, and plan
    assert len(plan1.ordered_hypotheses) == len(plan2.ordered_hypotheses)
    assert plan1.expected_value == plan2.expected_value
    assert len(plan1.ordered_hypotheses) > 0
    assert "graphql_analysis" in plan1.required_capabilities
