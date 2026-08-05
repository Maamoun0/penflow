import pytest
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.leadership import ResearchDirectorAgent, EconomyAgent
from penflow.leadership.economy_agent import TokenBudget

def test_economy_agent_budget_control():
    budget = TokenBudget(max_llm_tokens=1000, max_estimated_cost_usd=0.10)
    economy = EconomyAgent(budget=budget)

    # 1. Normal allocation
    allowed = economy.allocate_tokens(requested_tokens=500, estimated_cost=0.04)
    assert allowed is True
    assert economy.budget.used_llm_tokens == 500

    # 2. Exceeding budget
    denied = economy.allocate_tokens(requested_tokens=600, estimated_cost=0.08)
    assert denied is False

    # 3. Model routing decision
    optimal_model = economy.select_optimal_model("HIGH")
    assert optimal_model in ["CLOUD_HIGH_CAPACITY_LLM", "LOCAL_DETERMINISTIC_RULES"]

def test_research_director_agent_strategic_evaluation():
    ks = KnowledgeStore()
    ks.observations.record_observation(
        asset_id="target.com",
        obs_type="endpoint_discovered",
        data={"url": "https://target.com/graphql?id=100"}
    )
    
    economy = EconomyAgent()
    director = ResearchDirectorAgent(knowledge_store=ks, economy_agent=economy)

    plan = director.evaluate_target_strategy("target.com")
    assert plan is not None
    assert plan.expected_value > 0.0
    assert len(plan.ordered_hypotheses) > 0

    # Mid-scan re-planning test
    replan = director.evaluate_mid_scan_replanning("target.com", new_verified_count=1)
    assert replan is not None
