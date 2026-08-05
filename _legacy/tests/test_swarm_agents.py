import pytest
from penflow.core.event_bus import EventBus
from penflow.memory.quad_memory import QuadMemoryManager
from penflow.agents.director_agent import ResearchDirectorAgent
from penflow.agents.critic_agent import CriticAgent
from penflow.agents.economy_agent import EconomyAgent

@pytest.mark.asyncio
async def test_swarm_strategic_director():
    event_bus = EventBus.get_instance()
    director = ResearchDirectorAgent(event_bus=event_bus)
    
    # Test 1: Empty endpoints -> Deep Crawl decision
    decision_crawl = await director.evaluate_next_step({"target": "target.com", "endpoints": []})
    assert decision_crawl["recommended_action"] == "DEEP_CRAWL"
    
    # Test 2: GraphQL endpoints -> GraphQL test decision
    decision_gql = await director.evaluate_next_step({"target": "target.com", "endpoints": ["https://target.com/graphql"]})
    assert decision_gql["recommended_action"] == "TEST_GRAPHQL_SECURITY"

@pytest.mark.asyncio
async def test_critic_agent_falsification():
    critic = CriticAgent()
    
    # Test valid finding
    valid_finding = {
        "url": "https://target.com/api/user/101",
        "vuln_type": "BOLA_CROSS_SESSION",
        "raw_response": "Status 200 OK - User Data",
        "confidence": 0.95
    }
    verdict_valid = await critic.scrutinize_finding(valid_finding)
    assert verdict_valid["is_valid"] is True
    
    # Test invalid finding (contains login redirect)
    invalid_finding = {
        "url": "https://target.com/api/admin",
        "vuln_type": "AUTH_BYPASS",
        "raw_response": "Status 200 OK - Please sign in to continue login",
        "confidence": 0.5
    }
    verdict_invalid = await critic.scrutinize_finding(invalid_finding)
    assert verdict_invalid["is_valid"] is False

@pytest.mark.asyncio
async def test_economy_agent_routing():
    economy = EconomyAgent()
    
    # Test strategic planning route -> Cloud API
    route_plan = await economy.route_task({"task_type": "strategic_planning"})
    assert route_plan["provider"] == "cloud_api"
    assert route_plan["selected_model"] == "gemini-3.6-flash"
    
    # Test summarization route -> Local Ollama
    route_sum = await economy.route_task({"task_type": "summarization"})
    assert route_sum["provider"] == "ollama"
