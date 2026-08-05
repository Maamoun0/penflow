import pytest
from penflow.core.event_bus import EventBus
from penflow.agents.api_agent import APIAgent
from penflow.agents.idor_agent.idor_swarm_agent import IDORSwarmAgent
from penflow.network.http_client import HttpClient
from penflow.network.auth_session_manager import AuthSessionManager

@pytest.mark.asyncio
async def test_api_agent_initialization():
    event_bus = EventBus.get_instance()
    api_agent = APIAgent(event_bus=event_bus)
    
    assert api_agent.agent_name == "APIAgent"
    assert api_agent.role == "APIDiscovery"

@pytest.mark.asyncio
async def test_idor_swarm_agent_initialization():
    event_bus = EventBus.get_instance()
    idor_swarm = IDORSwarmAgent(event_bus=event_bus)
    
    assert idor_swarm.agent_name == "IDORSwarmAgent"
    assert idor_swarm.role == "VulnerabilitySpecialist"
