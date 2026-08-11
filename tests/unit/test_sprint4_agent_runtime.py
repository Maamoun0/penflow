import pytest
import asyncio
from typing import Dict, Any
from penflow.agents.base.base_agent import BaseAgent
from penflow.agents.agent_context import AgentContext
from penflow.agents.agent_registry import AgentRegistry
from penflow.agents.agent_health import AgentHealthState
from penflow.agents.agent_metrics import AgentMetricsTracker
from penflow.agents.agent_events import AgentEventBus
from penflow.agents.agent_supervisor import AgentSupervisor
from penflow.agents.agent_scheduler import AgentScheduler
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.core.context import ExecutionContext
from penflow.infrastructure.logger import get_logger

class MockTestAgent(BaseAgent):
    name = "MockTestAgent"
    version = "1.0.0"
    description = "Mock Agent for Unit Testing"
    capabilities = ["mock_analysis"]
    priority = 5
    requirements = []

    async def initialize(self, context: AgentContext) -> None:
        await super().initialize(context)

    async def execute(self, context: AgentContext, input_data: Dict[str, Any]) -> Dict[str, Any]:
        if input_data.get("trigger_fail"):
            raise ValueError("Mock Execution Error")
        return {"status": "success", "processed": input_data.get("data")}

@pytest.mark.asyncio
async def test_base_agent_lifecycle_and_health():
    agent = MockTestAgent()
    ks = KnowledgeStore()
    exec_ctx = ExecutionContext()
    ctx = AgentContext(knowledge_store=ks, execution_context=exec_ctx, logger=get_logger())

    health1 = await agent.health_check()
    assert health1.state == AgentHealthState.STOPPED

    await agent.initialize(ctx)
    health2 = await agent.health_check()
    assert health2.state == AgentHealthState.HEALTHY

    await agent.pause()
    health3 = await agent.health_check()
    assert health3.state == AgentHealthState.PAUSED

@pytest.mark.asyncio
async def test_agent_registry_and_loader():
    registry = AgentRegistry()
    registry.register(MockTestAgent)

    assert registry.is_enabled("MockTestAgent") is True
    assert "MockTestAgent" in registry.get_all_registered()

    instance = registry.get_agent_instance("MockTestAgent")
    assert instance is not None
    assert instance.name == "MockTestAgent"

@pytest.mark.asyncio
async def test_agent_events_pub_sub_and_request_response():
    bus = AgentEventBus()
    received = []

    async def event_handler(evt):
        received.append(evt.payload)
        if evt.reply_to:
            await bus.publish(evt.topic, "ResponderAgent", {"reply": "pong"}, reply_to=evt.reply_to)

    bus.subscribe("ping_topic", event_handler)

    # Publish
    await bus.publish("ping_topic", "SenderAgent", {"msg": "hello"})
    assert len(received) == 1
    assert received[0]["msg"] == "hello"

@pytest.mark.asyncio
async def test_agent_supervisor_and_scheduler():
    registry = AgentRegistry()
    registry.register(MockTestAgent)

    supervisor = AgentSupervisor(max_restarts=2)
    scheduler = AgentScheduler(registry=registry, supervisor=supervisor)

    ks = KnowledgeStore()
    exec_ctx = ExecutionContext()
    ctx = AgentContext(knowledge_store=ks, execution_context=exec_ctx, logger=get_logger())

    # Successful execution
    res = await scheduler.schedule_agent("MockTestAgent", ctx, {"data": "test_payload"})
    assert res["status"] == "success"
    assert res["processed"] == "test_payload"

    # Metrics
    metrics = supervisor.metrics_tracker.get_metrics("MockTestAgent")
    assert metrics.execution_count == 1
    assert metrics.successes == 1
