import asyncio
from typing import Dict, Any, List, Optional
from penflow.agents.agent_registry import AgentRegistry
from penflow.agents.agent_context import AgentContext
from penflow.agents.agent_runtime import AgentRuntime
from penflow.agents.agent_supervisor import AgentSupervisor
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.agent_scheduler")

class AgentScheduler:
    """
    Orchestrates scheduling and concurrent dispatching of registered Research Agents.
    """
    def __init__(self, registry: AgentRegistry, supervisor: Optional[AgentSupervisor] = None):
        self.registry = registry
        self.supervisor = supervisor or AgentSupervisor()

    async def schedule_agent(self, agent_name: str, context: AgentContext, input_data: Dict[str, Any]) -> Dict[str, Any]:
        agent_instance = self.registry.get_agent_instance(agent_name)
        if not agent_instance:
            raise ValueError(f"Agent '{agent_name}' is not registered or is disabled")

        if not self.registry.validate_dependencies(agent_name):
            raise RuntimeError(f"Dependencies for agent '{agent_name}' are unsatisfied")

        runtime = AgentRuntime(agent_instance, supervisor=self.supervisor)
        logger.info(f"[AgentScheduler] Dispatching agent '{agent_name}' (priority={agent_instance.priority})")
        return await runtime.run(context, input_data)
