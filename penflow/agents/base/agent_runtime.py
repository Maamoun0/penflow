import asyncio
from typing import Dict, Any, Optional
from penflow.agents.base.base_agent import BaseAgent
from penflow.agents.base.agent_context import AgentContext
from penflow.agents.base.agent_supervisor import AgentSupervisor
from penflow.agents.base.agent_metrics import AgentMetricsTracker
from penflow.shared.utils import get_utc_timestamp
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.agent_runtime")

class AgentRuntime:
    """
    Execution wrapper running an individual BaseAgent inside an AgentContext.
    Interacts with AgentSupervisor for error recovery and metrics collection.
    """
    def __init__(self, agent: BaseAgent, supervisor: Optional[AgentSupervisor] = None):
        self.agent = agent
        self.supervisor = supervisor or AgentSupervisor()

    async def run(self, context: AgentContext, input_data: Dict[str, Any]) -> Dict[str, Any]:
        start_time = get_utc_timestamp()
        
        try:
            if not self.agent._is_initialized:
                await self.agent.initialize(context)

            result = await self.agent.execute(context, input_data)
            duration = get_utc_timestamp() - start_time
            
            self.supervisor.metrics_tracker.record_execution(
                agent_name=self.agent.name,
                duration=duration,
                is_success=True
            )
            return result
        except Exception as e:
            duration = get_utc_timestamp() - start_time
            can_restart = await self.supervisor.handle_crash(self.agent, e)
            if can_restart:
                # Retry once after supervisor cleanup restart
                await self.agent.initialize(context)
                result = await self.agent.execute(context, input_data)
                return result
            raise e
