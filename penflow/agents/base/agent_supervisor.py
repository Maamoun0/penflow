import asyncio
from typing import Dict, Any, Optional
from penflow.agents.base.base_agent import BaseAgent
from penflow.agents.base.agent_health import AgentHealthStatus, AgentHealthState
from penflow.agents.agent_metrics import AgentMetricsTracker
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.agents.agent_supervisor")

class AgentSupervisor:
    """
    Monitors running agents, tracks failures and execution durations, and restarts crashed agents according to policy.
    """
    def __init__(self, max_restarts: int = 3, metrics_tracker: Optional[AgentMetricsTracker] = None):
        self.max_restarts = max_restarts
        self.metrics_tracker = metrics_tracker or AgentMetricsTracker()
        self._restart_counts: Dict[str, int] = {}
        self._health_statuses: Dict[str, AgentHealthStatus] = {}

    async def check_health(self, agent: BaseAgent) -> AgentHealthStatus:
        try:
            status = await agent.health_check()
            self._health_statuses[agent.name] = status
            return status
        except Exception as e:
            logger.error(f"[AgentSupervisor] Agent '{agent.name}' health check failed: {str(e)}")
            status = AgentHealthStatus(agent_name=agent.name, state=AgentHealthState.FAILED, details=str(e))
            self._health_statuses[agent.name] = status
            return status

    async def handle_crash(self, agent: BaseAgent, error: Exception) -> bool:
        name = agent.name
        self._restart_counts[name] = self._restart_counts.get(name, 0) + 1
        current_restarts = self._restart_counts[name]

        logger.error(f"[AgentSupervisor] Agent '{name}' crashed (attempt {current_restarts}/{self.max_restarts}): {str(error)}")
        self.metrics_tracker.record_execution(name, duration=0.0, is_success=False, error_msg=str(error))

        if current_restarts <= self.max_restarts:
            logger.info(f"[AgentSupervisor] Restarting agent '{name}'...")
            try:
                await agent.cleanup()
                return True
            except Exception as clean_err:
                logger.error(f"[AgentSupervisor] Failed cleanup for '{name}': {str(clean_err)}")
                return False
        else:
            logger.error(f"[AgentSupervisor] Max restarts reached for agent '{name}'. Marking FAILED.")
            self._health_statuses[name] = AgentHealthStatus(
                agent_name=name,
                state=AgentHealthState.FAILED,
                details="Max restarts exceeded"
            )
            return False
