import asyncio
from typing import List, Optional
from penflow.testing.strategy import Strategy
from penflow.testing.strategy_executor import StrategyExecutor

class StrategyScheduler:
    """
    Schedules and dispatches strategies for execution coordination.
    """
    def __init__(self, executor: Optional[StrategyExecutor] = None):
        self.executor = executor or StrategyExecutor()
        self._queue: List[Strategy] = []

    def schedule(self, strategy: Strategy) -> None:
        strategy.status = "SCHEDULED"
        self._queue.append(strategy)

    async def run_next(self) -> Optional[Dict[str, Any]]:
        if not self._queue:
            return None
        strat = self._queue.pop(0)
        return await self.executor.execute_strategy(strat)
