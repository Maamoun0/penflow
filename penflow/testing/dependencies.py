from typing import Dict, List, Set
from penflow.testing.strategy import Strategy

class StrategyDependencyGraph:
    """
    Manages dependency relationships and topological execution ordering across strategies.
    """
    def __init__(self):
        self._graph: Dict[str, Set[str]] = {}  # strategy_id -> set(dependency_strategy_ids)

    def add_dependency(self, strategy_id: str, depends_on_id: str) -> None:
        if strategy_id not in self._graph:
            self._graph[strategy_id] = set()
        self._graph[strategy_id].add(depends_on_id)

    def get_runnable_strategies(self, strategies: List[Strategy], completed_ids: Set[str]) -> List[Strategy]:
        runnable = []
        for strat in strategies:
            if strat.id not in completed_ids:
                deps = self._graph.get(strat.id, set())
                if deps.issubset(completed_ids):
                    runnable.append(strat)
        return runnable
