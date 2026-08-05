from typing import Dict, List, Optional
from penflow.testing.strategy import Strategy

class StrategyRegistry:
    """
    Registry for storing and managing active testing strategies.
    """
    def __init__(self):
        self._strategies: Dict[str, Strategy] = {}

    def register(self, strategy: Strategy) -> None:
        self._strategies[strategy.id] = strategy

    def get(self, strategy_id: str) -> Optional[Strategy]:
        return self._strategies.get(strategy_id)

    def get_all(self) -> List[Strategy]:
        return list(self._strategies.values())
