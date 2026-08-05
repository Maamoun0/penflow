from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.leadership.economy")

@dataclass
class TokenBudget:
    max_llm_tokens: int = 100000
    used_llm_tokens: int = 0
    max_estimated_cost_usd: float = 5.0
    current_cost_usd: float = 0.0

class EconomyAgent:
    """
    Economy Agent: Controls token usage, budget allocations, and models routing
    (Cloud LLM vs Local Rule Engine) to prevent runaway API costs during research.
    """
    def __init__(self, budget: Optional[TokenBudget] = None):
        self.budget = budget or TokenBudget()

    def allocate_tokens(self, requested_tokens: int, estimated_cost: float = 0.05) -> bool:
        if (self.budget.used_llm_tokens + requested_tokens > self.budget.max_llm_tokens) or \
           (self.budget.current_cost_usd + estimated_cost > self.budget.max_estimated_cost_usd):
            logger.warning(f"[EconomyAgent] Budget threshold reached! Throttling Cloud LLM usage.")
            return False
        
        self.budget.used_llm_tokens += requested_tokens
        self.budget.current_cost_usd += estimated_cost
        logger.info(f"[EconomyAgent] Tokens allocated: {requested_tokens}. Total cost so far: ${self.budget.current_cost_usd:.4f}")
        return True

    def select_optimal_model(self, task_complexity: str) -> str:
        """
        Routes task to local deterministic engine or high-capacity cloud LLM based on budget and complexity.
        """
        if self.budget.current_cost_usd >= self.budget.max_estimated_cost_usd * 0.90:
            return "LOCAL_DETERMINISTIC_RULES"
        
        if task_complexity == "HIGH":
            return "CLOUD_HIGH_CAPACITY_LLM"
        return "LOCAL_DETERMINISTIC_RULES"
