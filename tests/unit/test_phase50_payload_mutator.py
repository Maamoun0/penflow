import pytest
from penflow.intelligence.self_improving_payloads import (
    SelfImprovingPayloadEngine,
    GeneticPayloadMutator
)

def test_genetic_payload_mutator_operations():
    mutator = GeneticPayloadMutator()

    # Delimiter mutation
    p1 = "SELECT 1 FROM users"
    m1 = mutator.mutate_delimiters(p1)
    assert " " not in m1 or "/**/" in m1 or "%20" in m1 or "+" in m1

    # Quote mutation
    p2 = "admin' OR '1'='1"
    m2 = mutator.mutate_quotes(p2)
    assert '"' in m2

    # Crossover
    cross = mutator.crossover("SELECT * FROM a", "UNION SELECT 1,2")
    assert len(cross) > 5

def test_self_improving_reinforcement_feedback():
    engine = SelfImprovingPayloadEngine()
    initial_reward = engine.strategy_rewards["unicode_fullwidth"]

    # Record success -> reward should increase
    engine.record_feedback(
        strategy="unicode_fullwidth",
        target="target.com",
        technology="cloudflare",
        was_blocked=False,
        was_successful=True
    )
    assert engine.strategy_rewards["unicode_fullwidth"] > initial_reward

    # Record block -> reward should decrease
    engine.record_feedback(
        strategy="case_randomize",
        target="target.com",
        technology="cloudflare",
        was_blocked=True,
        was_successful=False,
        status_code=403
    )
    assert engine.strategy_rewards["case_randomize"] < 5.0

def test_evolve_population():
    engine = SelfImprovingPayloadEngine()
    seed = "admin' OR 1=1--"
    pop = engine.evolve_population(seed, generations=2, population_size=6)
    assert len(pop) > 1
    assert seed in pop
