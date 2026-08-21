"""
Active Exploit Chainer
Acts as the dynamic rules engine that listens to facts from the StateManager and dispatches chained tasks.
"""
import asyncio
from typing import Any, Dict, List
from penflow.infrastructure.logger import get_logger
from penflow.intelligence.state_manager import ExploitStateStore, StateFact
from penflow.intelligence.ai_brain import AIBrainStrategist

logger = get_logger("penflow.intelligence.active_chainer")

class ActiveExploitChainer:
    """
    Listens to new facts discovered during a live scan.
    Evaluates dynamic rules and triggers secondary attack agents if a chain is found.
    """
    def __init__(self, state_store: ExploitStateStore, dispatcher=None):
        self.state_store = state_store
        self.dispatcher = dispatcher # The AgentDispatcher to spawn new tasks
        self.ai_brain = AIBrainStrategist(state_store)
        self.state_store.subscribe(self)
        logger.info("[ActiveChainer] Subscribed to ExploitStateStore and initialized AI Brain")

    async def on_fact_added(self, fact: StateFact) -> None:
        """Callback triggered when a new fact is added to the StateStore."""
        logger.debug(f"[ActiveChainer] Received new fact: {fact.key}")
        await self._evaluate_rules(fact)

    async def _evaluate_rules(self, trigger_fact: StateFact) -> None:
        """Evaluates chaining rules based on the newly added fact."""
        
        # Rule 1: Open Redirect -> OAuth Token Theft
        if trigger_fact.key == "open_redirect_url":
            logger.info(f"[ActiveChainer] TRIGGER: Open Redirect found. Dispatching OAuth theft payload to {trigger_fact.asset}")
            if self.dispatcher:
                # In a real run, this dispatches the OAuthJWTCapabilityAgent with the leaked redirect URL
                await self.dispatcher.dispatch_task(
                    agent_name="OAuthJWTCapabilityAgent",
                    capability="oauth_redirect_chain",
                    asset=trigger_fact.asset,
                    context_data={"redirect_url": trigger_fact.value}
                )

        # Rule 2: IDOR -> Account Takeover
        elif trigger_fact.key == "leaked_user_email":
            logger.info(f"[ActiveChainer] TRIGGER: Leaked Email found. Dispatching Password Reset Poisoning to {trigger_fact.asset}")
            if self.dispatcher:
                await self.dispatcher.dispatch_task(
                    agent_name="AccountTakeoverCapabilityAgent",
                    capability="password_reset_poisoning_chained",
                    asset=trigger_fact.asset,
                    context_data={"target_email": trigger_fact.value}
                )

    async def run_ai_analysis_cycle(self) -> None:
        """Triggers the AI Brain to analyze the entire state and dispatch novel exploit chains."""
        logger.info("[ActiveChainer] Initiating AI Brain analysis cycle...")
        tasks = await self.ai_brain.analyze_state_and_strategize()
        
        if not tasks:
            logger.info("[ActiveChainer] AI Brain did not find any viable new chains.")
            return
            
        logger.info(f"[ActiveChainer] AI Brain discovered {len(tasks)} novel chains! Dispatching...")
        for task in tasks:
            agent_name = task.get("agent_name")
            capability = task.get("capability")
            asset = task.get("asset")
            context_data = task.get("context_data", {})
            reasoning = task.get("reasoning", "No reasoning provided by AI.")
            
            logger.info(f"[ActiveChainer] AI Brain Dispatching: {agent_name} ({capability}) on {asset}. Reasoning: {reasoning}")
            
            if self.dispatcher and agent_name and capability:
                await self.dispatcher.dispatch_task(
                    agent_name=agent_name,
                    capability=capability,
                    asset=asset,
                    context_data=context_data
                )
