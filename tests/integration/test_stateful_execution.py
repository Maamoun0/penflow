import pytest
import asyncio
from typing import Dict, Any

from penflow.intelligence.state_manager import ExploitStateStore
from penflow.intelligence.active_chainer import ActiveExploitChainer
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

# Mocking the dispatcher to track if the chained agent was called
class MockDispatcher:
    def __init__(self):
        self.dispatched_tasks = []
        
    async def dispatch_task(self, agent_name: str, capability: str, asset: str, context_data: Dict[str, Any]):
        self.dispatched_tasks.append({
            "agent_name": agent_name,
            "capability": capability,
            "asset": asset,
            "context_data": context_data
        })

@pytest.mark.asyncio
async def test_full_idor_to_ato_chain_execution():
    """
    Tests the End-to-End flow:
    1. System initializes with an ExploitStateStore
    2. We simulate the IDOR agent finding a leaked email and writing to the store
    3. The ActiveChainer should catch this via Pub/Sub
    4. The ActiveChainer should dispatch an Account Takeover task with the leaked email
    """
    
    # 1. Setup global context and architecture
    state_store = ExploitStateStore()
    dispatcher = MockDispatcher()
    
    # Initialize the chainer (this subscribes it to the state_store)
    chainer = ActiveExploitChainer(state_store=state_store, dispatcher=dispatcher)
    
    # Setup execution context (which the agents will use)
    knowledge_store = KnowledgeStore()
    context = CapabilityExecutionContext(
        asset="target.local",
        knowledge_store=knowledge_store,
        state_store=state_store
    )
    
    # 2. Simulate IDOR Agent behavior
    # Instead of making a real HTTP request, we simulate the exact action the IDOR agent takes when it finds a leak:
    leaked_email = "admin_super_secret@target.local"
    await context.state_store.add_fact(
        key="leaked_user_email", 
        value=leaked_email, 
        source_agent="IDORCapabilityAgent", 
        asset=context.asset
    )
    
    # 3. Allow asyncio tasks to process the Pub/Sub event
    await asyncio.sleep(0.1)
    
    # 4. Verify the Chainer caught the event and dispatched the ATO task
    assert len(dispatcher.dispatched_tasks) == 1
    
    task = dispatcher.dispatched_tasks[0]
    assert task["agent_name"] == "AccountTakeoverCapabilityAgent"
    assert task["capability"] == "password_reset_poisoning_chained"
    assert task["asset"] == "target.local"
    assert task["context_data"]["target_email"] == leaked_email
