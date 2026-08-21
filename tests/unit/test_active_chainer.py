import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from penflow.intelligence.state_manager import ExploitStateStore, StateFact
from penflow.intelligence.active_chainer import ActiveExploitChainer

@pytest.mark.asyncio
async def test_state_store_pubsub():
    store = ExploitStateStore()
    
    mock_subscriber = MagicMock()
    mock_subscriber.on_fact_added = AsyncMock()
    
    store.subscribe(mock_subscriber)
    
    await store.add_fact("test_key", "test_value", "TestAgent", "example.com")
    
    mock_subscriber.on_fact_added.assert_called_once()
    args, _ = mock_subscriber.on_fact_added.call_args
    fact = args[0]
    assert isinstance(fact, StateFact)
    assert fact.key == "test_key"
    assert fact.value == "test_value"

@pytest.mark.asyncio
async def test_active_chainer_idor_to_ato():
    store = ExploitStateStore()
    mock_dispatcher = MagicMock()
    mock_dispatcher.dispatch_task = AsyncMock()
    
    chainer = ActiveExploitChainer(store, mock_dispatcher)
    
    # Simulate an IDOR agent finding a leaked email
    await store.add_fact("leaked_user_email", "admin@target.local", "IDORAgent", "target.local")
    
    # Give async tasks a moment to process the pub/sub
    await asyncio.sleep(0.1)
    
    # Assert the chainer dynamically dispatched an ATO task
    mock_dispatcher.dispatch_task.assert_called_once_with(
        agent_name="AccountTakeoverCapabilityAgent",
        capability="password_reset_poisoning_chained",
        asset="target.local",
        context_data={"target_email": "admin@target.local"}
    )
