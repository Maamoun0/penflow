import asyncio
import pytest
from penflow.core.event_bus import EventBus, Event

@pytest.mark.asyncio
async def test_event_bus_pub_sub():
    bus = EventBus.get_instance()
    
    events_received = []
    wildcards_received = []
    
    async def handler1(event):
        events_received.append(event)
        
    async def handler2(event):
        wildcards_received.append(event)
        
    # Subscribe
    await bus.subscribe("TEST_EVENT", handler1)
    await bus.subscribe("*", handler2)
    
    # Emit event
    await bus.emit("TEST_EVENT", {"foo": "bar"})
    
    # Wait a brief moment for async tasks to run
    await asyncio.sleep(0.1)
    
    assert len(events_received) == 1
    assert events_received[0].type == "TEST_EVENT"
    assert events_received[0].data == {"foo": "bar"}
    
    assert len(wildcards_received) == 1
    assert wildcards_received[0].type == "TEST_EVENT"
    
    # Unsubscribe
    await bus.unsubscribe("TEST_EVENT", handler1)
    await bus.unsubscribe("*", handler2)
