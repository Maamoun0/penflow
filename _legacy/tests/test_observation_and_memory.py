import pytest
import time
from penflow.observation.observation_event import ObservationEvent
from penflow.memory.quad_memory import QuadMemoryManager

def test_observation_event_creation():
    event = ObservationEvent(
        event_type="http_response",
        target="example.com",
        data={"status": 200, "url": "https://example.com/api/user/1"},
        metadata={"source": "playwright"}
    )
    
    assert event.event_type == "http_response"
    assert event.target == "example.com"
    assert len(event.event_id) == 16
    
    event_dict = event.to_dict()
    restored = ObservationEvent.from_dict(event_dict)
    assert restored.event_id == event.event_id

def test_quad_memory_manager():
    memory = QuadMemoryManager(":memory:")
    
    # 1. Test Global Knowledge
    memory.add_global_knowledge("IDOR_BOLA", "Authorization", {"description": "Broken object level auth"})
    knowledge = memory.get_global_knowledge("IDOR_BOLA")
    assert knowledge["category"] == "Authorization"
    assert knowledge["details"]["description"] == "Broken object level auth"
    
    # 2. Test Target State
    memory.set_target_entity("app.target.com", "Endpoint", "/api/invoices", {"method": "GET", "auth_required": True})
    entities = memory.get_target_entities("app.target.com", "Endpoint")
    assert len(entities) == 1
    assert entities[0]["entity_key"] == "/api/invoices"
    
    # 3. Test Experiment History
    assert not memory.has_experiment_run("app.target.com", "hash_abc_123")
    memory.log_experiment("app.target.com", "hash_abc_123", "hypo_1", "HTTP_SWAP", "User A token", "200 OK", "SUCCESS")
    assert memory.has_experiment_run("app.target.com", "hash_abc_123")
    
    # 4. Test Research Journal
    entry_id = memory.record_journal_entry(
        target="app.target.com",
        hypothesis="User B can view User A invoice",
        reasoning="Missing authorization check on /api/invoices/101",
        evidence={"status": 200, "user_a_id": 101, "user_b_token": "valid"},
        result="CONFIRMED",
        reflection="IDOR vulnerability verified with 100% confidence"
    )
    assert entry_id > 0
    entries = memory.get_journal_entries("app.target.com")
    assert len(entries) == 1
    assert entries[0]["hypothesis"] == "User B can view User A invoice"
    
    memory.close()
