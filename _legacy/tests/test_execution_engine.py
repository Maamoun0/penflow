import pytest
import asyncio
from penflow.core.event_bus import EventBus
from penflow.core.command_bus import CommandBus
from penflow.core.acp_protocol import ACPMessage, ACPMessageType

@pytest.mark.asyncio
async def test_event_bus_wildcard_routing():
    bus = EventBus()
    received_events = []

    async def sub_handler(msg: ACPMessage):
        received_events.append(msg)

    bus.subscribe("recon.*", sub_handler)
    
    # Event matching wildcard recon.*
    msg1 = ACPMessage(
        sender={"team": "ReconTeam", "agent": "SubdomainAgent"},
        message_type=ACPMessageType.RECON_INTEL_PUBLISHED,
        payload={"subdomain": "api.company.com"}
    )
    
    # Event NOT matching wildcard recon.*
    msg2 = ACPMessage(
        sender={"team": "APITeam", "agent": "BOLAWorker"},
        message_type=ACPMessageType.CANDIDATE_FINDING_SUBMITTED,
        payload={"vuln": "BOLA"}
    )
    
    await bus.publish("recon.subdomain", msg1)
    await bus.publish("findings.candidate", msg2)
    
    assert len(received_events) == 1
    assert received_events[0].payload["subdomain"] == "api.company.com"

@pytest.mark.asyncio
async def test_command_bus_dispatch_and_locking():
    bus = CommandBus()
    command_log = []

    async def command_handler(msg: ACPMessage):
        command_log.append(msg)
        return {"status": "SUCCESS", "command_id": msg.message_id}

    bus.register_handler("ResearchWorker_IDOR_01", command_handler)

    cmd = ACPMessage(
        sender={"team": "ResearchDirector", "agent": "Planner"},
        recipient={"team": "APIDomain", "agent": "ResearchWorker_IDOR_01"},
        intent="EXECUTE_COMMAND",
        message_type="RunIDORCheck",
        payload={"endpoint": "/api/v1/users/101"}
    )

    result = await bus.dispatch("ResearchWorker_IDOR_01", cmd)
    assert result["status"] == "SUCCESS"
    assert len(command_log) == 1

    # Duplicate command dispatch with same message_id should be rejected by lock registry
    duplicate_result = await bus.dispatch("ResearchWorker_IDOR_01", cmd)
    assert duplicate_result["status"] == "REJECTED_DUPLICATE"
