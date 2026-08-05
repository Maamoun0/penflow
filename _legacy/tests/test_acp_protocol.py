import pytest
from penflow.core.acp_protocol import ACPMessage, ACPMessageType

def test_acp_message_creation_and_validation():
    msg = ACPMessage(
        sender={"team": "ReconTeam", "agent": "SubdomainAgent"},
        recipient={"team": "PlanningTeam", "agent": "StrategyAgent"},
        intent="INTEL_PUBLISH",
        message_type=ACPMessageType.RECON_INTEL_PUBLISHED,
        payload={"target": "company.com", "discovered_subdomains": ["api.company.com"]},
        meta={"priority": "HIGH"}
    )
    
    assert msg.acp_version == "1.0"
    assert msg.validate() is True
    assert msg.sender["team"] == "ReconTeam"
    assert msg.message_type == "ReconIntelPublished"
    
    json_str = msg.to_json()
    restored = ACPMessage.from_json(json_str)
    assert restored.message_id == msg.message_id
    assert restored.payload["target"] == "company.com"

def test_acp_message_validation_failure():
    invalid_msg = ACPMessage(
        sender={}, # Missing team
        message_type=""
    )
    assert invalid_msg.validate() is False
