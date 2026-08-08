import pytest
import pytest_asyncio
import time
from penflow.infrastructure.oob_server import (
    OOBCallbackServer,
    InteractionProtocol,
    InteractionCorrelator
)
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.agents import NovelSSRFRedirectAgent, PolyglotSSTIAgent

def test_oob_multiproto_tokens_and_payloads():
    server = OOBCallbackServer(base_domain="oob.test.local")
    token = server.generate_token(
        agent_name="ssrf_tester",
        scan_id="scan_abc123",
        target_url="https://victim.com/api/fetch",
        parameter_name="url",
        protocol=InteractionProtocol.HTTP
    )
    assert token.startswith("ssrf_tes")
    
    http_url = server.get_callback_url(token, protocol="http")
    assert http_url == f"http://{token}.oob.test.local/callback"
    
    https_url = server.get_callback_url(token, protocol="https")
    assert https_url == f"https://{token}.oob.test.local/callback"
    
    dns_payload = server.get_dns_payload(token)
    assert dns_payload == f"{token}.oob.test.local"
    
    smtp_payload = server.get_smtp_payload(token)
    assert smtp_payload == f"probe@{token}.oob.test.local"
    
    ldap_payload = server.get_ldap_payload(token)
    assert ldap_payload == f"ldap://{token}.oob.test.local:389/oob"

@pytest.mark.asyncio
async def test_oob_interaction_recording_and_correlation():
    server = OOBCallbackServer(base_domain="oob.test.local")
    token = server.generate_token(
        agent_name="ssti_tester",
        scan_id="scan_999",
        target_url="https://target.com/render",
        parameter_name="template",
        protocol=InteractionProtocol.DNS
    )

    # Context should be registered in the correlator
    ctx = server.correlator.get_context(token)
    assert ctx is not None
    assert ctx["agent_name"] == "ssti_tester"
    assert ctx["target_url"] == "https://target.com/render"

    # Record simulated DNS callback
    server.record_interaction(
        token=token,
        source_ip="192.168.1.50",
        request_data={"query_type": "A", "domain": f"{token}.oob.test.local"},
        protocol=InteractionProtocol.DNS
    )

    # Wait and check
    hit = await server.wait_for_interaction(token, timeout=1.0)
    assert hit is True

    interaction = server.get_interaction_data(token)
    assert interaction is not None
    assert interaction["confirmed"] is True
    assert interaction["latest_record"]["source_ip"] == "192.168.1.50"
    assert interaction["latest_record"]["protocol"] == "dns"
    assert interaction["context"]["agent_name"] == "ssti_tester"

@pytest.mark.asyncio
async def test_novel_ssrf_agent_oob_binding():
    agent = NovelSSRFRedirectAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("ssrf_redirect_chain", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any("oob_token" in f for f in findings)
    assert any(f["vector_id"] == "oob_multiproto_redirect" for f in findings)

@pytest.mark.asyncio
async def test_polyglot_ssti_agent_oob_binding():
    agent = PolyglotSSTIAgent()
    ctx = CapabilityExecutionContext(asset="example.com", knowledge_store=KnowledgeStore())
    res = await agent.execute("polyglot_ssti", ctx)
    assert res["is_vulnerable"] is True
    findings = res["findings"]
    assert any(f["vector_id"] == "blind_ssti_oob_dns" for f in findings)
    assert any("dns_host" in f for f in findings)
