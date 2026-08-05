import pytest
import asyncio
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.recon.target_manager import TargetManager
from penflow.recon.scope_manager import ScopeManager
from penflow.recon.asset_discovery import AssetDiscoveryEngine
from penflow.recon.dns_discovery import DNSDiscoveryEngine
from penflow.recon.certificate_discovery import CertificateDiscoveryEngine
from penflow.recon.repository_discovery import RepositoryDiscoveryEngine
from penflow.recon.javascript_discovery import JSDiscoveryEngine
from penflow.recon.endpoint_discovery import EndpointDiscoveryEngine
from penflow.recon.technology_fingerprint import TechnologyFingerprintEngine
from penflow.recon.change_detector import ChangeDetector
from penflow.recon.recon_scheduler import ReconScheduler
from penflow.recon.recon_pipeline import ReconPipeline

def test_target_and_scope_manager():
    tm = TargetManager()
    t = tm.add_target("Company", "company.com", priority=10)
    assert t.domain == "company.com"
    assert t.status == "ACTIVE"

    tm.pause_target(t.id)
    assert t.status == "PAUSED"

    sm = ScopeManager(in_scope=["*.company.com"], out_of_scope=["dev.company.com"])
    assert sm.is_in_scope("api.company.com") is True
    assert sm.is_in_scope("dev.company.com") is False
    assert sm.is_in_scope("other.com") is False

def test_dns_and_cert_discovery():
    dns = DNSDiscoveryEngine()
    dns.record_dns_entry("company.com", "A", "1.2.3.4")
    history = dns.get_dns_history("company.com")
    assert len(history) == 1
    assert history[0].value == "1.2.3.4"

    certs = CertificateDiscoveryEngine()
    certs.record_certificate("12345", "DigiCert", ["company.com", "sub.company.com"], 100.0, 2000000000.0)
    assert "sub.company.com" in certs.get_all_san_domains()

def test_js_and_endpoint_discovery():
    js_eng = JSDiscoveryEngine()
    js_meta = js_eng.record_js_file("https://company.com/app.js", "console.log('hi');", version="1.0.1", imports=["./utils.js"])
    assert js_meta.version == "1.0.1"
    assert "./utils.js" in js_meta.imports

    ep_eng = EndpointDiscoveryEngine()
    ep = ep_eng.record_endpoint("https://company.com/api/v1/user", endpoint_type="REST", method="GET", parameters=["id"])
    assert ep.endpoint_type == "REST"
    assert "id" in ep.parameters

def test_technology_and_change_detector():
    tech = TechnologyFingerprintEngine()
    prof = tech.update_profile("company.com", framework="Django", cloud="AWS")
    assert prof.framework == "Django"
    assert prof.cloud == "AWS"

    cd = ChangeDetector()
    evt1 = cd.inspect_and_detect("company.com", "ip", "1.1.1.1", "dns_changed")
    assert evt1 is not None

    evt2 = cd.inspect_and_detect("company.com", "ip", "1.1.1.1", "dns_changed")
    assert evt2 is None  # No change

    evt3 = cd.inspect_and_detect("company.com", "ip", "2.2.2.2", "dns_changed")
    assert evt3 is not None
    assert evt3.old_value == "1.1.1.1"
    assert evt3.new_value == "2.2.2.2"

@pytest.mark.asyncio
async def test_recon_pipeline_loop():
    ks = KnowledgeStore()
    pipeline = ReconPipeline(ks)
    pipeline.scope_manager.add_in_scope("*.target.com")

    # Initial observation -> Change detected -> Scheduled task
    task = await pipeline.process_observation("api.target.com", "js_file", {"url": "https://api.target.com/main.js"})
    assert task is not None
    assert task.target_asset == "api.target.com"
    assert task.recon_type == "deep_js_file_recon"

    # Subsequent identical observation -> No change -> No task
    task_dup = await pipeline.process_observation("api.target.com", "js_file", {"url": "https://api.target.com/main.js"})
    assert task_dup is None
