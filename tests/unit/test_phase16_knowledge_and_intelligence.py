import pytest
import asyncio
from penflow.knowledge.vulnerability_kb import VulnerabilityKnowledgeBase, VulnerabilityKB
from penflow.reporting.cvss_calculator import CVSSCalculator, CVSSv31Calculator
from penflow.reporting.report_generator import MarkdownReportGenerator
from penflow.testing.payload_engine import PayloadTemplateEngine
from penflow.testing.response_analyzer import SemanticResponseAnalyzer
from penflow.recon.endpoint_classifier import EndpointClassifier, ClassifiedEndpoint
from penflow.intelligence.writeup_miner import WriteupMiner
from penflow.intelligence.writeup_loader import WriteupIngestionEngine
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.knowledge.evidence_cas import EvidenceBundle
from penflow.agents import (
    NoSQLSQLiCapabilityAgent,
    SSTIRCECapabilityAgent,
    InfoDisclosureCapabilityAgent,
    RateLimitCapabilityAgent,
    OpenRedirectCapabilityAgent,
)
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore
from penflow.planning.execution_plan import ExecutionPlan


@pytest.mark.asyncio
async def test_vulnerability_kb_all_18_classes():
    kb = VulnerabilityKnowledgeBase()
    all_vulns = kb.list_all_vulnerabilities()
    assert len(all_vulns) >= 18

    # Verify specific new vulnerability classes
    for key in ["nosql_injection", "sql_injection", "ssti_rce", "command_injection", "rate_limit_bypass", "open_redirect", "info_disclosure"]:
        meta = kb.get_metadata(key)
        assert meta is not None
        assert meta.cwe_id.startswith("CWE-")
        assert len(meta.remediation_guidance) > 0


@pytest.mark.asyncio
async def test_cvss_calculator_and_report_generation():
    calc = CVSSCalculator()
    rep_gen = MarkdownReportGenerator()

    # Test CVSS for NoSQLi and SSTI
    nosql_metrics = calc.get_metrics_for("nosql_injection")
    nosql_cvss = calc.calculate_score(nosql_metrics)
    assert nosql_cvss["base_score"] >= 8.0
    assert nosql_cvss["severity"] in ("High", "Critical")

    ssti_metrics = calc.get_metrics_for("ssti_rce")
    ssti_cvss = calc.calculate_score(ssti_metrics)
    assert ssti_cvss["base_score"] >= 9.0
    assert ssti_cvss["severity"] == "Critical"

    # Test report generation logic
    ks = KnowledgeStore()
    ks.assets.register_asset("api.target.com", "subdomain")
    plan = ExecutionPlan(ordered_hypotheses=[])
    verified_findings = [{
        "vulnerability_type": "nosql_injection",
        "target": "api.target.com",
        "hash_id": "bundle_12345",
        "confidence_score": 0.94,
        "evidence": {
            "target_url": "https://api.target.com/api/v1/auth/login",
            "reasoning": "MongoDB operator injection bypassed auth"
        }
    }]

    report = rep_gen.generate_report("api.target.com", ks, plan, verified_findings)
    assert "NoSQL" in report
    assert "api.target.com" in report
    assert "Verified Findings" in report


@pytest.mark.asyncio
async def test_payload_template_engine():
    engine = PayloadTemplateEngine()
    
    nosql_p = engine.generate_nosql_payloads("https://target.com/api/search", "query")
    assert len(nosql_p) >= 4
    assert any("$ne" in str(p.json_data) or "[$ne]" in p.url for p in nosql_p)

    sqli_p = engine.generate_sqli_payloads("https://target.com/api/search", "q")
    assert len(sqli_p) >= 4
    assert any("SQLi" in p.name for p in sqli_p)

    ssti_p = engine.generate_ssti_payloads("https://target.com/render", "template")
    assert len(ssti_p) >= 4
    assert any("SSTI" in p.name for p in ssti_p)

    rce_p = engine.generate_rce_payloads("https://target.com/ping", "ip")
    assert len(rce_p) >= 4
    assert any("RCE" in p.name for p in rce_p)

    rl_headers = engine.generate_rate_limit_bypass_headers("https://target.com/login", ip_index=5)
    assert len(rl_headers) >= 4
    assert any("X-Forwarded-For" in p.headers for p in rl_headers)

    redir_p = engine.generate_open_redirect_payloads("https://target.com/redirect", "next")
    assert len(redir_p) >= 4
    assert any("evil.com" in p.url for p in redir_p)

    info_p = engine.generate_info_disclosure_probes("https://target.com")
    assert len(info_p) >= 6
    assert any("/actuator/env" in p.url for p in info_p)


@pytest.mark.asyncio
async def test_semantic_response_analyzer():
    analyzer = SemanticResponseAnalyzer()

    # Test NoSQL error detection
    res1 = analyzer.analyze_response(500, {}, "MongoError: Can't canonicalize query: BadValue unknown operator: $invalid")
    assert any(f["type"] == "nosql_error" for f in res1["findings"])

    # Test Actuator env leak
    res2 = analyzer.analyze_response(200, {}, '{"propertySources":[{"name":"systemProperties","source":{"spring.datasource.password":"secretpassword123"}}]}')
    assert any(f["type"] == "actuator_env_leak" for f in res2["findings"])

    # Test RCE execution output
    res3 = analyzer.analyze_response(200, {}, "uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)")
    assert any(f["type"] == "rce_output" for f in res3["findings"])


@pytest.mark.asyncio
async def test_endpoint_classifier_new_capabilities():
    classifier = EndpointClassifier()

    # Endpoint with search parameter -> SQLi & NoSQLi
    ep_search = ClassifiedEndpoint(url="https://api.target.com/api/v1/users?search=john", endpoint_type="parameterized", method="GET")
    caps_search = classifier._get_capabilities_for_endpoint(ep_search, [])
    assert "nosql_injection" in caps_search
    assert "sql_injection" in caps_search

    # Endpoint with template/preview -> SSTI
    ep_ssti = ClassifiedEndpoint(url="https://api.target.com/api/v1/preview/render?template=hello", endpoint_type="rest_api", method="GET")
    caps_ssti = classifier._get_capabilities_for_endpoint(ep_ssti, [])
    assert "ssti_analysis" in caps_ssti

    # Endpoint with redirect -> Open Redirect
    ep_redir = ClassifiedEndpoint(url="https://api.target.com/oauth/callback?redirect_uri=https://app.com", endpoint_type="auth", method="GET")
    caps_redir = classifier._get_capabilities_for_endpoint(ep_redir, [])
    assert "open_redirect" in caps_redir

    # Endpoint with actuator / debug -> Info Disclosure
    ep_act = ClassifiedEndpoint(url="https://api.target.com/actuator/env", endpoint_type="rest_api", method="GET")
    caps_act = classifier._get_capabilities_for_endpoint(ep_act, [])
    assert "info_disclosure" in caps_act


@pytest.mark.asyncio
async def test_specialist_agents_execution():
    ks = KnowledgeStore()
    context = CapabilityExecutionContext(
        asset="api.mock-target.com",
        knowledge_store=ks
    )

    # 1. NoSQL & SQLi Agent
    nosql_agent = NoSQLSQLiCapabilityAgent()
    assert len(nosql_agent.get_capabilities()) == 2
    res_nosql = await nosql_agent.execute("nosql_injection", context)
    assert res_nosql["status"] == "COMPLETED"
    assert res_nosql["agent"] == "NoSQLSQLiCapabilityAgent"

    # 2. SSTI & RCE Agent
    ssti_agent = SSTIRCECapabilityAgent()
    assert len(ssti_agent.get_capabilities()) == 2
    res_ssti = await ssti_agent.execute("ssti_analysis", context)
    assert res_ssti["status"] == "COMPLETED"

    # 3. Info Disclosure Agent
    info_agent = InfoDisclosureCapabilityAgent()
    assert len(info_agent.get_capabilities()) == 1
    res_info = await info_agent.execute("info_disclosure", context)
    assert res_info["status"] == "COMPLETED"

    # 4. Rate Limit Agent
    rl_agent = RateLimitCapabilityAgent()
    assert len(rl_agent.get_capabilities()) == 1
    res_rl = await rl_agent.execute("rate_limit_bypass", context)
    assert res_rl["status"] == "COMPLETED"

    # 5. Open Redirect Agent
    redir_agent = OpenRedirectCapabilityAgent()
    assert len(redir_agent.get_capabilities()) == 1
    res_redir = await redir_agent.execute("open_redirect", context)
    assert res_redir["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_critic_engine_falsification_rules():
    critic = CriticVerificationEngine()

    # Test 1: Static Asset Falsification
    bundle_static = EvidenceBundle(
        hash_id="b_static",
        vulnerability_type="nosql_injection",
        target="target.com",
        raw_traces={
            "target_url": "https://target.com/static/app.js",
            "is_vulnerable": True,
            "evidence_exchanges": [{"request": {"method": "GET", "url": "https://target.com/static/app.js"}, "response": {"status_code": 200}}]
        }
    )
    res_static = critic.verify_finding(bundle_static)
    assert not res_static["is_verified"]
    assert "static asset" in res_static["verification_reason"]

    # Test 2: SSTI Literal Reflection Falsification
    bundle_ssti_fake = EvidenceBundle(
        hash_id="b_ssti_fake",
        vulnerability_type="ssti_rce",
        target="target.com",
        raw_traces={
            "target_url": "https://target.com/preview",
            "is_vulnerable": True,
            "confidence_score": 0.90,
            "evidence_exchanges": [{
                "response": {"status_code": 200, "body_text": "Hello {{7*7}}, welcome!"}
            }]
        }
    )
    res_ssti_fake = critic.verify_finding(bundle_ssti_fake)
    assert not res_ssti_fake["is_verified"]
    assert "reflected as literal text" in res_ssti_fake["verification_reason"]

    # Test 3: WAF Block Falsification
    bundle_waf = EvidenceBundle(
        hash_id="b_waf",
        vulnerability_type="sql_injection",
        target="target.com",
        raw_traces={
            "target_url": "https://target.com/search",
            "is_vulnerable": True,
            "confidence_score": 0.90,
            "evidence_exchanges": [{
                "response": {"status_code": 403, "body_text": "Cloudflare Ray ID: 12345, Request Blocked by WAF"}
            }]
        }
    )
    res_waf = critic.verify_finding(bundle_waf)
    assert not res_waf["is_verified"]
    assert "WAF" in res_waf["verification_reason"]

    # Test 4: Genuine Verified Finding
    bundle_verified = EvidenceBundle(
        hash_id="b_true",
        vulnerability_type="nosql_injection",
        target="target.com",
        raw_traces={
            "target_url": "https://target.com/api/v1/auth/login",
            "is_vulnerable": True,
            "confidence_score": 0.94,
            "reasoning": "MongoDB operator injection bypassed auth and returned user records",
            "evidence_exchanges": [{
                "response": {"status_code": 200, "body_text": '{"user_id": 1, "username": "admin", "token": "jwt123"}'}
            }]
        }
    )
    res_verified = critic.verify_finding(bundle_verified)
    assert res_verified["is_verified"]
    assert res_verified["confidence_score"] >= 0.90
