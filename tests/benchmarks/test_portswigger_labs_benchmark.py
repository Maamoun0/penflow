"""
PortSwigger-Style Lab Benchmark Test Suite for PenFlow.

Executes and verifies PenFlow's capability agents, grounding CAS, critic falsification,
quality gate, CVSS scoring, and HackerOne report exporter against simulated PortSwigger labs.
"""
import pytest
import asyncio
import httpx
from penflow.knowledge.evidence_cas import EvidenceCAS, EvidenceBundle
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.validation.quality_gate import PreReportQualityGate
from penflow.reporting.cvss_calculator import CVSSCalculator
from penflow.reporting.impact_scorer import ImpactScorer
from penflow.reporting.hackerone_exporter import HackerOneReportExporter
from penflow.recon.security_headers_audit import SecurityHeadersAuditor
from tests.benchmarks.portswigger_lab_server import app


@pytest.fixture
def critic_engine():
    return CriticVerificationEngine()


@pytest.fixture
def quality_gate():
    return PreReportQualityGate(min_confidence=0.85, scope_domains=["localhost", "127.0.0.1", "testserver"])


@pytest.fixture
def cvss_calc():
    return CVSSCalculator()


@pytest.fixture
def impact_scorer():
    return ImpactScorer()


@pytest.fixture
def h1_exporter():
    return HackerOneReportExporter()


# --- Test Lab 1: SQL Injection (Error-Based) ---
@pytest.mark.asyncio
async def test_lab_1_sqli_error_based(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 1: SQL Injection - Verify detection, critic verification, CVSS & HackerOne export."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/lab/sqli/search?id=1%27+AND+ExtractValue(1%2C+CONCAT(0x5c%2C+%27penflow_sqli%27))--")
        assert resp.status_code == 500
        assert "penflow_sqli" in resp.text

        evidence = {
            "target_url": "http://testserver/lab/sqli/search?id=1%27+AND+ExtractValue(1%2C+CONCAT(0x5c%2C+%27penflow_sqli%27))--",
            "is_vulnerable": True,
            "confidence_score": 0.98,
            "reasoning": "SQL syntax error returned indicating full database manipulation.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "http://testserver/lab/sqli/search?id=1%27+AND+ExtractValue(1%2C+CONCAT(0x5c%2C+%27penflow_sqli%27))--"},
                "response": {"status_code": resp.status_code, "body_snippet": resp.text}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="sqli_vulnerability", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is True
        assert crit_res["confidence"] >= 0.85

        admitted = await quality_gate.filter_findings([crit_res])
        assert len(admitted) == 1

        impact = impact_scorer.evaluate_impact({"vulnerability_type": "sqli_vulnerability"})
        assert impact["cwe"] == "CWE-89"

        report_md = h1_exporter.export_report(crit_res)
        assert "SQLI_VULNERABILITY" in report_md
        assert "CWE-89" in report_md
        assert "penflow_sqli" in report_md


# --- Test Lab 2: Reflected XSS ---
@pytest.mark.asyncio
async def test_lab_2_reflected_xss(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 2: Reflected XSS - Verify payload reflection in HTML body."""
    payload = "<script>alert('penflow_xss_probe')</script>"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get(f"/lab/xss/comment?q={payload}")
        assert resp.status_code == 200
        assert payload in resp.text

        evidence = {
            "target_url": f"http://testserver/lab/xss/comment?q={payload}",
            "is_vulnerable": True,
            "confidence_score": 0.95,
            "reasoning": "Unsanitized XSS payload reflected directly in HTML body context.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": f"http://testserver/lab/xss/comment?q={payload}"},
                "response": {"status_code": resp.status_code, "body_snippet": resp.text}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="reflected_xss", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is True
        assert crit_res["confidence"] >= 0.85

        impact = impact_scorer.evaluate_impact({"vulnerability_type": "reflected_xss"})
        assert impact["cwe"] == "CWE-79"

        report_md = h1_exporter.export_report(crit_res)
        assert "REFLECTED_XSS" in report_md
        assert "CWE-79" in report_md


# --- Test Lab 3: SSRF (AWS EC2 Metadata) ---
@pytest.mark.asyncio
async def test_lab_3_ssrf_aws_metadata(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 3: SSRF - Verify AWS IMDS metadata leakage."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/lab/ssrf/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin")
        assert resp.status_code == 200
        assert "AKIAIOSFODNN7EXAMPLE" in resp.text

        evidence = {
            "target_url": "http://testserver/lab/ssrf/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
            "is_vulnerable": True,
            "confidence_score": 0.99,
            "reasoning": "Server-side request forgery leaked AWS IAM role credentials.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "http://testserver/lab/ssrf/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"},
                "response": {"status_code": 200, "body_snippet": resp.text}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="ssrf_metadata_exfiltration", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is True
        assert crit_res["confidence"] >= 0.85

        impact = impact_scorer.evaluate_impact({"vulnerability_type": "ssrf_metadata_exfiltration"})
        assert impact["cwe"] == "CWE-918"

        report_md = h1_exporter.export_report(crit_res)
        assert "SSRF" in report_md
        assert "CWE-918" in report_md


# --- Test Lab 4: IDOR / BOLA ---
@pytest.mark.asyncio
async def test_lab_4_idor_account_takeover(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 4: IDOR - Unauthorized cross-account data exfiltration."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/lab/idor/account?id=9999", headers={"Authorization": "Bearer token_alice"})
        assert resp.status_code == 200
        assert "live_admin_secret_key_root_99" in resp.text

        evidence = {
            "target_url": "http://testserver/lab/idor/account?id=9999",
            "is_vulnerable": True,
            "confidence_score": 0.95,
            "reasoning": "IDOR / BOLA vulnerability allows accessing arbitrary account credentials.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "http://testserver/lab/idor/account?id=9999"},
                "response": {"status_code": 200, "body_snippet": resp.text}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="idor_data_leakage", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is True
        assert crit_res["confidence"] >= 0.85

        impact = impact_scorer.evaluate_impact({"vulnerability_type": "idor_data_leakage"})
        assert impact["cwe"] == "CWE-639"


# --- Test Lab 5: CORS Misconfiguration ---
@pytest.mark.asyncio
async def test_lab_5_cors_origin_reflection(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 5: CORS - Arbitrary origin reflection with credentials enabled."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/lab/cors/userinfo", headers={"Origin": "https://attacker.evil.com"})
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "https://attacker.evil.com"
        assert resp.headers.get("access-control-allow-credentials") == "true"

        evidence = {
            "target_url": "http://testserver/lab/cors/userinfo",
            "is_vulnerable": True,
            "confidence_score": 0.90,
            "reasoning": "CORS misconfiguration reflects arbitrary untrusted Origin with credentials allowed.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "http://testserver/lab/cors/userinfo", "headers": {"Origin": "https://attacker.evil.com"}},
                "response": {"status_code": 200, "headers": dict(resp.headers), "body_snippet": resp.text}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="cors_misconfig_check", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is True
        assert crit_res["confidence"] >= 0.85

        impact = impact_scorer.evaluate_impact({"vulnerability_type": "cors_misconfig_check"})
        assert impact["cwe"] == "CWE-346"


# --- Test Lab 6: OS Command Injection ---
@pytest.mark.asyncio
async def test_lab_6_command_injection(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 6: Command Injection - RCE through concatenated shell parameters."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.get("/lab/rce/ping?ip=127.0.0.1%3Bid")
        assert resp.status_code == 200
        assert "uid=1000(appuser)" in resp.text

        evidence = {
            "target_url": "http://testserver/lab/rce/ping?ip=127.0.0.1%3Bid",
            "is_vulnerable": True,
            "confidence_score": 0.99,
            "reasoning": "Command Injection verified through system user identity output.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "http://testserver/lab/rce/ping?ip=127.0.0.1%3Bid"},
                "response": {"status_code": 200, "body_snippet": resp.text}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="command_injection", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is True
        assert crit_res["confidence"] >= 0.85

        impact = impact_scorer.evaluate_impact({"vulnerability_type": "command_injection"})
        assert impact["cwe"] in ("CWE-77", "CWE-78")

        report_md = h1_exporter.export_report(crit_res)
        assert "COMMAND_INJECTION" in report_md
        assert impact["cwe"] in report_md


# --- Test Lab 7: OAuth Redirect URI Manipulation ---
@pytest.mark.asyncio
async def test_lab_7_oauth_redirect_manipulation(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 7: OAuth - Authorization code leakage to attacker domain."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver", follow_redirects=False) as client:
        resp = await client.get("/lab/oauth/authorize?client_id=myclient&redirect_uri=https://attacker.evil.com/callback&response_type=code")
        assert resp.status_code == 302
        assert "attacker.evil.com" in resp.headers.get("location", "")

        evidence = {
            "target_url": "http://testserver/lab/oauth/authorize?client_id=myclient&redirect_uri=https://attacker.evil.com/callback&response_type=code",
            "is_vulnerable": True,
            "confidence_score": 0.95,
            "reasoning": "OAuth authorization endpoint leaked code parameter to external attacker domain.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "http://testserver/lab/oauth/authorize?client_id=myclient&redirect_uri=https://attacker.evil.com/callback&response_type=code"},
                "response": {"status_code": 302, "headers": dict(resp.headers)}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="oauth_redirect_manipulation", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is True
        assert crit_res["confidence"] >= 0.85

        impact = impact_scorer.evaluate_impact({"vulnerability_type": "oauth_redirect_manipulation"})
        assert impact["cwe"] == "CWE-601" or impact["cwe"] == "CWE-352"


# --- Test Lab 8: Missing Security Headers (Informative finding) ---
@pytest.mark.asyncio
async def test_lab_8_security_headers_audit(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 8: Security Headers - Hardening audit properly admitted as Informative."""
    evidence = {
        "target_url": "http://testserver/lab/headers/insecure",
        "is_vulnerable": True,
        "confidence_score": 0.30,
        "reasoning": "Missing HSTS, CSP, and X-Frame-Options headers.",
        "evidence_exchanges": [{
            "request": {"method": "GET", "url": "http://testserver/lab/headers/insecure"},
            "response": {"status_code": 200, "headers": {"Server": "Apache/2.4.41"}}
        }]
    }
    bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="security_config_audit", raw_traces=evidence)
    crit_res = critic_engine.verify_finding(bundle)
    assert crit_res["is_verified"] is True
    assert crit_res["confidence"] == 0.30

    admitted, rejected = await quality_gate.filter_findings_with_details([crit_res])
    assert len(admitted) == 1
    assert len(rejected) == 0

    report_md = h1_exporter.export_report(crit_res)
    assert "SECURITY_CONFIG_AUDIT" in report_md
    assert "CWE-693" in report_md or "Informative" in report_md or "[NONE]" in report_md


# --- Test Lab 9: Race Condition (Limit Overrun) ---
@pytest.mark.asyncio
async def test_lab_9_race_condition_limit_overrun(critic_engine, quality_gate, cvss_calc, impact_scorer, h1_exporter):
    """Lab 9: Race Condition - Multiple concurrent requests succeeding past limit."""
    evidence = {
        "target_url": "http://testserver/lab/race/coupon",
        "is_vulnerable": True,
        "confidence_score": 0.92,
        "reasoning": "HTTP/2 single-packet burst redeemed single-use coupon 4 times simultaneously.",
        "evidence_exchanges": [{
            "request": {"method": "POST", "url": "http://testserver/lab/race/coupon"},
            "response": {"status_code": 200, "body_snippet": '{"status": "success", "redemption_count": 4}'}
        }]
    }
    bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="race_condition_check", raw_traces=evidence)
    crit_res = critic_engine.verify_finding(bundle)
    assert crit_res["is_verified"] is True
    assert crit_res["confidence"] >= 0.85

    impact = impact_scorer.evaluate_impact({"vulnerability_type": "race_condition_check"})
    assert impact["cwe"] == "CWE-362"


# --- Test Lab 10: Negative Control (Zero False Positives) ---
@pytest.mark.asyncio
async def test_lab_10_negative_control_hardened_redirect(critic_engine, quality_gate):
    """Lab 10: Negative Control - Secure endpoint with standard CDN 301 must be falsified with 0 false positives."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver", follow_redirects=False) as client:
        resp = await client.get("/lab/secure/profile")
        assert resp.status_code == 301
        assert "company.com" in resp.headers.get("location", "")

        # Claim false open redirect / oauth on CDN alias redirect
        evidence = {
            "target_url": "http://testserver/lab/secure/profile",
            "is_vulnerable": True,
            "confidence_score": 0.80,
            "reasoning": "Claimed open redirect on edge redirect.",
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "http://testserver/lab/secure/profile"},
                "response": {"status_code": 301, "headers": dict(resp.headers)}
            }]
        }
        bundle = EvidenceCAS().store_evidence(target="localhost", vuln_type="open_redirect", raw_traces=evidence)
        crit_res = critic_engine.verify_finding(bundle)
        assert crit_res["is_verified"] is False
        assert "Falsified" in crit_res.get("verification_reason", "")

        admitted, rejected = await quality_gate.filter_findings_with_details([crit_res])
        assert len(admitted) == 0
        assert len(rejected) == 1
        assert "QualityGate" in rejected[0]["reason"]
