"""
PenFlow Golden Regression Suite.
Rigorous adversarial falsification regression suite containing positive and negative
test cases across all primary vulnerability domains (OAuth, SQLi, SSTI, BOLA, SSRF, Headers, CONNECT).
"""
import pytest
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.knowledge.evidence_cas import EvidenceCAS

@pytest.fixture
def critic():
    return CriticVerificationEngine()

@pytest.fixture
def cas():
    return EvidenceCAS()

# ─────────────────────────────────────────────────────────────────────────────
# 1. OAUTH
# ─────────────────────────────────────────────────────────────────────────────
def test_oauth_cdn_internal_redirect_negative(critic, cas):
    """Negative: 301 CDN Redirect to legitimate internal domain (nu.com.mx) must be FALSIFIED."""
    raw_oauth_neg = {
        "is_vulnerable": True,
        "confidence_score": 0.95,
        "reasoning": "OAuth redirect manipulation: Server redirected to target internal domain.",
        "target_url": "https://nu.com.mx/login",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://nu.com.mx/oauth/callback?redirect_uri=https://nu.com.mx"},
                "response": {
                    "status_code": 301,
                    "headers": {"Location": "https://nu.com.mx/dashboard", "Server": "CloudFront"},
                    "body_snippet": ""
                }
            }
        ]
    }
    b = cas.store_evidence("nu.com.mx", "oauth_misconfiguration", raw_oauth_neg)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"OAuth Negative Failed: {res}"

def test_oauth_token_leak_external_oob_positive(critic, cas):
    """Positive: OAuth redirecting to external attacker collaborator domain must be VERIFIED."""
    raw_oauth_pos = {
        "is_vulnerable": True,
        "confidence_score": 0.95,
        "reasoning": "CRITICAL OAuth State Verification Flaw: Token leaked to external collaborator.",
        "target_url": "https://nu.com.mx/oauth/callback",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://nu.com.mx/oauth/callback?redirect_uri=https://attacker.interactsh.com"},
                "response": {
                    "status_code": 302,
                    "headers": {"Location": "https://attacker.interactsh.com/token?access_token=secret123"},
                    "body_snippet": "Redirecting..."
                }
            }
        ]
    }
    b = cas.store_evidence("nu.com.mx", "oauth_misconfiguration", raw_oauth_pos)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"OAuth Positive Failed: {res}"

# ─────────────────────────────────────────────────────────────────────────────
# 2. SQL INJECTION (TIMING & BLIND)
# ─────────────────────────────────────────────────────────────────────────────
def test_sqli_timing_delay_404_negative(critic, cas):
    """Negative: Delay on HTTP 404 Not Found (Report 32 pattern) must be FALSIFIED."""
    raw_sqli_404 = {
        "is_vulnerable": True,
        "confidence_score": 0.93,
        "reasoning": "CRITICAL Time-based Blind SQLi: Payload '1' AND SLEEP(3)--' induced 3.03s delay (threshold: 3.0s).",
        "target_url": "https://lab.net/product?productId=1",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/product?productId=1"},
                "response": {"status_code": 404, "body_snippet": '"Not Found"'}
            }
        ]
    }
    b = cas.store_evidence("lab.net", "sql_injection", raw_sqli_404)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"SQLi 404 Negative Failed: {res}"

def test_sqli_timing_delay_405_negative(critic, cas):
    """Negative: Delay on HTTP 405 Method Not Allowed (Report 33 pattern) must be FALSIFIED."""
    raw_sqli_405 = {
        "is_vulnerable": True,
        "confidence_score": 0.93,
        "reasoning": "CRITICAL Time-based Blind SQLi: Payload '1' AND SLEEP(3)--' induced 3.22s delay (threshold: 3.0s).",
        "target_url": "https://lab.net/product/stock?storeId=1",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/product/stock?storeId=1"},
                "response": {"status_code": 405, "body_snippet": '"Method Not Allowed"'}
            }
        ]
    }
    b = cas.store_evidence("lab.net", "sql_injection", raw_sqli_405)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"SQLi 405 Negative Failed: {res}"

def test_sqli_soft_error_200_negative(critic, cas):
    """Negative: Delay on HTTP 200 containing soft error body must be FALSIFIED."""
    raw_sqli_soft = {
        "is_vulnerable": True,
        "confidence_score": 0.93,
        "reasoning": "CRITICAL Time-based Blind SQLi: Payload induced 3.10s delay.",
        "target_url": "https://lab.net/product?productId=1",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/product?productId=1"},
                "response": {"status_code": 200, "body_snippet": '{"error": "Invalid product ID"}'}
            }
        ]
    }
    b = cas.store_evidence("lab.net", "sql_injection", raw_sqli_soft)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"SQLi Soft Error Negative Failed: {res}"

def test_sqli_error_based_extraction_positive(critic, cas):
    """Positive: Genuine SQL database syntax error on HTTP 200 must be VERIFIED."""
    raw_sqli_pos = {
        "is_vulnerable": True,
        "confidence_score": 0.98,
        "reasoning": "CRITICAL Error-based SQLi: PostgreSQL syntax error revealed.",
        "target_url": "https://lab.net/filter?category=Gifts",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/filter?category=Gifts%27"},
                "response": {
                    "status_code": 200,
                    "body_snippet": "Internal Server Error: org.postgresql.util.PSQLException: unterminated quoted string at or near '''"
                }
            }
        ]
    }
    b = cas.store_evidence("lab.net", "sql_injection", raw_sqli_pos)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"SQLi Positive Failed: {res}"

# ─────────────────────────────────────────────────────────────────────────────
# 3. SSTI
# ─────────────────────────────────────────────────────────────────────────────
def test_ssti_fake_match_shop_price_negative(critic, cas):
    """Negative: Price match $49.00 on store page without evaluation must be FALSIFIED."""
    raw_ssti_neg = {
        "is_vulnerable": True,
        "confidence_score": 0.96,
        "reasoning": "CRITICAL SSTI Confirmed [Universal Polyglot Match]: Evaluated expression in response.",
        "target_url": "https://lab.net/?q=${'z'*1000}",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/?q=${'z'*1000}"},
                "response": {"status_code": 200, "body_text": '<html><body><h1>Our Products</h1><p>Price: $49.00</p></body></html>'}
            }
        ]
    }
    b = cas.store_evidence("lab.net", "ssti_rce", raw_ssti_neg)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"SSTI Negative Failed: {res}"

def test_ssti_mathematical_evaluation_proof_positive(critic, cas):
    """Positive: Genuine SSTI math evaluation 48239 * 71 = 3424969 must be VERIFIED."""
    raw_ssti_pos = {
        "is_vulnerable": True,
        "confidence_score": 0.98,
        "reasoning": "CRITICAL SSTI Confirmed: Expression {{48239*71}} evaluated to 3424969.",
        "target_url": "https://lab.net/?message={{48239*71}}",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/?message=control"},
                "response": {"status_code": 200, "body_text": "<html><h1>Hello control</h1></html>"}
            },
            {
                "request": {"method": "GET", "url": "https://lab.net/?message={{48239*71}}"},
                "response": {"status_code": 200, "body_text": "<html><h1>Hello 3424969</h1></html>"}
            }
        ]
    }
    b = cas.store_evidence("lab.net", "ssti_rce", raw_ssti_pos)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"SSTI Positive Failed: {res}"

# ─────────────────────────────────────────────────────────────────────────────
# 4. BOLA / IDOR
# ─────────────────────────────────────────────────────────────────────────────
def test_bola_identical_public_login_page_negative(critic, cas):
    """Negative: Identical public login HTML returned for different IDs must be FALSIFIED."""
    raw_bola_neg = {
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "reasoning": "BOLA Broken Object Level Auth: Accessed object without restriction.",
        "target_url": "https://lab.net/my-account?id=carlos",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/my-account?id=wiener"},
                "response": {"status_code": 200, "body_text": "<!DOCTYPE html><html><body><h1>Please Log In</h1></body></html>"}
            },
            {
                "request": {"method": "GET", "url": "https://lab.net/my-account?id=carlos"},
                "response": {"status_code": 200, "body_text": "<!DOCTYPE html><html><body><h1>Please Log In</h1></body></html>"}
            }
        ]
    }
    b = cas.store_evidence("lab.net", "bola", raw_bola_neg)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"BOLA Negative Failed: {res}"

def test_idor_private_data_leak_positive(critic, cas):
    """Positive: True IDOR leaking private profile attributes and API key must be VERIFIED."""
    raw_bola_pos = {
        "is_vulnerable": True,
        "confidence_score": 0.95,
        "reasoning": "CRITICAL IDOR: Accessed Carlos private profile and API key.",
        "target_url": "https://lab.net/api/user/carlos",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net/api/user/carlos"},
                "response": {
                    "status_code": 200,
                    "body_text": '{"username": "carlos", "email": "carlos@victim.com", "apikey": "secret_live_99812", "balance": 15000}'
                }
            }
        ]
    }
    b = cas.store_evidence("lab.net", "idor", raw_bola_pos)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"BOLA Positive Failed: {res}"

# ─────────────────────────────────────────────────────────────────────────────
# 5. SSRF
# ─────────────────────────────────────────────────────────────────────────────
def test_ssrf_relative_same_host_redirect_negative(critic, cas):
    """Negative: Relative redirect to same target host must be FALSIFIED."""
    raw_ssrf_neg = {
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "reasoning": "SSRF vulnerability: Backend redirected to relative static resource.",
        "target_url": "https://lab.net/product/stock",
        "evidence_exchanges": [
            {
                "request": {"method": "POST", "url": "https://lab.net/product/stock", "body": "stockApi=/product"},
                "response": {
                    "status_code": 302,
                    "headers": {"Location": "/product"},
                    "body_snippet": "Found"
                }
            }
        ]
    }
    b = cas.store_evidence("lab.net", "ssrf", raw_ssrf_neg)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"SSRF Negative Failed: {res}"

def test_ssrf_aws_cloud_metadata_exfiltration_positive(critic, cas):
    """Positive: True SSRF leaking AWS IAM metadata credentials must be VERIFIED."""
    raw_ssrf_pos = {
        "is_vulnerable": True,
        "confidence_score": 0.99,
        "reasoning": "CRITICAL Cloud Metadata Exfiltration: AWS IAM role credentials retrieved.",
        "target_url": "https://lab.net/product/stock",
        "evidence_exchanges": [
            {
                "request": {"method": "POST", "url": "https://lab.net/product/stock", "body": "stockApi=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"},
                "response": {
                    "status_code": 200,
                    "body_text": '{"Code": "Success", "AccessKeyId": "ASIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
                }
            }
        ]
    }
    b = cas.store_evidence("lab.net", "ssrf", raw_ssrf_pos)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"SSRF Positive Failed: {res}"

# ─────────────────────────────────────────────────────────────────────────────
# 6. MISSING SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────────────────
def test_missing_security_headers_capped_informative_positive(critic, cas):
    """Positive: Missing security headers capped at Informative severity (<= 0.30) must be VERIFIED."""
    raw_headers = {
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "reasoning": "Target missing Content-Security-Policy and Strict-Transport-Security headers.",
        "target_url": "https://lab.net",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://lab.net"},
                "response": {"status_code": 200, "headers": {"Server": "Apache"}, "body_snippet": "<html></html>"}
            }
        ]
    }
    b = cas.store_evidence("lab.net", "missing_headers", raw_headers)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"Headers Positive Failed: {res}"
    assert res["confidence"] <= 0.30, f"Headers should be capped at <= 0.30, got {res['confidence']}"

# ─────────────────────────────────────────────────────────────────────────────
# 7. HTTP/2 CONNECT TUNNEL
# ─────────────────────────────────────────────────────────────────────────────
def test_http2_connect_generic_html_negative(critic, cas):
    """Negative: Standard 200 HTML web page returned on CONNECT must be FALSIFIED."""
    raw_h2_neg = {
        "is_vulnerable": True,
        "confidence_score": 0.95,
        "reasoning": "HTTP/2 CONNECT method established an unauthenticated tunnel to internal endpoint 'localhost:8080'.",
        "target_url": "https://lab.net/",
        "evidence_exchanges": [
            {
                "request": {"method": "CONNECT", "url": "https://lab.net/", "headers": {":authority": "localhost:8080"}},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html; charset=utf-8"},
                    "body_snippet": "<!DOCTYPE html><html><body><h1>Online Shop</h1></body></html>"
                }
            }
        ]
    }
    b = cas.store_evidence("lab.net", "http2_connect_tunnel", raw_h2_neg)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"HTTP/2 CONNECT Negative Failed: {res}"

def test_http2_connect_internal_service_stream_positive(critic, cas):
    """Positive: Genuine internal Redis / IMDS banner on CONNECT tunnel must be VERIFIED."""
    raw_h2_pos = {
        "is_vulnerable": True,
        "confidence_score": 0.95,
        "reasoning": "HTTP/2 CONNECT method established an unauthenticated tunnel leaking internal Redis banner.",
        "target_url": "https://lab.net/",
        "evidence_exchanges": [
            {
                "request": {"method": "CONNECT", "url": "https://lab.net/", "headers": {":authority": "127.0.0.1:6379"}},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "application/octet-stream"},
                    "body_snippet": "+PONG\r\nredis_version:7.0.1"
                }
            }
        ]
    }
    b = cas.store_evidence("lab.net", "http2_connect_tunnel", raw_h2_pos)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"HTTP/2 CONNECT Positive Failed: {res}"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Security Headers — Unified finding deduplication tests
# ─────────────────────────────────────────────────────────────────────────────
def test_unified_headers_missing_hsts_positive(critic, cas):
    """Positive: A single consolidated finding when HSTS is missing must pass critic."""
    raw = {
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "reasoning": "Security header & cookie audit identified 2 configuration issue(s):\n  • [MEDIUM] Missing Strict-Transport-Security (HSTS)\n  • [LOW] Technology stack disclosure via 'server: nginx/1.18'",
        "target_url": "https://target.example.com/",
        "vulnerability_type": "security_headers_unified",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://target.example.com/"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html", "server": "nginx/1.18"},
                    "body_snippet": "<html><body>Hello</body></html>"
                }
            }
        ]
    }
    b = cas.store_evidence("target.example.com", "security_headers_unified", raw)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"Unified Headers Positive Failed: {res}"


def test_unified_headers_no_duplicate_findings(critic, cas):
    """Negative: A headers finding with identical request/response submitted twice must deduplicate."""
    from penflow.knowledge.evidence_cas import EvidenceCAS
    cas2 = EvidenceCAS()
    exchange = {
        "request": {"method": "GET", "url": "https://target.example.com/"},
        "response": {"status_code": 200, "headers": {"content-type": "text/html"}, "body_snippet": ""}
    }
    raw = {
        "is_vulnerable": True,
        "confidence_score": 0.90,
        "reasoning": "Missing HSTS on target.",
        "target_url": "https://target.example.com/",
        "evidence_exchanges": [exchange]
    }
    b1 = cas2.store_evidence("target.example.com", "security_headers_unified", raw)
    b2 = cas2.store_evidence("target.example.com", "security_headers_unified", raw)
    # Same asset + same vuln type should produce the same hash — content-addressed dedup
    assert b1.hash_id == b2.hash_id, "EvidenceCAS did NOT deduplicate identical findings"


# ─────────────────────────────────────────────────────────────────────────────
# 8. SSRF — IP Encoding Bypass payloads (structural tests)
# ─────────────────────────────────────────────────────────────────────────────
def test_ssrf_ip_encoding_payloads_exist():
    """Structural: SSRF payload list must include decimal, octal, hex, IPv6, DNS-rebind entries."""
    from penflow.agents.ssrf.ssrf_agent import SSRF_PAYLOADS
    payload_names = {p["name"] for p in SSRF_PAYLOADS}
    required = {
        "ip_decimal_loopback",
        "ip_octal_loopback",
        "ip_hex_loopback",
        "ipv6_loopback",
        "ipv6_mapped_ipv4",
        "double_encoded_localhost",
        "case_mixed_localhost",
        "aws_imdsv2_token",
        "dns_rebind_localtest_me",
        "dns_rebind_nip_io",
    }
    missing = required - payload_names
    assert not missing, f"SSRF missing expected bypass payloads: {missing}"


def test_ssrf_imdsv2_token_is_put():
    """Structural: aws_imdsv2_token payload must use PUT method with correct header."""
    from penflow.agents.ssrf.ssrf_agent import SSRF_PAYLOADS
    token_payload = next((p for p in SSRF_PAYLOADS if p["name"] == "aws_imdsv2_token"), None)
    assert token_payload is not None, "aws_imdsv2_token payload not found"
    assert token_payload.get("method", "").upper() == "PUT", "aws_imdsv2_token must use PUT"
    assert "X-aws-ec2-metadata-token-ttl-seconds" in token_payload.get("extra_headers", {}), \
        "aws_imdsv2_token must include X-aws-ec2-metadata-token-ttl-seconds in extra_headers"


def test_ssrf_gcp_payload_has_metadata_flavor_header():
    """Structural: GCP metadata payloads must include Metadata-Flavor: Google header."""
    from penflow.agents.ssrf.ssrf_agent import SSRF_PAYLOADS
    gcp_payloads = [p for p in SSRF_PAYLOADS if "gcp" in p["name"]]
    assert gcp_payloads, "No GCP payloads found"
    for p in gcp_payloads:
        assert p.get("extra_headers", {}).get("Metadata-Flavor") == "Google", \
            f"GCP payload '{p['name']}' missing Metadata-Flavor: Google header"


# ─────────────────────────────────────────────────────────────────────────────
# 9. CORS — Chain validation logic tests
# ─────────────────────────────────────────────────────────────────────────────
def test_cors_critical_origin_reflection_with_credentials_positive(critic, cas):
    """Positive: ACAO reflects attacker origin + ACAC:true + PII body = CRITICAL CORS."""
    raw = {
        "is_vulnerable": True,
        "confidence_score": 0.97,
        "reasoning": "CRITICAL CORS Chain Confirmed [Arbitrary External Origin]: Origin 'https://evil-attacker.com' reflected exactly, ACAC=true, and response body contains sensitive/PII data.",
        "target_url": "https://api.target.com/api/v1/user/profile",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://api.target.com/api/v1/user/profile",
                            "headers": {"Origin": "https://evil-attacker.com"}},
                "response": {
                    "status_code": 200,
                    "headers": {
                        "access-control-allow-origin": "https://evil-attacker.com",
                        "access-control-allow-credentials": "true"
                    },
                    "body_snippet": '{"username":"admin","email":"admin@target.com","role":"administrator"}'
                }
            }
        ]
    }
    b = cas.store_evidence("api.target.com", "cors_misconfig_check", raw)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"CORS Critical Positive Failed: {res}"


def test_cors_vary_origin_dynamic_reflection_medium(critic, cas):
    """Positive: ACAO reflects origin without credentials but Vary:Origin is present = MEDIUM."""
    raw = {
        "is_vulnerable": True,
        "confidence_score": 0.55,
        "reasoning": "MEDIUM CORS Dynamic Reflection: Origin reflected without credentials, but Vary: Origin confirms server dynamically sets ACAO.",
        "target_url": "https://api.target.com/api/v1/public",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://api.target.com/api/v1/public",
                            "headers": {"Origin": "https://evil-attacker.com"}},
                "response": {
                    "status_code": 200,
                    "headers": {
                        "access-control-allow-origin": "https://evil-attacker.com",
                        "vary": "Origin"
                    },
                    "body_snippet": '{"status": "ok"}'
                }
            }
        ]
    }
    b = cas.store_evidence("api.target.com", "cors_misconfig_check", raw)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"CORS Vary:Origin Medium Failed: {res}"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Open Redirect — meta-refresh and JS-location detection
# ─────────────────────────────────────────────────────────────────────────────
def test_open_redirect_header_based_positive(critic, cas):
    """Positive: 302 Location pointing to evil.com must pass critic."""
    raw = {
        "is_vulnerable": True,
        "confidence_score": 0.97,
        "reasoning": "CONFIRMED Open Redirect: 'redirect' accepted external domain — HTTP 302 Location: https://evil.com",
        "target_url": "https://target.com/auth/callback?redirect=https://evil.com",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://target.com/auth/callback?redirect=https://evil.com"},
                "response": {
                    "status_code": 302,
                    "headers": {"Location": "https://evil.com"},
                    "body_snippet": ""
                }
            }
        ]
    }
    b = cas.store_evidence("target.com", "open_redirect", raw)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"Open Redirect Header Positive Failed: {res}"


def test_open_redirect_meta_refresh_positive(critic, cas):
    """Positive: meta-refresh pointing to evil.com in body must be flagged."""
    raw = {
        "is_vulnerable": True,
        "confidence_score": 0.80,
        "reasoning": "POTENTIAL Open Redirect (meta-refresh): Parameter 'next' — attacker domain found in response body via 'meta-refresh' pattern.",
        "target_url": "https://target.com/redirect?next=https://evil.com",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://target.com/redirect?next=https://evil.com"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body_snippet": '<meta http-equiv="refresh" content="0;url=https://evil.com">'
                }
            }
        ]
    }
    b = cas.store_evidence("target.com", "open_redirect", raw)
    res = critic.verify_finding(b)
    assert res["is_verified"], f"Open Redirect meta-refresh Positive Failed: {res}"


def test_open_redirect_same_domain_negative(critic, cas):
    """Negative: 302 redirect to the same domain must NOT be flagged as open redirect."""
    raw = {
        "is_vulnerable": True,
        "confidence_score": 0.50,
        "reasoning": "Redirect to target.com/dashboard — internal redirect.",
        "target_url": "https://target.com/login",
        "evidence_exchanges": [
            {
                "request": {"method": "GET", "url": "https://target.com/login"},
                "response": {
                    "status_code": 302,
                    "headers": {"Location": "https://target.com/dashboard"},
                    "body_snippet": ""
                }
            }
        ]
    }
    b = cas.store_evidence("target.com", "open_redirect", raw)
    res = critic.verify_finding(b)
    assert not res["is_verified"], f"Open Redirect Same-Domain Negative Failed: {res}"


# ─────────────────────────────────────────────────────────────────────────────
# 11. S3 Bucket Exposure & Exploit Chainer Anti-Hallucination
# ─────────────────────────────────────────────────────────────────────────────
def test_s3_bucket_exposure_decoupled_from_ssrf():
    """Structural: s3_bucket_exposure must normalize to s3_bucket_exposure, NOT ssrf."""
    from penflow.domain.vulnerability_types import normalize_vulnerability_type
    assert normalize_vulnerability_type("s3_bucket_exposure") == "s3_bucket_exposure"
    assert normalize_vulnerability_type("public_s3_bucket_list") == "s3_bucket_exposure"
    assert normalize_vulnerability_type("cloud_misconfig") == "s3_bucket_exposure"


def test_exploit_chainer_does_not_invent_ssrf_chain_for_s3_bucket():
    """Anti-Hallucination: S3 bucket finding must NEVER produce an SSRF IAM theft exploit chain."""
    from penflow.intelligence.exploit_chainer import ExploitChainer
    s3_finding = {
        "vulnerability_type": "s3_bucket_exposure",
        "target_url": "https://sandbox-files.s3.amazonaws.com/",
        "is_vulnerable": True,
        "confidence": 0.98,
        "confidence_score": 0.98,
        "description": "Public AWS S3 bucket 'sandbox-files' permits unauthenticated ListBucket access.",
        "evidence": {
            "evidence_exchanges": [{
                "request": {"method": "GET", "url": "https://sandbox-files.s3.amazonaws.com/"},
                "response": {"status_code": 200, "body_snippet": "<ListBucketResult><Name>sandbox-files</Name></ListBucketResult>"}
            }]
        }
    }
    chainer = ExploitChainer()
    chains = chainer.construct_chains([s3_finding])
    assert len(chains) == 0, f"ExploitChainer hallucinated chain(s) for S3 bucket: {[c.title for c in chains]}"


def test_exploit_chainer_requires_verified_imds_proof_for_ssrf_iam_chain():
    """Positive Chaining: SSRF targeting 169.254.169.254 and leaking credentials MUST produce IAM chain."""
    from penflow.intelligence.exploit_chainer import ExploitChainer
    imds_finding = {
        "vulnerability_type": "ssrf_vulnerability",
        "target_url": "https://api.target.com/export",
        "is_vulnerable": True,
        "confidence": 0.99,
        "confidence_score": 0.99,
        "evidence": {
            "evidence_exchanges": [{
                "request": {"method": "POST", "url": "https://api.target.com/export", "body": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
                "response": {"status_code": 200, "body_snippet": "AccessKeyId: ASIA999, SecretAccessKey: xyz"}
            }]
        }
    }
    chainer = ExploitChainer()
    chains = chainer.construct_chains([imds_finding])
    assert len(chains) == 1, f"Expected 1 IMDS chain, got {len(chains)}"
    assert chains[0].chain_id == "CHAIN_SSRF_IAM_THEFT"


