"""
PenFlow Golden Regression Suite.
Rigorous adversarial falsification regression suite containing positive and negative
test cases across all primary vulnerability domains (OAuth, SQLi, SSTI, BOLA, SSRF, Headers).
"""
from penflow.validation.critic_engine import CriticVerificationEngine
from penflow.knowledge.evidence_cas import EvidenceCAS

def test_golden_regression_suite():
    critic = CriticVerificationEngine()
    cas = EvidenceCAS()
    results = []

    # ─────────────────────────────────────────────────────────────────────────────
    # 1. OAUTH
    # ─────────────────────────────────────────────────────────────────────────────
    # Negative: 301 CDN Redirect to legitimate internal domain (e.g. nu.com.mx)
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
    b_oauth_neg = cas.store_evidence("nu.com.mx", "oauth_misconfiguration", raw_oauth_neg)
    res_oauth_neg = critic.verify_finding(b_oauth_neg)
    assert not res_oauth_neg["is_verified"], f"OAuth Negative Failed: {res_oauth_neg}"
    results.append(("OAuth CDN Internal Redirect (Negative)", "PASSED [Falsified]"))

    # Positive: OAuth redirecting to external attacker collaborator domain
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
    b_oauth_pos = cas.store_evidence("nu.com.mx", "oauth_misconfiguration", raw_oauth_pos)
    res_oauth_pos = critic.verify_finding(b_oauth_pos)
    assert res_oauth_pos["is_verified"], f"OAuth Positive Failed: {res_oauth_pos}"
    results.append(("OAuth Token Leak to External OOB (Positive)", "PASSED [Verified]"))

    # ─────────────────────────────────────────────────────────────────────────────
    # 2. SQL INJECTION (TIMING & BLIND)
    # ─────────────────────────────────────────────────────────────────────────────
    # Negative: 404 Not Found delay (Report 32 case)
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
    b_sqli_404 = cas.store_evidence("lab.net", "sql_injection", raw_sqli_404)
    res_sqli_404 = critic.verify_finding(b_sqli_404)
    assert not res_sqli_404["is_verified"], f"SQLi 404 Negative Failed: {res_sqli_404}"
    results.append(("SQLi Timing Delay on HTTP 404 (Negative)", "PASSED [Falsified]"))

    # Negative: 405 Method Not Allowed delay (Report 33 case)
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
    b_sqli_405 = cas.store_evidence("lab.net", "sql_injection", raw_sqli_405)
    res_sqli_405 = critic.verify_finding(b_sqli_405)
    assert not res_sqli_405["is_verified"], f"SQLi 405 Negative Failed: {res_sqli_405}"
    results.append(("SQLi Timing Delay on HTTP 405 (Negative)", "PASSED [Falsified]"))

    # Negative: HTTP 200 with Soft Error body
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
    b_sqli_soft = cas.store_evidence("lab.net", "sql_injection", raw_sqli_soft)
    res_sqli_soft = critic.verify_finding(b_sqli_soft)
    assert not res_sqli_soft["is_verified"], f"SQLi Soft Error Negative Failed: {res_sqli_soft}"
    results.append(("SQLi Soft Error on HTTP 200 (Negative)", "PASSED [Falsified]"))

    # Positive: Genuine SQLi with database error extraction on 200 OK
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
    b_sqli_pos = cas.store_evidence("lab.net", "sql_injection", raw_sqli_pos)
    res_sqli_pos = critic.verify_finding(b_sqli_pos)
    assert res_sqli_pos["is_verified"], f"SQLi Positive Failed: {res_sqli_pos}"
    results.append(("SQLi Error-Based Extraction on HTTP 200 (Positive)", "PASSED [Verified]"))

    # ─────────────────────────────────────────────────────────────────────────────
    # 3. SSTI
    # ─────────────────────────────────────────────────────────────────────────────
    # Negative: Price matching 49.00 on standard store page without evaluation
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
    b_ssti_neg = cas.store_evidence("lab.net", "ssti_rce", raw_ssti_neg)
    res_ssti_neg = critic.verify_finding(b_ssti_neg)
    assert not res_ssti_neg["is_verified"], f"SSTI Negative Failed: {res_ssti_neg}"
    results.append(("SSTI Fake Match on Shop Price (Negative)", "PASSED [Falsified]"))

    # Positive: Genuine SSTI math evaluation 48239 * 71 = 3424969
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
    b_ssti_pos = cas.store_evidence("lab.net", "ssti_rce", raw_ssti_pos)
    res_ssti_pos = critic.verify_finding(b_ssti_pos)
    assert res_ssti_pos["is_verified"], f"SSTI Positive Failed: {res_ssti_pos}"
    results.append(("SSTI Mathematical Evaluation Proof (Positive)", "PASSED [Verified]"))

    # ─────────────────────────────────────────────────────────────────────────────
    # 4. BOLA / IDOR
    # ─────────────────────────────────────────────────────────────────────────────
    # Negative: 100% identical public HTML page returned for two different IDs
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
    b_bola_neg = cas.store_evidence("lab.net", "bola", raw_bola_neg)
    res_bola_neg = critic.verify_finding(b_bola_neg)
    assert not res_bola_neg["is_verified"], f"BOLA Negative Failed: {res_bola_neg}"
    results.append(("BOLA Identical Public Login Page (Negative)", "PASSED [Falsified]"))

    # Positive: True IDOR leaking distinct private user attributes
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
    b_bola_pos = cas.store_evidence("lab.net", "idor", raw_bola_pos)
    res_bola_pos = critic.verify_finding(b_bola_pos)
    assert res_bola_pos["is_verified"], f"BOLA Positive Failed: {res_bola_pos}"
    results.append(("IDOR Private Data & API Key Leak (Positive)", "PASSED [Verified]"))

    # ─────────────────────────────────────────────────────────────────────────────
    # 5. SSRF
    # ─────────────────────────────────────────────────────────────────────────────
    # Negative: Internal redirect staying on same target host
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
    b_ssrf_neg = cas.store_evidence("lab.net", "ssrf", raw_ssrf_neg)
    res_ssrf_neg = critic.verify_finding(b_ssrf_neg)
    assert not res_ssrf_neg["is_verified"], f"SSRF Negative Failed: {res_ssrf_neg}"
    results.append(("SSRF Relative Same-Host Redirect (Negative)", "PASSED [Falsified]"))

    # Positive: True SSRF leaking internal cloud metadata (ami-id / 169.254.169.254)
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
    b_ssrf_pos = cas.store_evidence("lab.net", "ssrf", raw_ssrf_pos)
    res_ssrf_pos = critic.verify_finding(b_ssrf_pos)
    assert res_ssrf_pos["is_verified"], f"SSRF Positive Failed: {res_ssrf_pos}"
    results.append(("SSRF AWS Cloud Metadata Exfiltration (Positive)", "PASSED [Verified]"))

    # ─────────────────────────────────────────────────────────────────────────────
    # 6. MISSING SECURITY HEADERS
    # ─────────────────────────────────────────────────────────────────────────────
    # Missing headers on target without CSP/HSTS capped at 0.30 Informative
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
    b_headers = cas.store_evidence("lab.net", "missing_headers", raw_headers)
    res_headers = critic.verify_finding(b_headers)
    assert res_headers["is_verified"], f"Headers Positive Failed: {res_headers}"
    assert res_headers["confidence"] <= 0.30, f"Headers should be capped at <= 0.30, got {res_headers['confidence']}"
    results.append(("Missing Security Headers Capped at Informative (Positive)", "PASSED [Verified]"))

    print("\n" + "="*80)
    print("PENFLOW GOLDEN REGRESSION SUITE RESULTS")
    print("="*80)
    for test_name, status in results:
        print(f"  {status.ljust(22)} | {test_name}")
    print("="*80)
    print(f"TOTAL TESTS: {len(results)} | PASSED: {len(results)} | FAILED: 0")
    print("="*80 + "\n")

if __name__ == "__main__":
    test_golden_regression_suite()
