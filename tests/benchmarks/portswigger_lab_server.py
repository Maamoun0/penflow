"""
PortSwigger-Style Vulnerability Benchmark Lab Server.

Implements realistic HTTP endpoints simulating classic PortSwigger Web Security Academy
and OWASP Top 10 vulnerability scenarios for rigorous benchmarking of PenFlow agents.
"""
import asyncio
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, Response, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

app = FastAPI(title="PortSwigger Benchmark Labs", description="Simulated Vulnerable Lab Environment")


# --- Lab 1: SQL Injection (WHERE clause vulnerability & Error-based / Time-based) ---
@app.get("/lab/sqli/search")
async def sqli_search(id: str = Query("1"), category: Optional[str] = None):
    # Error-based detection
    if "'" in id or "'" in str(category):
        if "ExtractValue" in id or "CONVERT" in id or "penflow_sqli" in id:
            return JSONResponse(
                status_code=500,
                content={"error": "XPATH syntax error: '\\penflow_sqli'", "db": "MySQL 8.0.32"}
            )
        if "pg_sleep" in id or "SLEEP" in id or "WAITFOR" in id:
            # Simulate database sleep delay
            await asyncio.sleep(3.0)
            return JSONResponse(
                status_code=200,
                content={"results": [{"id": 1, "name": "Secret Admin Data", "price": 9999}], "delayed": True}
            )
        return JSONResponse(
            status_code=500,
            content={"error": f"SQL syntax error in query: SELECT * FROM products WHERE id = '{id}'", "status": "failed"}
        )
    return JSONResponse(content={"results": [{"id": int(id) if id.isdigit() else 1, "name": "Standard Product", "price": 49}]})


# --- Lab 2: Reflected XSS (HTML Context with Reflection) ---
@app.get("/lab/xss/comment", response_class=HTMLResponse)
async def xss_comment(q: str = Query("test"), search: Optional[str] = None):
    query_val = search or q
    # Reflect query directly into HTML without HTML entity encoding
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results</h1>
        <div id="results">
            <p>0 results found for: <span>{query_val}</span></p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)


# --- Lab 3: SSRF (AWS EC2 Metadata Service Simulation) ---
@app.get("/lab/ssrf/proxy")
async def ssrf_proxy(url: str = Query(...)):
    # Simulate internal fetching logic
    if "169.254.169.254" in url:
        if "security-credentials" in url:
            return JSONResponse(
                status_code=200,
                content={
                    "Code": "Success",
                    "Type": "AWS-HMAC",
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "Token": "AQoDYXdzEJr1...",
                    "Expiration": "2026-08-15T00:00:00Z"
                }
            )
        elif "meta-data" in url:
            return Response(content="ami-id\nhostname\niam/\ninstance-id\ninstance-type\nlocal-ipv4", media_type="text/plain", status_code=200)
    elif "localhost" in url or "127.0.0.1" in url:
        return JSONResponse(status_code=200, content={"service": "internal-admin-backend", "status": "running", "admin_port": 8080})
    return JSONResponse(status_code=400, content={"error": f"Failed to fetch external resource: {url}"})


# --- Lab 4: Insecure Direct Object References (IDOR / BOLA) ---
USER_DB = {
    "1001": {"user_id": "1001", "username": "alice", "role": "user", "api_key": "live_user_key_alice_89a7"},
    "1002": {"user_id": "1002", "username": "bob", "role": "user", "api_key": "live_user_key_bob_47b2"},
    "9999": {"user_id": "9999", "username": "admin", "role": "superadmin", "api_key": "live_admin_secret_key_root_99"}
}

@app.get("/lab/idor/account")
async def idor_account(id: str = Query("1001"), authorization: Optional[str] = Header(None)):
    # BOLA flaw: Accepts any user id regardless of authentication header
    if id in USER_DB:
        return JSONResponse(status_code=200, content=USER_DB[id])
    return JSONResponse(status_code=404, content={"error": "User not found"})


# --- Lab 5: CORS Misconfiguration (Origin Reflection & Credentials Allowed) ---
@app.get("/lab/cors/userinfo")
async def cors_userinfo(request: Request):
    origin = request.headers.get("origin", "*")
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    }
    return JSONResponse(
        content={"user_id": "1001", "username": "alice", "email": "alice@target-organization.com", "private_token": "ptok_998124_secret"},
        headers=headers
    )


# --- Lab 6: OS Command Injection (RCE) ---
@app.get("/lab/rce/ping")
async def rce_ping(ip: str = Query("127.0.0.1")):
    if any(sep in ip for sep in [";", "|", "&", "`", "$("]):
        # Simulate command execution output
        if "whoami" in ip or "id" in ip:
            return Response(content="uid=1000(appuser) gid=1000(appuser) groups=1000(appuser),27(sudo)\n", media_type="text/plain", status_code=200)
        if "cat" in ip and "passwd" in ip:
            return Response(content="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nappuser:x:1000:1000:App User:/home/appuser:/bin/bash\n", media_type="text/plain", status_code=200)
        return Response(content="PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n", media_type="text/plain", status_code=200)
    return Response(content=f"PING {ip} (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n", media_type="text/plain", status_code=200)


# --- Lab 7: OAuth & Redirect URI Manipulation ---
@app.get("/lab/oauth/authorize")
async def oauth_authorize(client_id: str = Query(...), redirect_uri: str = Query(...), response_type: str = Query("code")):
    # Vulnerable OAuth Provider: Reflects redirect_uri with traversal or external attacker domain without validation
    auth_code = "auth_code_secret_token_88921_valid"
    if "attacker" in redirect_uri or "evil.com" in redirect_uri:
        return RedirectResponse(url=f"{redirect_uri}?code={auth_code}", status_code=302)
    return RedirectResponse(url=f"https://legit-app.local/callback?code={auth_code}", status_code=302)


# --- Lab 8: Missing Security Headers & Hardening ---
@app.get("/lab/headers/insecure")
async def headers_insecure():
    # Intentionally omitted HSTS, CSP, X-Frame-Options, X-Content-Type-Options
    resp = Response(content="<html><body>Insecure Server Configuration</body></html>", media_type="text/html", status_code=200)
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    return resp


# --- Lab 9: Race Condition (Limit Overrun Coupon Redemption) ---
COUPON_STORAGE = {"active_redemptions": 0, "max_allowed": 1}

@app.post("/lab/race/coupon")
async def race_coupon():
    # Vulnerable Time-Of-Check to Time-Of-Use (TOCTOU) gap
    current = COUPON_STORAGE["active_redemptions"]
    if current < COUPON_STORAGE["max_allowed"]:
        await asyncio.sleep(0.05)  # Window of vulnerability
        COUPON_STORAGE["active_redemptions"] += 1
        return JSONResponse(status_code=200, content={"status": "success", "message": "Coupon $50 applied!", "redemption_count": COUPON_STORAGE["active_redemptions"]})
    return JSONResponse(status_code=400, content={"status": "error", "message": "Coupon already redeemed."})


# --- Lab 10: Negative Control (Fully Hardened Endpoint with Standard Edge Redirect) ---
@app.get("/lab/secure/profile")
async def secure_profile():
    # Standard CloudFront Edge 301 alias redirect
    headers = {
        "Server": "CloudFront",
        "Location": "https://company.com/lab/secure/profile",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'"
    }
    return Response(status_code=301, headers=headers)


# --- Lab 11: JWT Algorithm Confusion & Unverified Signature ---
@app.get("/lab/jwt/admin")
async def jwt_admin(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "Missing Authorization header"})
    token = authorization.split(" ")[1]
    # Vulnerable JWT parser: Accepts alg: none or signature bypass
    if "eyJhbGciOiJub25l" in token or "YWRtaW4" in token or "admin" in token.lower() or "none" in token.lower():
        return JSONResponse(status_code=200, content={"status": "admin_granted", "role": "superadmin", "secret_key": "jwt_flag_admin_root_access_89a7"})
    return JSONResponse(status_code=403, content={"error": "Invalid signature or insufficient permissions"})


# --- Lab 12: Server-Side Prototype Pollution ---
@app.post("/lab/prototype/merge")
async def prototype_merge(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})
    body_str = str(body)
    if "__proto__" in body_str or "constructor.prototype" in body_str or "polluted" in body_str:
        return JSONResponse(status_code=200, content={"status": "polluted", "isAdmin": True, "gadget_output": "rce_prototype_gadget_success_exec"})
    return JSONResponse(status_code=200, content={"status": "merged", "isAdmin": False})


# --- Lab 13: Blind XXE via Out-of-Band DTD Exfiltration ---
@app.post("/lab/xxe/upload")
async def xxe_upload(request: Request):
    raw_body = (await request.body()).decode("utf-8", errors="ignore")
    if "<!ENTITY" in raw_body or "SYSTEM" in raw_body or "xxe_payload" in raw_body or "file://" in raw_body:
        return JSONResponse(
            status_code=200,
            content={
                "status": "parsed",
                "xxe_confirmed": True,
                "dtd_exfiltration": "root:x:0:0:root:/root:/bin/bash\nappuser:x:1000:1000:App:/home/appuser:/bin/bash"
            }
        )
    return JSONResponse(status_code=200, content={"status": "parsed", "items_processed": 1})


# --- Lab 14: HTTP Request Smuggling (CL.TE / CL.0 Desynchronization) ---
@app.post("/lab/smuggling/order")
async def smuggling_order(request: Request):
    headers = request.headers
    has_cl = "content-length" in headers
    has_te = "transfer-encoding" in headers
    raw_body = (await request.body()).decode("utf-8", errors="ignore")
    if (has_cl and has_te) or "0\r\n\r\n" in raw_body or "smuggled" in raw_body:
        return JSONResponse(
            status_code=200,
            content={"status": "smuggled_prefix_executed", "desync_detected": True, "queue_poisoned": True, "smuggled_path": "/admin/delete_user"}
        )
    return JSONResponse(status_code=200, content={"status": "order_placed", "order_id": 4821})


# --- Lab 15: SAML 2.0 XML Signature Wrapping (XSW) ---
@app.post("/lab/saml/sso")
async def saml_sso(request: Request):
    raw_body = (await request.body()).decode("utf-8", errors="ignore")
    if "saml:Assertion" in raw_body or "Response" in raw_body or "saml_xsw" in raw_body:
        if "Administrator" in raw_body or "role_admin" in raw_body or "xsw_attack" in raw_body:
            return JSONResponse(
                status_code=200,
                content={"status": "saml_authenticated", "role": "Administrator", "flag": "saml_xsw_flag_bypass_root_auth"}
            )
    return JSONResponse(status_code=200, content={"status": "saml_authenticated", "role": "User"})


# --- Lab 16: WebAuthn / Passkey Challenge Verification Flaw ---
@app.post("/lab/webauthn/verify")
async def webauthn_verify(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    if data.get("clientDataJSON") or data.get("passkey_bypass") or "challenge" in str(data):
        return JSONResponse(
            status_code=200,
            content={"status": "authenticated", "auth_method": "passkey_tampered_success", "user": "admin"}
        )
    return JSONResponse(status_code=400, content={"status": "challenge_mismatch"})


# --- Lab 17: Client-Side Path Traversal (CSPT) into API Manipulation ---
@app.get("/lab/cspt/api")
async def cspt_api(path: str = Query("users")):
    if "..%2f" in path or "../" in path or "admin" in path:
        return JSONResponse(
            status_code=200,
            content={"status": "traversed", "endpoint": "/api/v2/admin/keys", "keys": ["live_cspt_admin_key_sec99"]}
        )
    return JSONResponse(status_code=200, content={"status": "ok", "path": path, "items": []})


# --- Lab 18: GraphQL Batching & Query Depth Amplification ---
@app.post("/lab/graphql/query")
async def graphql_query(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    query_str = str(data.get("query", ""))
    if "__schema" in query_str or "__type" in query_str:
        return JSONResponse(
            status_code=200,
            content={"data": {"__schema": {"types": [{"name": "User"}, {"name": "AdminMutation"}, {"name": "SuperSecretVault"}]}}}
        )
    if query_str.count("author") > 2 or query_str.count("posts") > 2:
        return JSONResponse(
            status_code=200,
            content={"data": {"depth_amplification": True, "nested_execution_success": True}}
        )
    return JSONResponse(status_code=200, content={"data": {"status": "ok"}})


# --- Lab 19: Mass Assignment & BFLA ---
@app.put("/lab/mass_assignment/profile")
async def mass_assignment_profile(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    is_admin = data.get("is_admin", False)
    role = data.get("role", "user")
    if is_admin is True or role in ("admin", "superuser", "root"):
        return JSONResponse(
            status_code=200,
            content={"status": "updated", "is_admin": True, "role": "superuser", "permissions": ["ALL", "ROOT"]}
        )
    return JSONResponse(status_code=200, content={"status": "updated", "is_admin": False, "role": "user"})


# --- Lab 20: Multi-Stage Exploit Chain (SSRF -> Cloud IAM -> Token -> Admin Takeover) ---
@app.post("/lab/chain/admin_takeover")
async def exploit_chain_takeover(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    if data.get("iam_token") == "AKIAIOSFODNN7EXAMPLE" and data.get("role") == "admin":
        return JSONResponse(
            status_code=200,
            content={
                "chain_status": "COMPROMISED",
                "attack_path": "SSRF (IMDS) -> AWS IAM Key Theft -> Multi-Tenant Account Takeover",
                "composite_severity": "CRITICAL",
                "cvss_score": 10.0,
                "full_pwn": True
            }
        )
    return JSONResponse(status_code=400, content={"error": "Incomplete exploit chain"})

