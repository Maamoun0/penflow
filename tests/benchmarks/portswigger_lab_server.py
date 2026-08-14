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
