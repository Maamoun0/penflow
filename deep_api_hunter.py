"""
PENFLOW DEEP AUTHENTICATED API HUNTER
Goal: Find real, non-rejectable vulnerabilities on live ABB/Sensorfact assets
Focus: remotemonitoring.drives.abb.com, rbook.abb.com, rcm.motors.abb.com.cn, sensorfact.* domains
"""
import asyncio
import httpx
import sys
import re
import json
import urllib.parse

sys.stdout.reconfigure(encoding='utf-8')

# ─────────────────────────────────────────────────────────────
TARGETS = [
    "remotemonitoring.drives.abb.com",
    "rbook.abb.com",
    "rcm.motors.abb.com.cn",
    "qms.lmg.motion.abb.com.cn",
    "polaris.iam.motion.abb.com",
    "ra-workitem.cloudintegration.abb.com",
    "quotations.abb.com",
    "sensorfact.com",
    "sensorfact.nl",
    "sensorfact.de",
    "sensorfact.tools",
    "re460monitoring.traction.abb.com",
]

# Common API prefixes used in enterprise apps
API_PREFIXES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/api", "/rest/v1",
    "/graphql", "/graphiql",
    "/v1", "/v2",
    "/services", "/service",
    "/data", "/odata",
]

# Endpoint wordlist — enterprise/ABB specific
ENDPOINT_WORDLIST = [
    # Auth & Session
    "auth", "login", "logout", "token", "oauth", "oauth2",
    "authorize", "callback", "refresh", "session", "sso",
    # User & Account
    "users", "user", "me", "profile", "account", "accounts",
    "roles", "permissions", "groups", "members",
    # Data & Resources
    "devices", "device", "assets", "asset", "sensors", "sensor",
    "measurements", "measurement", "reports", "report",
    "alarms", "alarm", "events", "event", "notifications",
    "orders", "order", "products", "product",
    # Config & Admin
    "admin", "config", "configuration", "settings", "health",
    "status", "info", "version", "metrics", "actuator",
    # Common ABB-specific paths
    "drives", "drive", "motors", "motor", "inverter",
    "monitoring", "dashboard", "analytics",
    # File & Data
    "export", "import", "download", "upload", "files", "documents",
    # Developer
    "swagger", "swagger.json", "swagger.yaml",
    "openapi.json", "openapi.yaml",
    "api-docs", "api-spec", ".well-known",
    "docs", "documentation",
]

async def discover_js_api_calls(client, base_url):
    """Extract actual API calls from JavaScript source files."""
    found_routes = set()
    try:
        r = await client.get(f"{base_url}/", follow_redirects=True)
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text)
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)

        # Scan inline scripts
        for script in inline_scripts:
            routes = re.findall(r'["\`]/(?:api|v\d|rest|services|graphql)[/\w\-\.]*["\`]', script)
            found_routes.update(routes)
            routes2 = re.findall(r'(?:fetch|axios|\.get|\.post|\.put|\.delete)\(["\`]([^"\'`\s]{5,})["\`]', script)
            found_routes.update(routes2)

        # Download and scan external JS files
        for src in scripts[:15]:
            if not src.startswith("http"):
                src = base_url + "/" + src.lstrip("/")
            try:
                js_resp = await client.get(src, follow_redirects=True)
                routes = re.findall(r'["\`](/(?:api|v\d|rest|services|graphql|odata)[/\w\-\.{}\?=&]*)["\`]', js_resp.text)
                found_routes.update(routes)
                # Also check for hardcoded config values
                configs = re.findall(r'(?:baseURL|apiUrl|API_URL|endpoint|apiBase)["\']?\s*[:=]\s*["\`]([^"\'`\s]{8,})["\`]', js_resp.text)
                for c in configs:
                    print(f"    [JS CONFIG] Found: {c}")
            except Exception:
                pass

    except Exception as e:
        print(f"  JS discovery error: {e}")
    return found_routes

async def test_endpoint(client, base_url, path, results):
    """Test a single endpoint and record interesting findings."""
    url = f"{base_url}{path}"
    try:
        # Test unauthenticated
        r = await client.get(url, headers={
            "Origin": "https://evil.com",
            "Accept": "application/json, text/plain, */*",
        }, follow_redirects=False)

        status = r.status_code
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        ct = r.headers.get("content-type", "")
        length = len(r.content)

        interesting = False
        notes = []

        # Flag interesting findings
        if status == 200 and length > 10:
            interesting = True
            notes.append(f"200 OK ({length} bytes)")
            # Try to detect JSON/data responses
            if "json" in ct or r.text.strip().startswith("{") or r.text.strip().startswith("["):
                notes.append("JSON RESPONSE DETECTED")
                # Check for sensitive field names
                for field in ["token", "password", "secret", "key", "credential", "user", "email", "id"]:
                    if field in r.text.lower():
                        notes.append(f"SENSITIVE FIELD: '{field}'")

        if status in [401, 403] and length > 0:
            notes.append(f"Auth Required ({status}) - endpoint EXISTS")
            interesting = True

        if acao == "*" and status == 200 and "json" in ct:
            notes.append("CORS WILDCARD + JSON RESPONSE = HIGH IMPACT")
            interesting = True

        if acao and acao != "*" and "abb.com" not in acao and status == 200:
            notes.append(f"CORS: {acao}")
            interesting = True

        if interesting:
            result = {
                "url": url,
                "status": status,
                "acao": acao,
                "acac": acac,
                "content_type": ct,
                "length": length,
                "notes": notes,
                "body_preview": r.text[:200] if status == 200 else ""
            }
            results.append(result)
            print(f"  [FOUND] {url}")
            print(f"    Status: {status} | CT: {ct} | ACAO: {acao if acao else 'none'} | Len: {length}")
            for n in notes:
                print(f"    NOTE: {n}")
            if result["body_preview"]:
                print(f"    Body: {result['body_preview'][:120]}")
            print()

    except Exception:
        pass

async def scan_target(domain, all_results):
    """Deep scan a single target."""
    base_url = f"https://{domain}"
    results = []
    print(f"\n{'='*70}")
    print(f"[*] DEEP SCANNING: {domain}")
    print(f"{'='*70}")

    async with httpx.AsyncClient(
        verify=False,
        timeout=8.0,
        limits=httpx.Limits(max_connections=10),
        follow_redirects=True
    ) as client:
        # Step 1: JS-based route discovery
        print(f"  [1/3] Extracting routes from JavaScript...")
        js_routes = await discover_js_api_calls(client, base_url)
        print(f"  Found {len(js_routes)} routes from JS analysis")
        for r in list(js_routes)[:5]:
            print(f"    -> {r}")

        # Step 2: Build full path list
        paths_to_test = set()

        # From JS discovery
        for route in js_routes:
            if isinstance(route, str) and len(route) > 2:
                clean = route.strip("'\"`")
                if clean.startswith("/"):
                    paths_to_test.add(clean)

        # From wordlist combinations
        for prefix in API_PREFIXES:
            paths_to_test.add(prefix)
            paths_to_test.add(f"{prefix}/")
            for word in ENDPOINT_WORDLIST:
                paths_to_test.add(f"{prefix}/{word}")

        print(f"  [2/3] Testing {len(paths_to_test)} endpoints...")

        # Step 3: Test in batches of 15
        paths_list = list(paths_to_test)
        batch_size = 15
        for i in range(0, len(paths_list), batch_size):
            batch = paths_list[i:i+batch_size]
            tasks = [test_endpoint(client, base_url, p, results) for p in batch]
            await asyncio.gather(*tasks)

        # Step 4: Also test for CORS on authenticated paths
        print(f"  [3/3] Testing CORS with authentication-related payloads...")
        auth_paths = ["/api/users", "/api/me", "/api/profile", "/api/user/profile",
                      "/v1/users", "/v1/me", "/v2/users", "/rest/users"]
        for p in auth_paths:
            await test_endpoint(client, base_url, p, results)

    all_results[domain] = results
    print(f"  [DONE] {domain}: {len(results)} interesting findings")

async def main():
    all_results = {}
    for domain in TARGETS:
        await scan_target(domain, all_results)

    # Final report
    print("\n" + "="*70)
    print("DEEP SCAN FINAL REPORT")
    print("="*70)
    total = sum(len(v) for v in all_results.values())
    print(f"Total Interesting Findings: {total}")
    print()

    high_impact = []
    for domain, results in all_results.items():
        for r in results:
            if "JSON RESPONSE DETECTED" in r["notes"] or "CORS WILDCARD + JSON" in r["notes"]:
                high_impact.append(r)

    if high_impact:
        print(f"[!!! HIGH IMPACT FINDINGS: {len(high_impact)} !!!]")
        for h in high_impact:
            print(f"  URL: {h['url']}")
            print(f"  Notes: {', '.join(h['notes'])}")
            print()

    # Save full results
    with open("reports/deep_scan_results.json", "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"Full results saved to: reports/deep_scan_results.json")

asyncio.run(main())
