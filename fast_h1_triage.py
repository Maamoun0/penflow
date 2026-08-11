import asyncio
import httpx
import sys
import os
import re

sys.stdout.reconfigure(encoding='utf-8')

print("="*80)
print("FAST ASYNC TRIAGE & DEEP VULNERABILITY VERIFIER")
print("="*80)

from scan_scope_abb import SCOPE

async def main():
    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
        # 1. Test CORS on live domains
        print("\n--- 1. CORS Misconfiguration Testing (Origin: evil.com) ---")
        live_domains = [
            "products.mo.cloudintegration.abb.com",
            "rbook.abb.com",
            "polaris.iam.motion.abb.com",
            "salestool.ch.abb.com",
            "remotemonitoring.drives.abb.com",
            "receiver.remotemonitoring.drives.abb.com",
            "receiver-drives.abb.com.cn",
            "re460monitoring.traction.abb.com",
            "rcm.motors.abb.com.cn",
            "ra-workitem.cloudintegration.abb.com",
            "quotations.abb.com",
            "qms.lmg.motion.abb.com.cn",
            "sensorfact.com",
            "sensorfact.nl",
            "sensorfact.de",
            "sensorfact.tools",
            "sensorfact.pt",
            "sensorfact.it"
        ]
        
        for d in live_domains:
            try:
                r = await client.get(f"https://{d}/", headers={"Origin": "https://evil.com"})
                acao = r.headers.get("access-control-allow-origin")
                acac = r.headers.get("access-control-allow-credentials")
                if acao:
                    print(f"  [+] CORS Header on {d}: ACAO={acao} | ACAC={acac}")
            except Exception:
                pass

        # 2. Test Open Redirects
        print("\n--- 2. Open Redirect Testing ---")
        redirect_test_paths = [
            ("shorturl.abb.com", ["/?url=https://evil.com", "/?next=https://evil.com", "/?dest=https://evil.com", "/?r=https://evil.com"]),
            ("redirect.abb.com", ["/?url=https://evil.com", "/?redirect=https://evil.com", "/?to=https://evil.com"]),
            ("salestool.ch.abb.com", ["/login?return=https://evil.com", "/redirect?url=https://evil.com"]),
            ("sensorfact.com", ["/login?redirect=https://evil.com", "/auth?callback=https://evil.com"]),
            ("polaris.iam.motion.abb.com", ["/oauth2/authorize?redirect_uri=https://evil.com&client_id=test&response_type=code", "/login?returnUrl=https://evil.com"])
        ]
        
        for host, paths in redirect_test_paths:
            for p in paths:
                url = f"https://{host}{p}"
                try:
                    r = await client.get(url)
                    if r.status_code in [301, 302, 303, 307, 308]:
                        loc = r.headers.get("location", "")
                        print(f"  [!] Redirect on {url} -> Status {r.status_code} | Location: {loc}")
                except Exception:
                    pass

        # 3. Test Specific High-Value Endpoints
        print("\n--- 3. Testing High-Value API & Security Endpoints ---")
        test_endpoints = [
            ("polaris.iam.motion.abb.com", "/oauth2/jwks"),
            ("polaris.iam.motion.abb.com", "/.well-known/openid-configuration"),
            ("rbook.abb.com", "/api/"),
            ("products.mo.cloudintegration.abb.com", "/.git/HEAD"),
            ("products.mo.cloudintegration.abb.com", "/api-docs"),
            ("rcm.motors.abb.com.cn", "/api/"),
            ("sensorfact.com", "/graphql"),
            ("sensorfact.nl", "/graphql")
        ]
        
        for host, ep in test_endpoints:
            url = f"https://{host}{ep}"
            try:
                r = await client.get(url)
                print(f"  Endpoint: {url} -> Status: {r.status_code} (Length: {len(r.content)})")
                if r.status_code == 200:
                    print(f"    Sample: {r.text[:150].replace(chr(10), ' ')}")
            except Exception as e:
                print(f"  Endpoint: {url} -> Error: {e}")

asyncio.run(main())
