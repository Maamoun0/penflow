import httpx
import sys
import os
import re

sys.stdout.reconfigure(encoding='utf-8')

print("="*80)
print("PENFLOW DEEP LIVE VULNERABILITY VERIFICATION")
print("="*80)

client = httpx.Client(verify=False, timeout=10.0, follow_redirects=True)

def test_file_exposure(domain, paths):
    print(f"\n[*] Testing file exposure on: {domain}")
    # First get 404 baseline
    try:
        baseline_r = client.get(f"https://{domain}/nonexistent_random_path_1238947192837.txt")
        baseline_len = len(baseline_r.content)
        baseline_status = baseline_r.status_code
        print(f"    Baseline 404: Status={baseline_status}, Length={baseline_len}")
    except Exception as e:
        print(f"    Error connecting: {e}")
        return

    for p in paths:
        url = f"https://{domain}/{p.lstrip('/')}"
        try:
            r = client.get(url)
            # Check if it differs from baseline
            if r.status_code == 200:
                is_soft_404 = (abs(len(r.content) - baseline_len) < 50 and baseline_status == 200)
                if not is_soft_404:
                    print(f"  [+] 200 OK: {url} (Length: {len(r.content)})")
                    # Check first 200 bytes of content
                    snippet = r.text[:200].replace('\n', ' ')
                    print(f"      Content: {snippet[:150]}")
                else:
                    print(f"  [-] Soft-404 / Default: {url}")
            elif r.status_code in [401, 403]:
                print(f"  [!] {r.status_code} Forbidden/Auth: {url}")
            else:
                pass
        except Exception as e:
            pass

# Test products.mo.cloudintegration.abb.com
test_file_exposure("products.mo.cloudintegration.abb.com", [
    ".env", ".env.local", "config.json", "package.json", "web.config", 
    ".git/config", ".git/HEAD", "robots.txt", "swagger.json", "openapi.json", "api-docs"
])

# Test rbook.abb.com
test_file_exposure("rbook.abb.com", [
    ".env", "config.json", "robots.txt", "api/", "swagger.json", "openapi.json",
    "manifest.json", "health", "actuator/health", "actuator/env", "api/v1"
])

# Test polaris.iam.motion.abb.com
test_file_exposure("polaris.iam.motion.abb.com", [
    "robots.txt", ".env", "swagger.json", "openapi.json", "api/", "health",
    "actuator/health", "actuator/env", "auth/health", "oauth2/jwks"
])

# Test salestool.ch.abb.com
test_file_exposure("salestool.ch.abb.com", [
    "robots.txt", ".env", "config.json", "api/", "swagger.json"
])

# Test remotemonitoring.drives.abb.com
test_file_exposure("remotemonitoring.drives.abb.com", [
    "robots.txt", ".env", "config.json", "api/", "swagger.json"
])

# Test sensorfact.com
test_file_exposure("sensorfact.com", [
    "robots.txt", ".env", "api/", "graphql", "swagger.json", "openapi.json"
])

# Test CORS on live assets
print("\n" + "="*80)
print("[*] Testing CORS Misconfigurations with Origin reflection")
for domain in ["products.mo.cloudintegration.abb.com", "rbook.abb.com", "polaris.iam.motion.abb.com", "sensorfact.com"]:
    url = f"https://{domain}/"
    try:
        r = client.get(url, headers={"Origin": "https://evil.com"})
        acao = r.headers.get("access-control-allow-origin")
        acac = r.headers.get("access-control-allow-credentials")
        if acao:
            print(f"  [!] CORS on {domain}: ACAO={acao}, ACAC={acac}")
    except Exception as e:
        pass
