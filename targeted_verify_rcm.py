"""
TARGETED VERIFICATION: rcm.motors.abb.com.cn
Real API paths discovered via JS mining:
/api/services/app/Permission/GetMyOrgAssociatedAccount
/api/services/app/Permission/GetAllPermissionsByRoleId
/api/services/app/Permission/UpdatePermission
/api/services/app/User/GetOrgUserById
/api/services/app/Permission/GetPermissionTree
"""
import httpx
import sys
import json

sys.stdout.reconfigure(encoding='utf-8')

BASE = "https://rcm.motors.abb.com.cn"

# These are real discovered API paths from JS analysis
REAL_API_PATHS = [
    "/api/services/app/Permission/GetMyOrgAssociatedAccount",
    "/api/services/app/Permission/GetAllPermissionsByRoleId",
    "/api/services/app/Permission/UpdatePermission",
    "/api/services/app/User/GetOrgUserById",
    "/api/services/app/Permission/GetPermissionTree",
    "/api/services/app/User/GetAllUsers",
    "/api/services/app/User/GetAll",
    "/api/services/app/Role/GetAll",
    "/api/services/app/Account/GetAll",
    "/api/tokenauth/authenticate",
    "/api/account",
    "/api/user",
    "/api/users",
]

client = httpx.Client(verify=False, timeout=10.0, follow_redirects=True)

print("="*70)
print("TARGETED VERIFICATION: rcm.motors.abb.com.cn")
print("Testing REAL JS-discovered API endpoints")
print("="*70)

# First get a baseline
baseline = client.get(f"{BASE}/nonexistent_path_xyzabc123", headers={"Accept": "application/json"})
print(f"\nBaseline (404): Status={baseline.status_code}, Length={len(baseline.content)}, CT={baseline.headers.get('content-type','')}")

print()
for path in REAL_API_PATHS:
    url = f"{BASE}{path}"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": "https://evil.com"
    }
    
    # Test GET
    try:
        r = client.get(url, headers=headers)
        acao = r.headers.get("access-control-allow-origin", "")
        ct = r.headers.get("content-type", "")
        
        is_json = "json" in ct or (r.text.strip().startswith("{") or r.text.strip().startswith("["))
        is_different_from_baseline = abs(len(r.content) - len(baseline.content)) > 50 or r.status_code != baseline.status_code
        
        tag = ""
        if r.status_code == 200 and is_json:
            tag = " 🔴 JSON RESPONSE - REVIEW!"
        elif r.status_code in [401, 403]:
            tag = " 🟡 Auth Required - ENDPOINT EXISTS"
        elif r.status_code == 200 and is_different_from_baseline:
            tag = " 🟠 200 but not JSON"
        
        if tag or r.status_code not in [404, 301, 302]:
            print(f"[{r.status_code}] {path}{tag}")
            print(f"    CT={ct} | Len={len(r.content)} | ACAO={acao or 'none'}")
            if r.status_code == 200 and len(r.content) < 2000:
                print(f"    Body: {r.text[:300]}")
            print()
    except Exception as e:
        print(f"    Error on {url}: {e}")

    # Also test POST for mutation endpoints
    if "Update" in path or "authenticate" in path or "Create" in path:
        try:
            r2 = client.post(url, headers=headers, json={})
            if r2.status_code not in [404, 405]:
                print(f"  POST [{r2.status_code}] {path}")
                ct2 = r2.headers.get("content-type", "")
                if "json" in ct2:
                    print(f"    Body: {r2.text[:300]}")
        except Exception:
            pass

print("\n" + "="*70)
print("Checking config.js for hardcoded API config")
print("="*70)
try:
    r = client.get(f"{BASE}/config.js", headers={"Accept": "*/*"})
    print(f"config.js Status: {r.status_code} | Length: {len(r.content)}")
    if r.status_code == 200:
        print(f"Content:\n{r.text[:1000]}")
except Exception as e:
    print(f"Error: {e}")
