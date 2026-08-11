import httpx
import sys

sys.stdout.reconfigure(encoding='utf-8')

client = httpx.Client(verify=False, timeout=10.0, follow_redirects=True)

urls_to_test = [
    "https://shorturl.abb.com/?url=https://evil.com",
    "https://polaris.iam.motion.abb.com/login?returnUrl=https://evil.com",
    "https://sensorfact.tools/",
    "https://sensorfact.energy/",
    "https://sensorfact.cloud/",
]

for u in urls_to_test:
    try:
        r = client.get(u)
        print(f"URL: {u}")
        print(f"  Final URL: {r.url}")
        print(f"  Status: {r.status_code}")
        print(f"  Redirect History: {[h.status_code for h in r.history]}")
        print(f"  History URLs: {[str(h.url) for h in r.history]}")
        print("-" * 60)
    except Exception as e:
        print(f"Error on {u}: {e}")
