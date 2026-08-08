import httpx
import sys
import os
import re
import socket
import subprocess

sys.stdout.reconfigure(encoding='utf-8')

print("="*80)
print("PENFLOW DEEP TRIAGE FOR HACKERONE-READY SUBMISSIONS")
print("="*80)

client = httpx.Client(verify=False, timeout=8.0, follow_redirects=False)

from scan_scope_abb import SCOPE

# ─────────────────────────────────────────────────────────────
# 1. CNAME & SUBDOMAIN TAKEOVER CHECK via NSLOOKUP
# ─────────────────────────────────────────────────────────────
print("\n[*] 1. Checking CNAMEs and Subdomain Takeovers via nslookup...")

takeover_fingerprints = {
    "github.io": "There isn't a GitHub Pages site here",
    "s3.amazonaws.com": "The specified bucket does not exist",
    "aws": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "trafficmanager.net": "404 Not Found",
    "cloudapp.azure.com": "Azure",
    "cloudfront.net": "Bad request / The request could not be satisfied",
    "herokuapp.com": "No such app",
    "fastly.net": "Fastly error: unknown domain",
    "pantheonsite.io": "404 error unknown site",
    "zendesk.com": "Help Center Closed",
    "unbouncepages.com": "The requested URL was not found",
    "ghost.io": "The thing you were looking for is no longer here",
    "bitbucket.io": "Repository not found",
    "surge.sh": "project not found"
}

dangling_cnames = []

for domain in SCOPE:
    try:
        proc = subprocess.run(["nslookup", "-type=CNAME", domain], capture_output=True, text=True, timeout=3)
        out = proc.stdout
        cnames = []
        for line in out.splitlines():
            if "canonical name" in line.lower() or "aliases" in line.lower():
                parts = line.split("=")
                if len(parts) > 1:
                    cnames.append(parts[-1].strip().rstrip('.'))
        for cname in cnames:
            print(f"  CNAME: {domain} -> {cname}")
            for provider in takeover_fingerprints:
                if provider in cname:
                    print(f"    [!] Cloud Provider Target: {domain} -> {cname}")
                    try:
                        resp = client.get(f"https://{domain}")
                        for fp_prov, fp_text in takeover_fingerprints.items():
                            if fp_text.lower() in resp.text.lower():
                                print(f"        [CRITICAL TAKEOVER CONFIRMED!] Fingerprint: '{fp_text}'")
                                dangling_cnames.append({
                                    "target": domain,
                                    "cname": cname,
                                    "evidence": resp.text[:300]
                                })
                    except Exception as e:
                        pass
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
# 2. OPEN REDIRECT CHECKS
# ─────────────────────────────────────────────────────────────
print("\n[*] 2. Checking Open Redirect on redirect/shorturl/sensorfact assets...")
redirect_targets = [
    "shorturl.abb.com", "redirect.abb.com", "salestool.ch.abb.com", 
    "sensorfact.com", "sensorfact.nl", "sensorfact.tools", "sensorfact.de", "sensorfact.it"
]
redirect_params = ["url", "redirect", "next", "dest", "to", "return", "target", "r", "u", "link", "goto", "callback"]

open_redirects = []

for domain in redirect_targets:
    test_urls = [
        f"https://{domain}/",
        f"https://{domain}/redirect",
        f"https://{domain}/login",
        f"https://{domain}/out",
        f"https://{domain}/go",
        f"https://{domain}/auth",
    ]
    for base in test_urls:
        for p in redirect_params:
            for payload in ["https://evil.com", "//evil.com", "https:evil.com", "/\\evil.com"]:
                test_payload = f"{base}?{p}={payload}"
                try:
                    r = client.get(test_payload)
                    if r.status_code in [301, 302, 303, 307, 308]:
                        loc = r.headers.get("location", "")
                        if "evil.com" in loc:
                            print(f"  [CRITICAL OPEN REDIRECT!] {test_payload} -> Location: {loc}")
                            open_redirects.append({
                                "url": test_payload,
                                "location": loc,
                                "status": r.status_code
                            })
                except Exception:
                    pass

# ─────────────────────────────────────────────────────────────
# 3. JS SECRETS & HARDCODED CREDENTIALS
# ─────────────────────────────────────────────────────────────
print("\n[*] 3. Checking for sensitive tokens/keys in discovered JavaScript files...")
js_targets = [
    "https://rbook.abb.com",
    "https://rcm.motors.abb.com.cn",
    "https://qms.lmg.motion.abb.com.cn",
    "https://polaris.iam.motion.abb.com",
    "https://products.mo.cloudintegration.abb.com"
]

secret_patterns = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "JWT Token": r'eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]+',
    "Private Key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "Generic API Key": r'(?:api[_-]?key|auth[_-]?token|bearer[_-]?token|client[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
    "Internal Corporate URL": r'https?://[a-zA-Z0-9_\-\.]+\.(?:corp|internal|local|abb\.net)'
}

found_secrets = []

for base_url in js_targets:
    try:
        r = client.get(base_url)
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text)
        print(f"  Found {len(scripts)} scripts on {base_url}")
        for s in scripts:
            if not s.startswith("http"):
                s_url = base_url.rstrip("/") + "/" + s.lstrip("/")
            else:
                s_url = s
            try:
                js_resp = client.get(s_url)
                for name, pat in secret_patterns.items():
                    matches = re.findall(pat, js_resp.text, re.IGNORECASE)
                    if matches:
                        print(f"    [!] Potential Secret [{name}] in {s_url}: {matches[:3]}")
                        found_secrets.append({
                            "type": name,
                            "url": s_url,
                            "matches": matches[:3]
                        })
            except Exception:
                pass
    except Exception as e:
        print(f"  Error accessing {base_url}: {e}")

print("\n" + "="*80)
print("TRIAGE SUMMARY")
print(f"Dangling CNAMEs: {len(dangling_cnames)}")
print(f"Open Redirects : {len(open_redirects)}")
print(f"Secrets Found  : {len(found_secrets)}")
