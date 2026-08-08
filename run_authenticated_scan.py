"""
PenFlow Phase 2 — Authenticated Scan Runner
==========================================
How to use:
1. Fill config/identities.yaml with real credentials for the target
2. Set TARGET_BASE_URL to the target domain
3. Run: python run_authenticated_scan.py
"""
import asyncio
import sys
import json
import os
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8')

# ─────────────────────────────────────────────────────────────
# CONFIGURATION — Edit these before running
# ─────────────────────────────────────────────────────────────

TARGET_BASE_URL = "https://rcm.motors.abb.com.cn"  # Change to your target

# Endpoints discovered from JS analysis (from scan phase)
ENDPOINTS_TO_TEST = [
    "/api/services/app/Permission/GetMyOrgAssociatedAccount",
    "/api/services/app/Permission/GetAllPermissionsByRoleId",
    "/api/services/app/Permission/UpdatePermission",
    "/api/services/app/User/GetOrgUserById",
    "/api/services/app/User/GetAll",
    "/api/services/app/User/GetOrgUserById",
    "/api/services/app/Permission/GetPermissionTree",
    "/api/services/app/Role/GetAll",
    "/api/services/app/Account/GetAll",
    "/api/tokenauth/authenticate",
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/me",
    "/api/account",
    "/api/v1/users",
    "/api/v1/me",
    "/api/v1/profile",
]

# Profile endpoints to test Mass Assignment
PROFILE_ENDPOINTS = [
    "/api/profile",
    "/api/me",
    "/api/services/app/User/UpdateUser",
    "/api/account",
    "/api/v1/profile",
]

# ─────────────────────────────────────────────────────────────

async def main():
    print("="*70)
    print("PENFLOW PHASE 2 — AUTHENTICATED IDOR & BFLA SCANNER")
    print("="*70)
    print(f"Target: {TARGET_BASE_URL}")
    print(f"Endpoints: {len(ENDPOINTS_TO_TEST)}")
    print()

    # Import Phase 2 engines
    from penflow.auth.account_pool import AccountPool
    from penflow.auth.idor_authenticated_engine import IDORAuthenticatedEngine
    from penflow.auth.bfla_authenticated_engine import BFLAAuthenticatedEngine

    # Initialize with the config
    pool = AccountPool(config_path="config/identities.yaml")

    print("[*] Accounts loaded:")
    for acc_id, acc in pool.accounts.items():
        print(f"    [{acc_id}] {acc.username} (role={acc.role}, type={acc.auth_type})")
    print()

    # ─── IDOR SCAN ───────────────────────────────────────────
    print("[1/2] Running IDOR Scan (User A vs User B cross-account access)...")
    idor_engine = IDORAuthenticatedEngine(account_pool=pool)
    idor_results = await idor_engine.run_idor_scan(
        base_url=TARGET_BASE_URL,
        endpoints=ENDPOINTS_TO_TEST,
        user_a_id="authenticated_user_a",
        user_b_id="authenticated_user_b",
    )

    print()
    print(f"IDOR Results: {idor_results.get('total_vulnerable', 0)} vulnerable / {idor_results.get('endpoints_tested', 0)} tested")
    if idor_results.get("vulnerable_findings"):
        print("\n🔴 IDOR VULNERABILITIES FOUND:")
        for f in idor_results["vulnerable_findings"]:
            print(f"  URL      : {f['url']}")
            print(f"  Confidence: {f['confidence']:.0%}")
            print(f"  Reasoning: {f['reasoning']}")
            print(f"  A Status : {f['user_a_status']} | B Status: {f['user_b_status']} | Guest: {f['guest_status']}")
            print()
    elif not idor_results.get("authenticated"):
        print(f"\n⚠️  Authentication failed: {idor_results.get('error')}")
        print("   → Update config/identities.yaml with real credentials")
    else:
        print("  → No IDOR found (all endpoints properly authorized)")

    # ─── BFLA SCAN ───────────────────────────────────────────
    print("\n[2/2] Running BFLA Scan (Standard user vs Admin functions)...")
    bfla_engine = BFLAAuthenticatedEngine(account_pool=pool)
    bfla_results = await bfla_engine.run_bfla_scan(
        base_url=TARGET_BASE_URL,
        endpoints=ENDPOINTS_TO_TEST,
        profile_endpoints=PROFILE_ENDPOINTS,
        standard_user_id="authenticated_user_b",
    )

    print()
    print(f"BFLA Results: {bfla_results.get('total_vulnerable', 0)} vulnerable / {bfla_results.get('endpoints_tested', 0)} tested")
    if bfla_results.get("vulnerable_findings"):
        print("\n🔴 BFLA VULNERABILITIES FOUND:")
        for f in bfla_results["vulnerable_findings"]:
            print(f"  Type     : {f['type']}")
            print(f"  URL      : {f['url']}")
            print(f"  Confidence: {f['confidence']:.0%}")
            print(f"  Reasoning: {f['reasoning']}")
            print()
    elif not bfla_results.get("findings") and not bfla_results.get("error"):
        print("  → No BFLA found (authorization properly enforced)")

    # ─── SAVE RESULTS ────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"reports/authenticated_scan_{timestamp}.json"
    os.makedirs("reports", exist_ok=True)

    combined = {
        "target": TARGET_BASE_URL,
        "timestamp": timestamp,
        "idor": idor_results,
        "bfla": bfla_results,
        "summary": {
            "total_idor": idor_results.get("total_vulnerable", 0),
            "total_bfla": bfla_results.get("total_vulnerable", 0),
        }
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(combined, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*70}")
    print(f"Scan complete. Results saved: {output_file}")
    print(f"IDOR Findings: {idor_results.get('total_vulnerable', 0)}")
    print(f"BFLA Findings: {bfla_results.get('total_vulnerable', 0)}")

asyncio.run(main())
