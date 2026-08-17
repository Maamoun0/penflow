"""
Batch Lab Evaluation Runner for PenFlow.
Executes scans against PortSwigger Academy targets across categories,
aggregates report summaries, and saves all reports.
"""
import os
import sys
import asyncio
import time
from datetime import datetime, timezone
from typing import List, Dict, Any

from penflow.app.web import execute_scan

LAB_TARGETS = [
    # 1. XSS
    {"category": "XSS", "url": "https://0a1c00c40345113080937bce0027000e.web-security-academy.net/"},
    {"category": "XSS", "url": "https://0a9200b803db27a582b2dd65009f00c6.web-security-academy.net/"},
    {"category": "XSS", "url": "https://0a4f001f039f896081e52a0100c50042.web-security-academy.net/"},
    {"category": "XSS", "url": "https://0a5d00ab046fdbad815c028e0056007c.web-security-academy.net/"},

    # 2. Web Cache Deception
    {"category": "Web Cache Deception", "url": "https://0a9b00b20469e9e1816e6b8d0087002c.web-security-academy.net/"},
    {"category": "Web Cache Deception", "url": "https://0ae7001203cdad9c80816225001800b7.web-security-academy.net/"},
    {"category": "Web Cache Deception", "url": "https://0a6b008903b8875a81b5936a001f00e9.web-security-academy.net/"},
    {"category": "Web Cache Deception", "url": "https://0a6400d9041776a180fb99aa007e00c5.web-security-academy.net/"},
    {"category": "Web Cache Deception", "url": "https://0ab7001403316d0f80e1ad2100b7005d.web-security-academy.net/"},

    # 3. API Testing
    {"category": "API Testing", "url": "https://0aaa00a1046860e082ba494f004b0094.web-security-academy.net/"},
    {"category": "API Testing", "url": "https://0ae40050038570fa82946012000600ae.web-security-academy.net/"},
    {"category": "API Testing", "url": "https://0afa003a03a588b881d584b1003d0045.web-security-academy.net/"},

    # 4. NoSQL Injection
    {"category": "NoSQL Injection", "url": "https://0ad700d404bc292288dd14790018000d.web-security-academy.net/"},
    {"category": "NoSQL Injection", "url": "https://0a450057039a75e18049c66500ec0039.web-security-academy.net/"},
    {"category": "NoSQL Injection", "url": "https://0abf007b038a5b9d8168343800510070.web-security-academy.net/"},
    {"category": "NoSQL Injection", "url": "https://0ac600130357d931815d5840006700b6.web-security-academy.net/"},

    # 5. Server-Side Request Forgery (SSRF)
    {"category": "SSRF", "url": "https://0a2d005e0490abeb815949700004006e.web-security-academy.net/"},
    {"category": "SSRF", "url": "https://0a1d005603da1b4880b33f4a006e0073.web-security-academy.net/"},
    {"category": "SSRF", "url": "https://0a4b009003e8f87a8732a31500980081.web-security-academy.net/"},
    {"category": "SSRF", "url": "https://0a49001f045e920a803b7156001300f4.web-security-academy.net/"},
    {"category": "SSRF", "url": "https://0a8f006204ca706680a8f3a0003e00c9.web-security-academy.net/"},

    # 6. Race Conditions
    {"category": "Race Conditions", "url": "https://0ae70092040ff9b181e0d94400b8006a.web-security-academy.net/"},
    {"category": "Race Conditions", "url": "https://0ae70096030f83108085581d00fe00a9.web-security-academy.net/"},
    {"category": "Race Conditions", "url": "https://0a8a00f703ce93d282ce5c50004000e5.web-security-academy.net/"},
    {"category": "Race Conditions", "url": "https://0a1600e503cc3168801e21aa004300d1.web-security-academy.net/"},
    {"category": "Race Conditions", "url": "https://0ace0076037e20cc81cba7f00033003d.web-security-academy.net/"},
    {"category": "Race Conditions", "url": "https://0a29006e03e2086f82942fc10075007c.web-security-academy.net/"},
]

OUTPUT_DIR = os.path.join(os.getcwd(), "reports", "batch_1")
os.makedirs(OUTPUT_DIR, exist_ok=True)

MASTER_REPORT_PATH = os.path.join(OUTPUT_DIR, "master_batch_1_report.md")

async def scan_single_lab(item: Dict[str, str], index: int, total: int) -> Dict[str, Any]:
    category = item["category"]
    url = item["url"]
    clean_target = url.replace("https://", "").replace("http://", "").rstrip("/")

    print(f"\n[{index}/{total}] 🚀 Scanning {category} Lab: {clean_target} ...")
    start_time = time.time()
    try:
        report_md = await execute_scan(target_domain=clean_target)
        elapsed = time.time() - start_time
        
        # Save individual report
        filename = f"lab_{index:02d}_{category.lower().replace(' ', '_')}_{clean_target[:12]}.md"
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_md)

        # Parse key metrics from report
        lines = report_md.splitlines()
        findings_count = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
        verified_titles = []

        for line in lines:
            if "| **Total Findings** |" in line:
                try: findings_count = int(line.split("|")[2].strip())
                except: pass
            elif "| **Critical** |" in line:
                try: critical = int(line.split("|")[2].strip())
                except: pass
            elif "| **High** |" in line:
                try: high = int(line.split("|")[2].strip())
                except: pass
            elif "| **Medium** |" in line:
                try: medium = int(line.split("|")[2].strip())
                except: pass
            elif "| **Low** |" in line:
                try: low = int(line.split("|")[2].strip())
                except: pass
            elif "| **Informative** |" in line:
                try: info = int(line.split("|")[2].strip())
                except: pass
            elif line.startswith("### 🔴 Finding #") or line.startswith("### 🟠 Finding #") or line.startswith("### 🟡 Finding #") or line.startswith("### 🟢 Finding #"):
                title = line.split(":", 1)[-1].strip() if ":" in line else line
                verified_titles.append(title)

        print(f"[{index}/{total}] ✅ COMPLETED in {elapsed:.1f}s | Findings: {findings_count} (Crit:{critical}, High:{high}, Med:{medium}, Low:{low}, Info:{info})")
        
        return {
            "index": index,
            "category": category,
            "target": clean_target,
            "url": url,
            "elapsed_sec": elapsed,
            "findings_count": findings_count,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "verified_titles": verified_titles,
            "report_file": filename,
            "full_report_md": report_md,
            "status": "SUCCESS"
        }
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[{index}/{total}] ❌ ERROR scanning {clean_target}: {e}")
        return {
            "index": index,
            "category": category,
            "target": clean_target,
            "url": url,
            "elapsed_sec": elapsed,
            "findings_count": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "verified_titles": [],
            "report_file": "",
            "full_report_md": f"# Error scanning {clean_target}\n\n{e}",
            "status": f"ERROR: {e}"
        }

async def run_all_scans():
    print(f"Starting PenFlow Multi-Agent Audit of {len(LAB_TARGETS)} PortSwigger Labs...")
    total = len(LAB_TARGETS)
    results = []

    # Run in sequential or mini-batch (to avoid overloading external network and lab containers)
    for idx, item in enumerate(LAB_TARGETS, 1):
        res = await scan_single_lab(item, idx, total)
        results.append(res)

    # Generate Master Aggregated Markdown Report
    print("\nCompiling Master Aggregated Report...")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    total_findings = sum(r["findings_count"] for r in results)
    total_crit = sum(r["critical"] for r in results)
    total_high = sum(r["high"] for r in results)
    total_med = sum(r["medium"] for r in results)
    total_low = sum(r["low"] for r in results)
    total_info = sum(r["info"] for r in results)

    master_lines = [
        "# 🛡️ PenFlow Comprehensive Batch Security Assessment Report (Batch #1)",
        "",
        f"**Date**: `{now_str}`  ",
        f"**Platform**: `PenFlow SROS v1.0`  ",
        f"**Total Labs Audited**: `{len(results)}`  ",
        f"**Overall Certified Findings**: `{total_findings}` (🔴 Critical: `{total_crit}`, 🟠 High: `{total_high}`, 🟡 Medium: `{total_med}`, 🟢 Low: `{total_low}`, ⚪ Informative: `{total_info}`)  ",
        "",
        "---",
        "",
        "## 📊 Executive Summary Table",
        "",
        "| # | Category | Lab Target Host | Findings | Crit / High / Med / Low / Info | Key Certified Findings | Scan Time |",
        "|---|----------|-----------------|----------|--------------------------------|------------------------|-----------|",
    ]

    for r in results:
        sev_str = f"{r['critical']} / {r['high']} / {r['medium']} / {r['low']} / {r['info']}"
        titles_str = ", ".join(r['verified_titles'][:2]) or "Baseline Security Profile"
        master_lines.append(
            f"| {r['index']} | **{r['category']}** | `{r['target'][:20]}...` | **{r['findings_count']}** | `{sev_str}` | {titles_str} | {r['elapsed_sec']:.1f}s |"
        )

    master_lines.extend([
        "",
        "---",
        "",
        "## 📑 Detailed Assessment per Lab Target",
        ""
    ])

    for r in results:
        master_lines.extend([
            f"### Lab #{r['index']}: [{r['category']}] `{r['target']}`",
            "",
            f"- **URL**: {r['url']}",
            f"- **Findings**: `{r['findings_count']}` (Critical: {r['critical']}, High: {r['high']}, Medium: {r['medium']}, Low: {r['low']}, Info: {r['info']})",
            f"- **Scan Time**: `{r['elapsed_sec']:.1f}s`",
            "",
            "#### Full Verification Report",
            "",
            r["full_report_md"],
            "",
            "---",
            ""
        ])

    with open(MASTER_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(master_lines))

    # Also copy to artifact directory
    artifact_master = r"C:\Users\Maamoun\.gemini\antigravity-ide\brain\beca9dce-ff66-4d71-88eb-13ae3287994e\master_batch_1_report.md"
    with open(artifact_master, "w", encoding="utf-8") as f:
        f.write("\n".join(master_lines))

    print(f"\n🎉 ALL SCANS COMPLETE! Master report written to:\n- {MASTER_REPORT_PATH}\n- {artifact_master}")

if __name__ == "__main__":
    asyncio.run(run_all_scans())
