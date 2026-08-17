"""
Batch File Upload Labs Audit Runner for PenFlow.
Executes scans against 7 PortSwigger File Upload Academy targets,
aggregates report summaries, and saves all individual & master reports.
"""
import os
import sys
import asyncio
import time
from datetime import datetime, timezone
from typing import List, Dict, Any

from penflow.app.web import execute_scan

LAB_TARGETS = [
    {"category": "File Upload", "name": "Lab 1", "url": "https://0a3f001a04a7493c88efac9100b000fe.web-security-academy.net/"},
    {"category": "File Upload", "name": "Lab 2", "url": "https://0a6400a60452e5b8814944d2002b0061.web-security-academy.net/"},
    {"category": "File Upload", "name": "Lab 3", "url": "https://0ac000a503088786811aa7640094008d.web-security-academy.net/"},
    {"category": "File Upload", "name": "Lab 4", "url": "https://0ad600f604575362811a0c73005800bc.web-security-academy.net/"},
    {"category": "File Upload", "name": "Lab 5", "url": "https://0a8f00c804e333ab80e1d04800b90079.web-security-academy.net/"},
    {"category": "File Upload", "name": "Lab 6", "url": "https://0aaa009803a87829814448940027008f.web-security-academy.net/"},
    {"category": "File Upload", "name": "Lab 7", "url": "https://0a5800ec03262eaa80d9858300820039.web-security-academy.net/"},
]

OUTPUT_DIR = os.path.join(os.getcwd(), "reports", "file_upload_batch")
os.makedirs(OUTPUT_DIR, exist_ok=True)

MASTER_REPORT_PATH = os.path.join(OUTPUT_DIR, "master_file_upload_report.md")

async def scan_single_lab(item: Dict[str, str], index: int, total: int) -> Dict[str, Any]:
    category = item["category"]
    name = item["name"]
    url = item["url"]
    clean_target = url.replace("https://", "").replace("http://", "").rstrip("/")

    print(f"\n[{index}/{total}] 🚀 Scanning {category} - {name}: {clean_target} ...")
    start_time = time.time()
    try:
        report_md = await execute_scan(target_domain=clean_target)
        elapsed = time.time() - start_time
        
        filename = f"lab_{index:02d}_{clean_target[:12]}.md"
        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_md)

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
        if verified_titles:
            print(f"       🎯 Detected: {', '.join(verified_titles)}")

        return {
            "index": index,
            "category": category,
            "name": name,
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
            "name": name,
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
    print(f"Starting PenFlow Multi-Agent Audit of {len(LAB_TARGETS)} File Upload Labs...")
    total = len(LAB_TARGETS)
    results = []

    for idx, item in enumerate(LAB_TARGETS, 1):
        res = await scan_single_lab(item, idx, total)
        results.append(res)

    print("\nCompiling Master Aggregated File Upload Report...")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    total_findings = sum(r["findings_count"] for r in results)
    total_crit = sum(r["critical"] for r in results)
    total_high = sum(r["high"] for r in results)
    total_med = sum(r["medium"] for r in results)
    total_low = sum(r["low"] for r in results)
    total_info = sum(r["info"] for r in results)

    master_lines = [
        "# 🛡️ PenFlow Comprehensive Security Assessment Report: File Upload Vulnerabilities",
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
        "| # | Lab # | Lab Target Host | Findings | Crit / High / Med / Low / Info | Key Certified Findings | Scan Time |",
        "|---|-------|-----------------|----------|--------------------------------|------------------------|-----------|",
    ]

    for r in results:
        sev_str = f"{r['critical']} / {r['high']} / {r['medium']} / {r['low']} / {r['info']}"
        titles_str = ", ".join(r['verified_titles'][:2]) or "Baseline Security Profile"
        master_lines.append(
            f"| {r['index']} | **{r['name']}** | `{r['target'][:20]}...` | **{r['findings_count']}** | `{sev_str}` | {titles_str} | {r['elapsed_sec']:.1f}s |"
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
            f"### Lab #{r['index']}: `{r['target']}`",
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

    artifact_master = r"C:\Users\Maamoun\.gemini\antigravity-ide\brain\beca9dce-ff66-4d71-88eb-13ae3287994e\master_file_upload_report.md"
    with open(artifact_master, "w", encoding="utf-8") as f:
        f.write("\n".join(master_lines))

    print(f"\n🎉 ALL FILE UPLOAD SCANS COMPLETE! Master report written to:\n- {MASTER_REPORT_PATH}\n- {artifact_master}")

if __name__ == "__main__":
    asyncio.run(run_all_scans())
