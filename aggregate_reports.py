import json
import os
import sys
import glob

sys.stdout.reconfigure(encoding='utf-8')

# Aggregate all JSON reports in reports/
reports_dir = r'c:\Users\Maamoun\Downloads\antygravity\bug bounty\reports'
all_target_results = {}

for jp in glob.glob(os.path.join(reports_dir, 'abb_sensorfact_scope_report_*.json')):
    try:
        with open(jp, 'r', encoding='utf-8') as f:
            data = json.load(f)
            target_results = data.get('target_results', [])
            for tr in target_results:
                t = tr.get('target')
                findings = tr.get('findings', [])
                if findings:
                    if t not in all_target_results or len(findings) > len(all_target_results[t]):
                        all_target_results[t] = tr
    except Exception as e:
        print(f"Error reading {jp}: {e}")

print(f"Total unique targets with findings across all reports: {len(all_target_results)}")

all_findings = []
for t, tr in all_target_results.items():
    findings = tr.get('findings', [])
    print(f"\nTarget: {t} ({len(findings)} findings)")
    for f in findings:
        all_findings.append(f)
        sev = f.get('severity', 'UNKNOWN')
        vtype = f.get('vulnerability_type', 'unknown')
        url = f.get('target_url', '')
        desc = f.get('description', '')
        print(f"  [{sev:7s}] Type: {vtype:25s} | URL: {url}")

print(f"\nTotal aggregated findings: {len(all_findings)}")
