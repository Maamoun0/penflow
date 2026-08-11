import sqlite3
import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

print("="*80)
print("PENFLOW COMPREHENSIVE FINDINGS ANALYSIS & TRIAGE")
print("="*80)

# Check SQLite Database
db_path = r'c:\Users\Maamoun\Downloads\antygravity\bug bounty\penflow.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Check tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in cur.fetchall()]
    print(f"Database tables: {tables}")
    
    if "findings" in tables:
        cur.execute("SELECT count(*) FROM findings")
        cnt = cur.fetchone()[0]
        print(f"Total findings in DB: {cnt}")
        
        cur.execute("SELECT DISTINCT vulnerability_type, severity, count(*) FROM findings GROUP BY vulnerability_type, severity ORDER BY count(*) DESC")
        print("\nFindings Breakdown in DB:")
        for vtype, sev, c in cur.fetchall():
            print(f"  [{sev:8s}] {vtype:35s} : {c}")
            
        cur.execute("SELECT target_url, vulnerability_type, severity, cvss_score, description, evidence FROM findings WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM') LIMIT 30")
        sample_findings = cur.fetchall()
        print(f"\nSample High/Critical/Medium findings ({len(sample_findings)} shown):")
        for f in sample_findings:
            print("-" * 60)
            print(f"Target: {f[0]}")
            print(f"Type  : {f[1]} | Sev: {f[2]} | CVSS: {f[3]}")
            print(f"Desc  : {f[4][:150] if f[4] else ''}")
            print(f"Evid  : {f[5][:200] if f[5] else ''}")

# Check latest JSON report
reports_dir = r'c:\Users\Maamoun\Downloads\antygravity\bug bounty\reports'
json_reports = sorted([os.path.join(reports_dir, f) for f in os.listdir(reports_dir) if f.startswith('abb_sensorfact') and f.endswith('.json')])
print(f"\nFound {len(json_reports)} scope JSON reports:")
for r in json_reports:
    print(f"  {os.path.basename(r)} ({os.path.getsize(r):,} bytes)")

latest_json = json_reports[-1]
with open(latest_json, 'r', encoding='utf-8') as f:
    data = json.load(f)
    print(f"\nLatest report summary ({os.path.basename(latest_json)}):")
    print(f"  Total findings: {data.get('total_findings')}")
    print(f"  Severity: {data.get('findings_by_severity')}")
    print(f"  Types: {data.get('findings_by_type')}")
