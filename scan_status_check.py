import sys, os
sys.stdout.reconfigure(encoding='utf-8')

log_path = r'C:\Users\Maamoun\.gemini\antigravity-ide\brain\b0e71b1e-044a-409e-9cec-9f87ea2f6200\.system_generated\tasks\task-116.log'
with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

live = 0
dead = 0
findings_total = 0
cur = ''
targets_done = []
complete = False

for line in lines:
    l = line.strip()
    if '[SCANNING]' in l:
        cur = l.split('[SCANNING]')[-1].strip()
    elif '[+] LIVE' in l:
        live += 1
    elif '[-] DEAD' in l:
        dead += 1
    elif 'Verified findings:' in l:
        try:
            n = int(l.split('Verified findings:')[-1].strip())
            findings_total += n
            targets_done.append((cur, n))
        except:
            pass
    elif 'SCOPE SCAN' in l and 'COMPLETE' in l:
        complete = True

status = 'COMPLETE' if complete else 'RUNNING'
print(f'Log lines   : {len(lines)}')
print(f'Status      : {status}')
print(f'Scanned     : {live + dead}/100')
print(f'Live        : {live}')
print(f'Dead        : {dead}')
print(f'Findings    : {findings_total}')
print(f'Current     : {cur}')
print()
print('=== Per-Target Findings ===')
for t, n in targets_done:
    print(f'  [{n:3d}] {t}')

# Check report files
reports_dir = r'c:\Users\Maamoun\Downloads\antygravity\bug bounty\reports'
print()
print('=== Report Files ===')
if os.path.exists(reports_dir):
    rpts = [f for f in os.listdir(reports_dir) if 'abb_sensorfact' in f]
    for r in sorted(rpts):
        size = os.path.getsize(os.path.join(reports_dir, r))
        print(f'  {r} ({size} bytes)')
    if not rpts:
        print('  (no report generated yet)')
