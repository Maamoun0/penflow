import sys, os
sys.stdout.reconfigure(encoding='utf-8')

path = r'C:\Users\Maamoun\.gemini\antigravity-ide\brain\b0e71b1e-044a-409e-9cec-9f87ea2f6200\.system_generated\tasks\task-224.log'
with open(path, 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

live=0; dead=0; skip=0; findings_total=0; cur=''; timeout_count=0
targets_done=[]; complete=False

for line in lines:
    l = line.strip()
    if '[SCANNING]' in l and not l.startswith('{'):
        cur = l.split('[SCANNING]')[-1].strip()
    elif '[SKIP]' in l:
        skip += 1
    elif '[TIMEOUT]' in l:
        timeout_count += 1
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
    elif 'COMPLETE' in l and 'SCOPE SCAN' in l:
        complete = True

status = 'COMPLETE' if complete else 'RUNNING'
print(f'Status      : {status}')
print(f'Log lines   : {len(lines)}')
print(f'Skipped     : {skip}')
print(f'Live        : {live}')
print(f'Dead        : {dead}')
print(f'Timeouts    : {timeout_count}')
print(f'New Findings: {findings_total}')
print(f'Current     : {cur}')

if targets_done:
    print()
    print('=== New findings per target ===')
    for t, n in targets_done:
        bar = '#' * min(n, 40)
        print(f'  [{n:3d}] {bar} {t}')

# Check latest report
reports_dir = r'c:\Users\Maamoun\Downloads\antygravity\bug bounty\reports'
if os.path.exists(reports_dir):
    rpts = sorted([f for f in os.listdir(reports_dir) if f.endswith('.md')])
    print()
    print('=== Report Files ===')
    for r in rpts:
        size = os.path.getsize(os.path.join(reports_dir, r))
        print(f'  {r}  ({size:,} bytes)')

if complete:
    print()
    print('>>> SCAN COMPLETE — Reading latest report...')
    if rpts:
        latest = os.path.join(reports_dir, rpts[-1])
        with open(latest, 'r', encoding='utf-8', errors='replace') as f:
            print(f.read())
