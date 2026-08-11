import sys
import os
import json
import re

sys.stdout.reconfigure(encoding='utf-8')

log_path = r'C:\Users\Maamoun\.gemini\antigravity-ide\brain\b0e71b1e-044a-409e-9cec-9f87ea2f6200\.system_generated\tasks\task-116.log'

findings_by_target = {}
cur_target = None

with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        l = line.strip()
        if '[SCANNING]' in l and not l.startswith('{'):
            cur_target = l.split('[SCANNING]')[-1].strip()
            if cur_target not in findings_by_target:
                findings_by_target[cur_target] = []
        elif l.startswith('{'):
            try:
                d = json.loads(l)
                msg = d.get('message', '')
                component = d.get('component', '')
                # Check for agent findings
                if 'finding' in msg.lower() or 'vulnerability' in msg.lower() or 'discovered' in msg.lower() or 'flagged' in msg.lower():
                    if cur_target:
                        findings_by_target[cur_target].append((component, msg))
            except:
                pass

print("Summary of logged discoveries / findings in task-116:")
for t, msgs in findings_by_target.items():
    if msgs:
        print(f"\nTarget: {t} ({len(msgs)} events)")
        for comp, m in msgs[:10]:
            print(f"  [{comp}] {m[:140]}")
        if len(msgs) > 10:
            print(f"  ... and {len(msgs)-10} more events")
