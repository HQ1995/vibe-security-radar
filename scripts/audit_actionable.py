#!/usr/bin/env python3
"""Identify actionable pipeline improvements from audit findings.

Groups recurring improvement suggestions by (category, affected_file) and
surfaces those that are HIGH severity or have occurred >= 3 times.
"""

import json
from collections import defaultdict
from pathlib import Path


def main():
    findings = json.loads((Path.home() / '.cache/cve-analyzer/audit/findings.json').read_text())

    # Group recurring suggestions by (category, affected_file)
    groups = defaultdict(lambda: {'count': 0, 'severity': 'LOW', 'descriptions': [], 'cve_ids': []})
    for f in findings:
        for s in f.get('improvement_suggestions', []):
            if not isinstance(s, dict):
                continue
            if not s.get('recurring'):
                continue
            key = (s.get('category', ''), s.get('affected_file', ''))
            groups[key]['count'] += 1
            groups[key]['descriptions'].append(s['description'][:100])
            groups[key]['cve_ids'].append(f['cve_id'])
            if s.get('severity') == 'HIGH':
                groups[key]['severity'] = 'HIGH'
            elif s.get('severity') == 'MEDIUM' and groups[key]['severity'] != 'HIGH':
                groups[key]['severity'] = 'MEDIUM'

    # Actionable = HIGH severity OR count >= 3
    actionable = {k: v for k, v in groups.items() if v['severity'] == 'HIGH' or v['count'] >= 3}
    if not actionable:
        print('No actionable improvements yet.')
        return

    for (cat, file), info in sorted(actionable.items(), key=lambda x: -x[1]['count']):
        print(f'{info["severity"]:6s} x{info["count"]} {cat} in {file}')
        for d in info['descriptions'][:2]:
            print(f'       {d}')
        print(f'       CVEs: {", ".join(info["cve_ids"])}')


if __name__ == '__main__':
    main()
