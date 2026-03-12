#!/usr/bin/env python3
"""Aggregate recurring improvement issues from prior audit findings.

Reads ~/.cache/cve-analyzer/audit/findings.json and summarizes suggestion
categories and recurring issues across all audits.
"""

import json
from collections import Counter
from pathlib import Path


def main():
    audit_path = Path.home() / '.cache/cve-analyzer/audit/findings.json'
    if not audit_path.exists():
        print('No prior findings.')
        return

    findings = json.loads(audit_path.read_text())
    cats = Counter()
    recurring = []
    for f in findings:
        for s in f.get('improvement_suggestions', []):
            if isinstance(s, dict):
                cats[s.get('category', '?')] += 1
                if s.get('recurring'):
                    recurring.append(f'{s["category"]}: {s["description"][:80]}...')

    print(f'Suggestion categories across {len(findings)} audits: {dict(cats)}')
    if recurring:
        print(f'\nRecurring issues ({len(recurring)}):')
        for r in recurring:
            print(f'  - {r}')


if __name__ == '__main__':
    main()
