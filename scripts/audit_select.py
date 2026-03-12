#!/usr/bin/env python3
"""CVE target selection for independent audit.

Selects an unaudited CVE from cached results, prioritizing:
  1. Tribunal-confirmed (on website, FP hurts credibility)
  2. Tribunal-overturned (tribunal said no but LLM said yes -- possible FN)
  3. Unverified (has AI signals, no tribunal yet)

Usage:
  audit_select.py              # auto-pick next unaudited CVE
  audit_select.py CVE-2025-1234  # use a specific CVE ID
"""

import argparse
import json
import os
import random
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Select a CVE target for audit")
    parser.add_argument("cve_id", nargs="?", default=None, help="Specific CVE ID to audit (optional)")
    args = parser.parse_args()

    if args.cve_id:
        print(args.cve_id)
        return

    cache = Path.home() / '.cache/cve-analyzer/results'
    audit_path = Path.home() / '.cache/cve-analyzer/audit/findings.json'

    # Load already-audited CVEs
    audited = set()
    if audit_path.exists():
        for f in json.loads(audit_path.read_text()):
            audited.add(f.get('cve_id', ''))

    # Bucket unaudited CVEs by priority
    tribunal_confirmed = []   # Priority 1: on website, FP hurts credibility
    tribunal_overturned = []  # Priority 2: tribunal said no but LLM said yes -- possible FN
    unverified = []           # Priority 3: has AI signals, no tribunal yet

    for f in sorted(cache.glob('*.json')):
        try:
            data = json.loads(f.read_text())
        except:
            continue
        cve_id = data.get('cve_id', f.stem)
        if cve_id in audited:
            continue
        if data.get('error'):
            continue

        ai_bics = [b for b in data.get('bug_introducing_commits', [])
                    if b.get('commit', {}).get('ai_signals')]
        if not ai_bics:
            continue

        has_tribunal_confirmed = any(
            (b.get('tribunal_verdict') or {}).get('final_verdict', '').upper() == 'CONFIRMED'
            for b in ai_bics)
        has_tribunal_denied = any(
            (b.get('tribunal_verdict') or {}).get('final_verdict', '').upper() in ('UNLIKELY', 'UNRELATED')
            for b in ai_bics)
        has_llm_confirmed = any(
            (b.get('llm_verdict') or {}).get('verdict', '').upper() == 'CONFIRMED'
            for b in ai_bics)

        if has_tribunal_confirmed:
            tribunal_confirmed.append(cve_id)
        elif has_tribunal_denied and has_llm_confirmed:
            tribunal_overturned.append(cve_id)
        elif has_llm_confirmed:
            unverified.append(cve_id)

    random.shuffle(tribunal_confirmed)
    random.shuffle(tribunal_overturned)
    random.shuffle(unverified)

    print(f'Unaudited: {len(tribunal_confirmed)} tribunal-confirmed, {len(tribunal_overturned)} overturned, {len(unverified)} unverified')
    pick = (tribunal_confirmed or tribunal_overturned or unverified or [None])[0]
    if pick:
        print(f'Selected: {pick}')
    else:
        print('Nothing to audit.')


if __name__ == '__main__':
    main()
