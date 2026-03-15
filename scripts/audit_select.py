#!/usr/bin/env python3
"""CVE target selection for independent audit.

Selects an unaudited CVE from cached results, prioritizing:
  1. Verifier-confirmed (on website, FP hurts credibility)
  2. Verifier-overturned (verifier said no but LLM said yes -- possible FN)
  3. Unverified (has AI signals, no deep verification yet)

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

    def _get_deep_verdict(bic):
        vv = bic.get('deep_verification') or bic.get('verification_verdict')
        if vv:
            if 'final_verdict' not in vv and 'verdict' in vv:
                return {**vv, 'final_verdict': vv['verdict']}
            return vv
        return bic.get('tribunal_verdict')

    # Bucket unaudited CVEs by priority
    verified_confirmed = []   # Priority 1: on website, FP hurts credibility
    verified_overturned = []  # Priority 2: verifier said no but LLM said yes -- possible FN
    unverified = []           # Priority 3: has AI signals, no deep verification yet

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

        has_verified_confirmed = any(
            (_get_deep_verdict(b) or {}).get('final_verdict', '').upper() == 'CONFIRMED'
            for b in ai_bics)
        has_verified_denied = any(
            (_get_deep_verdict(b) or {}).get('final_verdict', '').upper() in ('UNLIKELY', 'UNRELATED')
            for b in ai_bics)
        has_llm_confirmed = any(
            (b.get('screening_verification') or b.get('llm_verdict') or {}).get('verdict', '').upper() == 'CONFIRMED'
            for b in ai_bics)

        if has_verified_confirmed:
            verified_confirmed.append(cve_id)
        elif has_verified_denied and has_llm_confirmed:
            verified_overturned.append(cve_id)
        elif has_llm_confirmed:
            unverified.append(cve_id)

    random.shuffle(verified_confirmed)
    random.shuffle(verified_overturned)
    random.shuffle(unverified)

    print(f'Unaudited: {len(verified_confirmed)} verified-confirmed, {len(verified_overturned)} overturned, {len(unverified)} unverified')
    pick = (verified_confirmed or verified_overturned or unverified or [None])[0]
    if pick:
        print(f'Selected: {pick}')
    else:
        print('Nothing to audit.')


if __name__ == '__main__':
    main()
