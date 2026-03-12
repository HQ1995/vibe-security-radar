#!/usr/bin/env python3
"""Pattern analysis across audit findings.

Reads ~/.cache/cve-analyzer/audit/findings.json and reports:
  - Overall agreement rate
  - Disagreements by phase
  - Signal verification breakdown
  - Blame agreement breakdown
  - Vulnerability type breakdown and per-type accuracy
  - Improvement suggestion frequency
  - LLM/Tribunal failure mode diagnostics
"""

import json
from collections import Counter
from pathlib import Path


def main():
    findings = json.loads((Path.home() / '.cache/cve-analyzer/audit/findings.json').read_text())
    print(f'Total findings: {len(findings)}')

    # Agreement rate
    agree = sum(1 for f in findings if f.get('agreement'))
    print(f'Agreement rate: {agree}/{len(findings)} ({100*agree/len(findings):.0f}%)')

    # Disagreements by phase
    phases = Counter(f.get('disagreement_phase') for f in findings if not f.get('agreement'))
    print(f'Disagreements by phase: {dict(phases)}')

    # Signal type issues
    signals = Counter(f['stages'].get('signal_verification') for f in findings)
    print(f'Signal verification: {dict(signals)}')

    # Blame accuracy
    blames = Counter(f['stages'].get('blame_agreement') for f in findings)
    print(f'Blame agreement: {dict(blames)}')

    # Vulnerability type breakdown
    vtypes = Counter(f.get('vulnerability_type', 'unknown') for f in findings)
    print(f'Vulnerability types: {dict(vtypes)}')

    # Accuracy by vulnerability type
    for vtype in vtypes:
        vtype_findings = [f for f in findings if f.get('vulnerability_type', 'unknown') == vtype]
        vtype_agree = sum(1 for f in vtype_findings if f.get('agreement'))
        print(f'  {vtype}: {vtype_agree}/{len(vtype_findings)} agreement')

    # Improvement suggestion frequency
    all_suggestions = []
    for f in findings:
        for s in f.get('improvement_suggestions', []):
            cat = s.get('category', s) if isinstance(s, dict) else str(s)
            all_suggestions.append(cat)
    cats = Counter(all_suggestions)
    print(f'Improvement categories: {dict(cats)}')

    # LLM/Tribunal failure modes
    llm_diag = [f.get('llm_tribunal_diagnosis', {}) for f in findings if f.get('llm_tribunal_diagnosis')]
    if llm_diag:
        p1_wrong = sum(1 for d in llm_diag if not d.get('phase1_vuln_type_correct', True))
        fallbacks = sum(d.get('fallback_verdicts', 0) for d in llm_diag)
        truncation = sum(1 for d in llm_diag if d.get('diff_truncation_impact'))
        failure_modes = Counter()
        for d in llm_diag:
            if d.get('llm_failure_mode'):
                failure_modes[d['llm_failure_mode']] += 1
            for m in d.get('tribunal_failure_modes', []):
                failure_modes[m] += 1
        print(f'\nLLM/Tribunal diagnostics ({len(llm_diag)} findings):')
        print(f'  Phase 1 vuln type wrong: {p1_wrong}')
        print(f'  Fallback verdicts: {fallbacks}')
        print(f'  Truncation impact: {truncation}')
        if failure_modes:
            print(f'  Failure modes: {dict(failure_modes)}')


if __name__ == '__main__':
    main()
