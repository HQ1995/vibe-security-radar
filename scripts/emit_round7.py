#!/usr/bin/env python3
"""Emit round7 18-key JSONL lines for a batch of cases.

Reads a data file (list of case dicts) and appends compact JSONL lines to
the target lane file. Each case dict must carry the 18 keys; helper fills
defaults. This is the serial main-session writer (no subagents).
"""
import json
import sys

from audit_record_gates import check_record

KEYS = [
    'class_id', 'case_id', 'repo', 'advisory_ids', 'bug_semantics',
    'flaw_origin', 'introducer_sha', 'introducer_parent',
    'introducer_parent_absent', 'squash_decomposed', 'decomposed_shas',
    'ai_marker', 'verdict', 'fix_sha', 'direct_fix_sha', 'evidence',
    'reasoning', 'remaining_gap',
]


def emit(cases: list, out_path: str) -> None:
    compact = dict(ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    with open(out_path, 'a') as f:
        for c in cases:
            line = {k: c.get(k) for k in KEYS}
            assert line['class_id'], 'missing class_id'
            assert line['verdict'] in {'NOT_AI', 'AI_ROOT_CAUSE', 'AI_CODE_FLAWED', 'BLOCKED', 'EVIDENCE_GAP'}, line['verdict']
            problems = check_record(line)
            if problems:
                raise SystemExit('audit_record_gates: ' + '; '.join(problems))
            f.write(json.dumps(line, **compact) + '\n')
            print(f"DONE {line['class_id']} {line['verdict']}")
    print(f"BATCH_COMPLETE {len(cases)} -> {out_path}")


if __name__ == '__main__':
    data_file, out_path = sys.argv[1], sys.argv[2]
    cases = json.load(open(data_file))
    emit(cases, out_path)
