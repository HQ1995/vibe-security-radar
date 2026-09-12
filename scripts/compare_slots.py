#!/usr/bin/env python3
"""Compare two independent audit slots over the same batch.

Two blind audits of one batch disagree where the two briefs asked for
different fields, or where a rule lived only in prose. This prints that
comparison, so the drift is one command instead of a hand diff.

Usage:
  python3 scripts/compare_slots.py --a research/<batch>/review \\
      --b research/<batch>/verify/cases [--json report.json] [--probe-git]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_record_gates import AI_VERDICTS, check_record_strict, review_signals

SKIP = re.compile(r"INDEX|manifest|selection|summary|excluded", re.I)
SQUASH_SUBJECT = re.compile(r"\(#\d+\)$")
FLAG_KINDS = (
    ("advisory_dead_vs_verdict", "but verdict is"),
    ("advisory_disposition", "advisory_disposition"),
    ("atomic_vs_landing", "is its own landing commit"),
    ("bic_granularity", "bic_granularity"),
    ("squash_decomposition", "SQUASH_DECOMPOSED requires"),
    ("decomposition_probe", "AGGREGATE_MEMBERS_UNREACHABLE requires"),
    ("non_git_boundary", "NON_GIT_BOUNDARY requires"),
    ("flip_condition", "requires flip_condition"),
    ("fix_ai_marker", "fix_ai_marker.state"),
    ("ai_on_bic_type", "ai_on_bic must be a JSON boolean"),
    ("ai_verdict_marker", "needs ai_on_bic true"),
    ("not_ai_vs_ai_on_bic", "NOT_AI contradicts"),
)
GIT_ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}


def load(path: Path) -> dict[str, dict]:
    files = sorted(path.rglob('*.json')) if path.is_dir() else [path]
    records: dict[str, dict] = {}
    for file in files:
        if SKIP.search(file.name):
            continue
        try:
            record = json.loads(file.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(record, dict) and 'verdict' in record:
            records[str(record.get('class_id') or file.stem)] = record
    return records


def sha(value) -> str:
    return str(value).lower() if isinstance(value, str) and value.strip() else ''


def view(record: dict) -> dict:
    """One shape for both slots: new fields win, older ones map onto them."""
    members = record.get('decomposed_shas') or record.get('candidate_set') or []
    return {
        'verdict': record.get('verdict'),
        'bic': sha(record.get('introducer_sha')),
        'fix': sha(record.get('fix_sha')) or sha(record.get('direct_fix_sha')),
        'landing': sha(record.get('landing_commit')),
        'members': [sha(m) for m in members if isinstance(m, str) and sha(m)],
        'flip': bool(str(record.get('flip_condition') or '').strip())
        or bool(re.search(r'\bflip', str(record.get('reasoning') or ''), re.I)),
        'ai_on_bic': record.get('ai_on_bic')
        if isinstance(record.get('ai_on_bic'), bool)
        else None,
        'gap': str(record.get('remaining_gap') or '').strip(),
    }


def flag_kind(message: str) -> str:
    for kind, needle in FLAG_KINDS:
        if needle in message:
            return kind
    return 'other'


def squash_shape(value: str, clone: str) -> str:
    """squash / merge / atomic / unknown for one commit object, probed in git."""
    if not (value and clone):
        return 'unknown'
    try:
        done = subprocess.run(
            ['git', '-C', clone, 'show', '-s', '--format=%H %P%n%cn <%ce>%n%s', value],
            capture_output=True, text=True, timeout=30, env=GIT_ENV, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 'unknown'
    lines = done.stdout.splitlines()
    if done.returncode or len(lines) < 3:
        return 'unknown'
    if len(lines[0].split()[1:]) > 1:
        return 'merge'
    if 'noreply@github.com' in lines[1] or SQUASH_SUBJECT.search(lines[2]):
        return 'squash'
    return 'atomic'


def compare(a_path: Path, b_path: Path, probe_git: bool = False) -> dict:
    a_raw, b_raw = load(a_path), load(b_path)
    a = {key: view(record) for key, record in a_raw.items()}
    b = {key: view(record) for key, record in b_raw.items()}
    shared = sorted(set(a) & set(b))

    verdicts = {}
    for name, slot in (('a', a), ('b', b)):
        verdicts[name] = dict(collections.Counter(v['verdict'] for v in slot.values()))

    disagreements = [key for key in shared if a[key]['verdict'] != b[key]['verdict']]
    tp = sorted(
        key for key in shared
        if a[key]['verdict'] in AI_VERDICTS or b[key]['verdict'] in AI_VERDICTS
    )

    bic_same = [key for key in shared if a[key]['bic'] and a[key]['bic'] == b[key]['bic']]
    bic_differ = [
        key for key in shared
        if a[key]['bic'] and b[key]['bic'] and a[key]['bic'] != b[key]['bic']
    ]
    kinds = collections.Counter()
    for key in bic_differ:
        left, right = a[key], b[key]
        if left['bic'] in right['members']:
            kinds['a_bic_is_b_member'] += 1
        elif right['bic'] in left['members']:
            kinds['b_bic_is_a_member'] += 1
        elif right['landing'] == left['bic']:
            kinds['a_bic_is_b_landing'] += 1
        elif left['landing'] == right['bic']:
            kinds['b_bic_is_a_landing'] += 1
        else:
            kinds['unexplained'] += 1

    fix_differ = [
        key for key in shared
        if a[key]['fix'] and b[key]['fix'] and a[key]['fix'] != b[key]['fix']
    ]
    presence = {}
    for field, getter in (
        ('flip_condition', lambda raw: bool(str(raw.get('flip_condition') or '').strip())),
        ('flip (field or prose)', lambda raw: view(raw)['flip']),
        ('bic_granularity', lambda raw: bool(raw.get('bic_granularity'))),
        ('decomposition evidence', lambda raw: bool(
            raw.get('decomposed_shas')
            or raw.get('decomposition_probe')
            or raw.get('squash_decomposed') is not None
        )),
        ('advisory_disposition', lambda raw: bool(raw.get('advisory_disposition'))),
        ('ai_admissibility', lambda raw: bool(raw.get('ai_admissibility'))),
        ('ai_on_bic boolean', lambda raw: isinstance(raw.get('ai_on_bic'), bool)),
    ):
        presence[field] = [
            sum(1 for raw in (a_raw, b_raw)[i].values() if getter(raw))
            for i in (0, 1)
        ]

    flags, signals = {}, {}
    for name, raw in (('a', a_raw), ('b', b_raw)):
        counter = collections.Counter()
        by_kind = collections.defaultdict(list)
        for key, record in raw.items():
            for message in check_record_strict(record):
                counter[flag_kind(message)] += 1
            for message in review_signals(record):
                kind = 'ai_disclosure_claim' if 'claims' in message else 'residual_open_surface'
                by_kind[kind].append(key)
        flags[name] = dict(counter)
        signals[name] = {kind: sorted(ids) for kind, ids in by_kind.items()}

    report = {
        'a': {'path': str(a_path), 'records': len(a_raw)},
        'b': {'path': str(b_path), 'records': len(b_raw)},
        'shared': len(shared),
        'only_a': sorted(set(a) - set(b)),
        'only_b': sorted(set(b) - set(a)),
        'verdicts': verdicts,
        'verdict_agreement': len(shared) - len(disagreements),
        'verdict_disagreements': [
            {'class_id': key, 'a': a[key]['verdict'], 'b': b[key]['verdict']}
            for key in disagreements
        ],
        'tp': [
            {'class_id': key, 'a': a[key]['verdict'], 'b': b[key]['verdict'],
             'same_bic': bool(a[key]['bic']) and a[key]['bic'] == b[key]['bic']}
            for key in tp
        ],
        'bic_same': len(bic_same),
        'bic_missing': len(shared) - len(bic_same) - len(bic_differ),
        'bic_differ': len(bic_differ),
        'bic_differ_kinds': dict(kinds),
        'bic_differ_samples': [
            {'class_id': key, 'a': a[key]['bic'], 'b': b[key]['bic']}
            for key in bic_differ
        ],
        'fix_differ': len(fix_differ),
        'presence': presence,
        'strict_flags': flags,
        'signals': signals,
    }
    if probe_git:
        shape = {'a': collections.Counter(), 'b': collections.Counter()}
        for key in shared:
            clone = a_raw[key].get('clone') or b_raw[key].get('clone') or ''
            shape['a'][squash_shape(a[key]['bic'], clone)] += 1
            shape['b'][squash_shape(b[key]['bic'], clone)] += 1
        report['bic_shape'] = {name: dict(counts) for name, counts in shape.items()}
    return report


def render(report: dict, limit: int) -> str:
    out = [
        'A ' + report['a']['path'] + '  records=' + str(report['a']['records']),
        'B ' + report['b']['path'] + '  records=' + str(report['b']['records']),
        'shared=%d  only A=%d  only B=%d'
        % (report['shared'], len(report['only_a']), len(report['only_b'])),
        '',
        'verdicts                 A      B',
    ]
    for verdict in sorted(set(report['verdicts']['a']) | set(report['verdicts']['b'])):
        out.append(
            '  %-22s %5d %6d'
            % (verdict, report['verdicts']['a'].get(verdict, 0),
               report['verdicts']['b'].get(verdict, 0))
        )
    out.append('verdict agreement        %d/%d'
               % (report['verdict_agreement'], report['shared']))
    out.append('')
    out.append('TP family (AI_ROOT_CAUSE / AI_CODE_FLAWED / AI_CAUSAL_CONTRIBUTOR)')
    out.append('  union=%d  same verdict=%d  same BIC=%d'
               % (len(report['tp']),
                  sum(1 for row in report['tp'] if row['a'] == row['b']),
                  sum(1 for row in report['tp'] if row['same_bic'])))
    for row in report['tp'][:limit]:
        out.append('  %s  A=%-20s B=%-20s bic_same=%s'
                   % (row['class_id'], row['a'] or 'none', row['b'] or 'none',
                      row['same_bic']))
    out.append('')
    out.append('BIC  same=%d  differ=%d  missing=%d   %s'
               % (report['bic_same'], report['bic_differ'], report['bic_missing'],
                  report['bic_differ_kinds']))
    for row in report['bic_differ_samples'][:3]:
        out.append('  %s  A=%s B=%s' % (row['class_id'], row['a'][:12], row['b'][:12]))
    out.append('fix  differ=%d' % report['fix_differ'])
    if 'bic_shape' in report:
        out.append('BIC shape (probed)  A=%s  B=%s'
                   % (report['bic_shape']['a'], report['bic_shape']['b']))
    out.append('')
    out.append('field presence           A      B')
    for field, counts in report['presence'].items():
        out.append('  %-22s %5d %6d' % (field, counts[0], counts[1]))
    out.append('')
    out.append('strict flags             A      B')
    for kind in sorted(set(report['strict_flags']['a']) | set(report['strict_flags']['b'])):
        out.append('  %-22s %5d %6d'
                   % (kind, report['strict_flags']['a'].get(kind, 0),
                      report['strict_flags']['b'].get(kind, 0)))
    out.append('')
    out.append('review signals (heuristic, read these first)   A      B')
    for kind in ('ai_disclosure_claim', 'residual_open_surface'):
        out.append('  %-22s %5d %6d'
                   % (kind, len(report['signals']['a'].get(kind, [])),
                      len(report['signals']['b'].get(kind, []))))
    both = sorted(set(report['signals']['a'].get('ai_disclosure_claim', []))
                   & set(report['signals']['b'].get('ai_disclosure_claim', [])))
    out.append('  both slots flag the same disclosure case: %d' % len(both))
    for key in both[:limit]:
        out.append('    ' + key)
    return '\n'.join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--a', type=Path, required=True, help='slot A record dir')
    parser.add_argument('--b', type=Path, required=True, help='slot B record dir')
    parser.add_argument('--json', type=Path, help='also write the report as JSON')
    parser.add_argument('--limit', type=int, default=8, help='rows per section')
    parser.add_argument('--probe-git', action='store_true',
                        help='read each BIC object to classify squash/merge/atomic')
    args = parser.parse_args()
    report = compare(args.a, args.b, args.probe_git)
    print(render(report, args.limit))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
