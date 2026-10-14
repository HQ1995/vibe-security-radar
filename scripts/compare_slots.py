#!/usr/bin/env python3
"""Compare independent audit slots over the same batch.

Two blind audits of one batch disagree where the two briefs asked for
different fields, or where a rule lived only in prose. This prints that
comparison, so the drift is one command instead of a hand diff.

Usage:
  python3 scripts/compare_slots.py --lane auditor1=PATH --lane auditor2=PATH --lane auditor3=PATH
  python3 scripts/compare_slots.py --a research/<batch>/review \\
      --b research/<batch>/verify/cases [--json report.json] [--probe-git]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_record_gates import AI_VERDICTS, check_record, check_record_strict, load_record, review_signals

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

# Text differences are review obligations, not machine-decided contradictions.
# Keep distinct roles distinct: a landing is not an atomic member, and a later
# AI contribution is not a decomposed BIC member.
RESEARCH_FIELDS = {
    'advisory': ('verdict', 'advisory_ids', 'advisory_disposition',
                 'advisory_aliases', 'false_positive_ground'),
    'mechanism': ('cause', 'mechanism', 'mechanisms', 'bug_semantics',
                  'flaw_origin', 'counterevidence', 'evidence', 'reasoning'),
    'bic': ('introducer_sha', 'introducer_parent', 'bic_granularity',
            'bic_minimality', 'bic_note', 'landing_commit', 'landing_basis',
            'landing_note', 'decomposed_shas', 'decomposition_probe'),
    'ai': ('ai_on_bic', 'ai_marker', 'ai_admissibility', 'identity_class',
           'disclosure_convention', 'disclosure_convention_evidence',
           'candidate_set', 'candidate_details', 'carrier_set', 'ai_evidence'),
    'fix': ('fix_sha', 'direct_fix_sha', 'atomic_repair_sha', 'fix_shas',
            'minimum_fix_set', 'fix_granularity', 'fix', 'fix_note',
            'fix_ai_marker', 'fix_chain', 'ir_chain', 'unpatched', 'potential_fix'),
    'versions': ('versions', 'affected_versions', 'fixed_versions',
                 'fixed_release', 'clone_head_sha'),
    'residual': ('remaining_gap', 'residual_triage', 'flip_condition'),
}


def research_differences_many(records: dict[str, dict]) -> dict:
    """List differing claims from every lane without choosing a preferred report."""
    first = next(iter(records.values()))
    return {
        dimension: {field: {name: record.get(field) for name, record in records.items()}
                    for field in fields
                    if any(record.get(field) != first.get(field) for record in records.values())}
        for dimension, fields in RESEARCH_FIELDS.items()
        if any(record.get(field) != first.get(field)
               for field in fields for record in records.values())
    }


def research_differences(a: dict, b: dict) -> dict:
    return research_differences_many({'a': a, 'b': b})


def lane_paths(values=None, a: Path | None = None, b: Path | None = None) -> dict[str, Path]:
    if values:
        if a is not None or b is not None:
            raise ValueError('use --lane or --a/--b, not both')
        paths = {}
        for value in values:
            name, separator, path = value.partition('=')
            if not separator or not path or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', name):
                raise ValueError('--lane requires NAME=PATH')
            if name == 'accepted' or name in paths:
                raise ValueError(f'duplicate or reserved lane name: {name}')
            paths[name] = Path(path)
    elif a is not None and b is not None:
        paths = {'a': a, 'b': b}
    else:
        raise ValueError('supply named --lane inputs, or both --a and --b')
    if len({path.resolve() for path in paths.values()}) != len(paths):
        raise ValueError('independent lanes must have distinct input paths')
    return paths


def load_snapshot(path: Path) -> tuple[dict[str, dict], dict[str, str]]:
    files = sorted(path.rglob('*.json')) if path.is_dir() else [path]
    records: dict[str, dict] = {}
    digests = {}
    for file in files:
        if SKIP.search(file.name):
            continue
        try:
            data = file.read_bytes()
            record = load_record(data.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"{file}: {exc}") from exc
        if isinstance(record, dict) and 'verdict' in record:
            key = str(record.get('class_id') or file.stem)
            if key in records:
                raise ValueError(f'{file}: duplicate class_id {key}')
            records[key] = record
            digests[key] = hashlib.sha256(data).hexdigest()
    return records, digests


def load(path: Path) -> dict[str, dict]:
    return load_snapshot(path)[0]


def sha(value) -> str:
    return str(value).lower() if isinstance(value, str) and value.strip() else ''


def view(record: dict) -> dict:
    """One shape for both slots: new fields win, older ones map onto them."""
    members = record.get('decomposed_shas') or []
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
    """Inspect Git shape; single-parent/root objects need separate minimality research."""
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
    return 'single_parent_or_root'


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
        if a[key]['fix'] != b[key]['fix']
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
            for message in check_record(record) + check_record_strict(record):
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
        'fix_differ_samples': [
            {'class_id': key, 'a': a[key]['fix'], 'b': b[key]['fix']}
            for key in fix_differ
        ],
        'research_differences': {
            key: differences for key in shared
            if (differences := research_differences(a_raw[key], b_raw[key]))
        },
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


def compare_many(paths: dict[str, Path], probe_git: bool = False) -> dict:
    if not paths:
        raise ValueError('at least one auditor input is required')
    slots = {name: load(path) for name, path in paths.items()}
    union = set().union(*(set(records) for records in slots.values()))
    shared = set.intersection(*(set(records) for records in slots.values()))
    report = {
        'lanes': {name: {'path': str(paths[name]), 'records': len(records),
                         'verdicts': dict(collections.Counter(r.get('verdict') for r in records.values()))}
                  for name, records in slots.items()},
        'union': len(union), 'shared': len(shared),
        'missing': {name: sorted(union - set(records)) for name, records in slots.items()},
        'research_differences': {
            cid: differences for cid in sorted(shared)
            if (differences := research_differences_many({name: records[cid] for name, records in slots.items()}))
        },
        'strict_flags': {name: {cid: errors for cid, record in records.items()
                               if (errors := check_record(record) + check_record_strict(record))}
                         for name, records in slots.items()},
        'signals': {name: {cid: messages for cid, record in records.items()
                          if (messages := review_signals(record))}
                    for name, records in slots.items()},
        'scope': 'comparison only; use the adjudication gate and manifest for acceptance',
    }
    if probe_git:
        report['bic_shape'] = {
            name: dict(collections.Counter(squash_shape(sha(r.get('introducer_sha')), r.get('clone') or '')
                                           for r in records.values()))
            for name, records in slots.items()
        }
    return report


def render(report: dict, limit: int) -> str:
    if 'lanes' in report:
        out = [f'{name}: records={slot["records"]} missing={len(report["missing"][name])} '
               f'flagged={len(report["strict_flags"][name])} path={slot["path"]}'
               for name, slot in report['lanes'].items()]
        out.append(f'union={report["union"]} shared={report["shared"]} '
                   f'research differences={len(report["research_differences"])} (not acceptance)')
        out.extend(f'{cid}: {", ".join(dimensions)}'
                   for cid, dimensions in list(report['research_differences'].items())[:limit])
        if 'bic_shape' in report:
            out.append('Git shapes (not logical atomicity): ' + json.dumps(report['bic_shape']))
        return '\n'.join(out)
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
    out.append('research differences requiring adjudication=%d (not acceptance)'
               % len(report['research_differences']))
    for key, dimensions in list(report['research_differences'].items())[:limit]:
        out.append('  %s  %s' % (key, ', '.join(dimensions)))
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
    parser.add_argument('--a', type=Path, help='legacy slot A record dir')
    parser.add_argument('--b', type=Path, help='legacy slot B record dir')
    parser.add_argument('--lane', action='append', help='NAME=PATH; repeat for every independent auditor')
    parser.add_argument('--json', type=Path, help='also write the report as JSON')
    parser.add_argument('--limit', type=int, default=8, help='rows per section')
    parser.add_argument('--probe-git', action='store_true',
                        help='inspect Git shape; this cannot establish logical atomicity')
    args = parser.parse_args()
    try:
        paths = lane_paths(args.lane, args.a, args.b)
        report = compare_many(paths, args.probe_git) if args.lane else compare(args.a, args.b, args.probe_git)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(render(report, args.limit))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
