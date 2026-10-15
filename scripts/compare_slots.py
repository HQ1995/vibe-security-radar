#!/usr/bin/env python3
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
from audit_record_gates import check_record, check_record_strict, load_record, review_signals

SKIP = re.compile(r"INDEX|manifest|selection|summary|excluded", re.I)
SQUASH_SUBJECT = re.compile(r"\(#\d+\)$")
GIT_ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}

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
    first = next(iter(records.values()))
    return {
        dimension: {field: {name: record.get(field) for name, record in records.items()}
                    for field in fields
                    if any(record.get(field) != first.get(field) for record in records.values())}
        for dimension, fields in RESEARCH_FIELDS.items()
        if any(record.get(field) != first.get(field)
               for field in fields for record in records.values())
    }


def lane_paths(values) -> dict[str, Path]:
    if not values:
        raise ValueError('supply a named --lane input for every independent auditor')
    paths = {}
    for value in values:
        name, separator, path = value.partition('=')
        if not separator or not path or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', name):
            raise ValueError('--lane requires NAME=PATH')
        if name == 'accepted' or name in paths:
            raise ValueError(f'duplicate or reserved lane name: {name}')
        paths[name] = Path(path)
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


def squash_shape(value: str, clone: str) -> str:
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


def main() -> int:
    parser = argparse.ArgumentParser(description='Compare independent audit slots over the same batch')
    parser.add_argument('--lane', action='append', help='NAME=PATH; repeat for every independent auditor')
    parser.add_argument('--json', type=Path, help='also write the report as JSON')
    parser.add_argument('--limit', type=int, default=8, help='rows per section')
    parser.add_argument('--probe-git', action='store_true',
                        help='inspect Git shape; this cannot establish logical atomicity')
    args = parser.parse_args()
    try:
        report = compare_many(lane_paths(args.lane), args.probe_git)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(render(report, args.limit))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
