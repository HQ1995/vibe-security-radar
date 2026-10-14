#!/usr/bin/env python3
"""Seal an owned delivery and verify its exact bytes without reading other judgments.

This is packaging, not research acceptance. Freeze this helper and its dependencies
with new assignments; old batches keep their original submission contract.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_record_gates import load_record
from audit_reduction_gate import check_research_work, digest, manifest_ids

read_text = load_record


def read(path: Path) -> dict:
    return load_record(path.read_text())


def owned(path: str, root: Path) -> Path:
    value = Path(path).absolute()
    if value.resolve() != value or not value.is_file() or root not in value.parents:
        raise ValueError(f'delivery file must exist within owned output without symlinks: {value}')
    if not value.read_bytes().strip():
        raise ValueError(f'empty delivery file: {value}')
    return value


def build(spec: dict) -> dict:
    required = {'batch', 'task', 'binding_sha256', 'manifest', 'output', 'report',
                'records', 'evidence', 'checks'}
    if not required <= set(spec) or set(spec) - required - {'research_work', 'decisions'}:
        raise ValueError('delivery needs identity, manifest, output, report, records, evidence and checks')
    if not all(isinstance(spec[k], str) and spec[k].strip() for k in required - {'records', 'evidence', 'checks'}):
        raise ValueError('delivery identity and paths must be nonempty strings')
    root = Path(spec['output']).absolute()
    if root.resolve() != root or not root.is_dir():
        raise ValueError('owned output must be an existing absolute directory without symlinks')
    ids = manifest_ids(Path(spec['manifest']))
    if not isinstance(spec['records'], dict) or set(spec['records']) != ids:
        raise ValueError('delivery records must cover the original manifest exactly')
    files = {}

    def pin(path: str) -> Path:
        value = owned(path, root)
        files[str(value)] = digest(value)
        return value

    pin(spec['report'])
    for cid, path in spec['records'].items():
        if read(pin(path)).get('class_id') != cid:
            raise ValueError(f'{cid}: record identity mismatch')
    for category in ('evidence', 'checks'):
        if not isinstance(spec[category], list) or not spec[category]:
            raise ValueError(f'{category}: nonempty list required')
        for path in spec[category]:
            file = pin(path)
            if category == 'checks':
                check = read(file)
                if not isinstance(check.get('argv'), list) or type(check.get('exit_code')) is not int:
                    raise ValueError('check receipt needs actual argv and integer exit_code')
                for output in check.get('outputs', []):
                    target = pin(output['path'])
                    if digest(target) != output['sha256']:
                        raise ValueError('changed check output')
    if 'research_work' in spec:
        if not isinstance(spec['research_work'], dict) or set(spec['research_work']) != ids:
            raise ValueError('research sidecars must cover the original manifest exactly')
        for cid, path in spec['research_work'].items():
            sidecar = pin(path)
            work = read(sidecar)
            problems = []

            def receipt(item, label):
                if not isinstance(item, dict) or set(item) != {'path', 'sha256'}:
                    problems.append(f'{label}: receipt needs path and sha256')
                    return
                target = pin(str(sidecar.parent / item['path']))
                if digest(target) != item['sha256']:
                    problems.append(f'{label}: changed evidence receipt')

            errors, _, _, _ = check_research_work(work.get('research', work), cid, receipt)
            if errors or problems:
                raise ValueError('; '.join(errors + problems))
    if 'decisions' in spec:
        read(pin(spec['decisions']))
    return {'version': 1, **spec, 'manifest_sha256': digest(Path(spec['manifest'])),
            'case_ids': sorted(ids), 'files': files, 'scope': 'sealed delivery only; not causal acceptance'}


def seal(spec: dict) -> Path:
    value = build(spec)
    path = Path(spec['output']) / 'DELIVERY.json'
    # A correction gets a new attempt/output; never overwrite a sealed original.
    with path.open('x') as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write('\n')
    verify(path)
    return path


def verify(path: Path, binding: dict | None = None) -> dict:
    value = read(path)
    if value.get('version') != 1 or path.absolute() != Path(value['output']) / 'DELIVERY.json':
        raise ValueError('wrong delivery version or location')
    spec = {key: item for key, item in value.items()
            if key not in {'version', 'manifest_sha256', 'case_ids', 'files', 'scope'}}
    if build(spec) != value:
        raise ValueError('sealed delivery bytes or coverage changed')
    if binding is not None:
        from audit_dispatch import binding_hash
        if (any(value[key] != binding[key] for key in ('batch', 'task', 'output'))
                or value['binding_sha256'] != binding_hash(binding)
                or value['manifest'] != binding['manifest']['path']
                or value['manifest_sha256'] != binding['manifest']['sha256']
                or value['case_ids'] != binding['case_ids']):
            raise ValueError('delivery differs from original task binding')
        if binding['role'] == 'auditor' and 'research_work' not in value:
            raise ValueError('new flow auditor delivery requires its research sidecars')
        if binding['role'] == 'adjudicator' and 'decisions' not in value:
            raise ValueError('adjudicator delivery requires frozen decisions')
    failed = [file for file in value['checks'] if read(Path(file))['exit_code'] != 0]
    if failed:
        raise ValueError(f'delivery checks failed; retain original receipts: {failed}')
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['seal', 'check'])
    parser.add_argument('path', type=Path, help='delivery spec for seal; DELIVERY.json for check')
    args = parser.parse_args()
    try:
        result = {'delivery': str(seal(read(args.path)))} if args.action == 'seal' else verify(args.path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
