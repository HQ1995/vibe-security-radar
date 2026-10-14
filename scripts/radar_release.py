#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

import audit_delivery as delivery
import audit_dispatch as dispatch
import claims
import ledger_store
import radar_flow


def update(batch: str, values: dict) -> None:
    with dispatch.lock(dispatch.RESEARCH / '.dispatch.lock'):
        path = dispatch.index_path(batch)
        document = dispatch.read_index(path)
        document['flow']['release'].update(values)
        dispatch.write_index(path, document)


def execute(root: Path, label: str, argv: list[str], *, check: bool = True) -> str:
    root.mkdir(parents=True, exist_ok=True)
    stem = root / (label + '-' + uuid.uuid4().hex)
    receipt = {'argv': argv, 'cwd': str(ledger_store.ROOT), 'started_at': dispatch.now(),
               'exit_code': None, 'scope': 'command execution only'}
    dispatch.write_index(stem.with_suffix('.json'), receipt)
    result = subprocess.run(argv, cwd=ledger_store.ROOT, capture_output=True, text=True, check=False)
    outputs = []
    for suffix, text in (('.stdout', result.stdout), ('.stderr', result.stderr)):
        file = stem.with_suffix(suffix)
        file.write_text(text)
        outputs.append({'path': str(file), 'sha256': dispatch.digest(file)})
    receipt.update(finished_at=dispatch.now(), exit_code=result.returncode, outputs=outputs)
    dispatch.write_index(stem.with_suffix('.json'), receipt)
    if result.returncode and check:
        raise ValueError(f'{label} failed: original receipt {stem.with_suffix(".json")}')
    return result.stdout


def ledger(root: Path, *args: str, structured: bool = True):
    output = execute(root, args[0], ['numactl', '--cpunodebind=1', '--membind=1', sys.executable,
                                   str(ledger_store.ROOT / 'scripts/ledger_store.py'), *args])
    return delivery.read_text(output) if structured else output


def records_view(seal: dict) -> Path:
    paths = [Path(p) for p in seal['records'].values()]
    if len(paths) == 1:
        return paths[0]
    if len({p.parent for p in paths}) != 1:
        raise ValueError('multi-case delivery needs a complete records-only directory')
    return paths[0].parent


def gate(batch: str, plan: dict, accepted: dict, root: Path, *, expect: str = 'ACCEPTED') -> dict:
    decision = delivery.read(Path(accepted['decisions']))['reduction']
    pin = decision['pins']['reduction_gate']
    entry = dispatch.read_index(dispatch.index_path(batch))['dispatch'][plan['adjudicator']['task']]
    if (dispatch.digest(Path(pin['path'])) != pin['sha256']
            or not any(hashes.get(pin['path']) == pin['sha256'] for hashes in entry['binding']['inputs'].values())):
        raise ValueError('reduction gate must be the assigned frozen executable')
    argv = ['numactl', '--cpunodebind=1', '--membind=1', sys.executable, '-B', pin['path'],
            '--manifest', accepted['manifest'], '--accepted', str(records_view(accepted)),
            '--decisions', accepted['decisions'], '--research-contract', 'causal-work-v1']
    for receipt in plan['auditors']:
        entry = radar_flow.entry_for(batch, receipt)
        seal = delivery.verify(Path(entry['delivery']['path']), entry['binding'])
        argv.extend(['--lane', receipt.get('lane', receipt['task']) + '=' + str(records_view(seal))])
    result = delivery.read_text(execute(root, 'final-gate', argv, check=expect == 'ACCEPTED'))
    ids = accepted['case_ids']
    lanes = set(result.get('auditors', [])) == {r.get('lane', r['task']) for r in plan['auditors']}
    if expect == 'BLOCKED':
        blocked = [f'{cid}: research remains BLOCKED' for cid in ids]
        if (not lanes or result.get('cases') != len(ids) or result.get('research_status') != {'BLOCKED': len(ids)}
                or sorted(result.get('problems', [])) != sorted(blocked)):
            raise ValueError('final gate does not confirm a researched blocker for every case and lane')
        return result
    if (result.get('delivery_valid') is not True or result.get('cases') != len(ids)
            or result.get('research_status') != {'ACCEPTED': len(ids)} or not lanes):
        raise ValueError('final gate does not accept the original manifest and every declared lane')
    return result


def prepare(plan: dict, receipt: dict) -> tuple[dict, list[dict], list[dict], Path]:
    if set(plan) != {'batch', 'description', 'patches', 'assessments', 'leader_review'}:
        raise ValueError('release plan needs batch, description, patches, assessments and leader_review')
    batch = plan['batch']
    allotted = dispatch.authorize(batch, receipt)
    if allotted['endpoint'] not in {'ledger', 'site'}:
        raise ValueError('research endpoint does not authorize canonical writes')
    document = dispatch.read_index(dispatch.index_path(batch))
    dispatch.require_running_scope(document)
    flow = document['flow']
    if any(entry['active'] for entry in document['dispatch'].values()):
        raise ValueError('stop and seal/retire all original assignments before release')
    adj = document['dispatch'][flow['plan']['adjudicator']['task']]
    accepted = delivery.verify(Path(adj['delivery']['path']), adj['binding'])
    if dispatch.digest(Path(adj['delivery']['path'])) != adj['delivery']['sha256']:
        raise ValueError('collected adjudication seal changed')
    review = delivery.read(Path(plan['leader_review']))
    if (review.get('batch') != batch or review.get('leader') != allotted['leader']
            or review.get('delivery_sha256') != adj['delivery']['sha256']
            or set(review.get('cases', {})) != set(allotted['case_ids'])):
        raise ValueError('leader source review must bind the complete original manifest and final seal')
    for cid, reviewed in review['cases'].items():
        if not isinstance(reviewed.get('basis'), str) or not reviewed['basis'].strip() or not reviewed.get('evidence'):
            raise ValueError(f'{cid}: leader review needs substantive basis and primary receipts')
        for item in reviewed['evidence']:
            if accepted['files'].get(item['path']) != item['sha256']:
                raise ValueError('leader review evidence must belong to the sealed accepted delivery')
    for line in Path(plan['patches']).read_text().splitlines():
        if line.strip():
            delivery.read_text(line)
    patches = ledger_store.read_patches(Path(plan['patches']), require_assessments=True)
    assessments = [delivery.read_text(line) for line in Path(plan['assessments']).read_text().splitlines() if line.strip()]
    if {p['row']['class_id'] for p in patches} != set(allotted['case_ids']):
        raise ValueError('release patches must cover the original manifest exactly')
    ids = [a.get('assessment_id') for a in assessments]
    if not ids or not all(isinstance(i, str) and i for i in ids) or len(set(ids)) != len(ids):
        raise ValueError('every assessment needs its original stable unique ID')
    if set(ids) != {i for p in patches for i in p['assessment_ids']}:
        raise ValueError('assessment payload differs from patch support')
    for patch in patches:
        cid = patch['row']['class_id']
        if patch['row']['causal_research'] != delivery.read(Path(accepted['records'][cid])):
            raise ValueError('canonical projection differs from accepted synthesis')
        for assessment in assessments:
            if assessment['assessment_id'] in patch['assessment_ids'] and (
                    assessment['class_id'] != cid or assessment['base_ledger_revision'] != patch['expected_revision']):
                raise ValueError('assessment case or base revision differs from patch')
    pins = {}
    for key in ('patches', 'assessments', 'leader_review'):
        pins.update(dispatch.snapshot(Path(plan[key])))
    prior = flow.get('release')
    if prior is not None and (prior['plan'] != plan or prior['pins'] != pins):
        raise ValueError('release bytes changed; preserve the original intent and receipts')
    if prior is None:
        with dispatch.lock(dispatch.RESEARCH / '.dispatch.lock'):
            path = dispatch.index_path(batch)
            document = dispatch.read_index(path)
            document['flow']['release'] = {'plan': plan, 'pins': pins, 'finalize_started': False, 'holds': []}
            dispatch.write_index(path, document)
    root = dispatch.index_path(batch).parent / 'release' / 'automatic'
    gate(batch, flow['plan'], accepted, root)
    return allotted, patches, assessments, root


def observe(root: Path, patches: list[dict]) -> tuple[bool, dict]:
    readbacks = {}
    landed = []
    for patch in patches:
        cid = patch['row']['class_id']
        row = ledger(root, 'get', cid)
        history = ledger(root, 'history', cid)
        latest = history['versions'][-1]
        committed = row['revision'] == patch['expected_revision'] + 1 and row['row'] == patch['row']
        baseline = row['revision'] == patch['expected_revision']
        if not committed and not baseline:
            raise ValueError(f'{cid}: unexpected canonical revision/content; reconcile before any write')
        if row['revision'] != latest['revision'] or row['row'] != latest['row']:
            raise ValueError('row and history disagree')
        if committed and (latest['source_assessment_ids'] != sorted(set(patch['assessment_ids']))
                          or latest['checksum'] != ledger_store.sha256(ledger_store.raw_row(patch['row']))
                          or latest['change_set_id'] != row['change_set_id']):
            raise ValueError('committed row history differs from prepared patch')
        readbacks[cid] = {'get': row, 'history': history}
        landed.append(committed)
    if any(landed) and not all(landed):
        raise ValueError('mixed landing state; inspect the original atomic transaction')
    if all(landed) and len({r['get']['change_set_id'] for r in readbacks.values()}) != 1:
        raise ValueError('rows do not share the prepared atomic change set')
    return all(landed), readbacks


def assessments_match(assessments: list[dict], readbacks: dict) -> list[dict]:
    missing = []
    for item in assessments:
        history = readbacks[item['class_id']]['history']
        if history['class_id'] != item['class_id']:
            raise ValueError('stored assessment history belongs to another case')
        found = [a for a in history['assessments'] if a['assessment_id'] == item['assessment_id']]
        if not found:
            missing.append(item)
        elif any(found[0].get(key) != value for key, value in item.items() if key != 'class_id'):
            raise ValueError('stored assessment differs from the exact original payload; never accept an ID-only skip')
    return missing


def release_claims(batch: str, allotted: dict, patches: list[dict]) -> list[str]:
    document = dispatch.read_index(dispatch.index_path(batch))
    binding = document['dispatch'][document['flow']['plan']['adjudicator']['task']]['binding']
    released = []
    for patch in patches:
        cid = patch['row']['class_id']
        for claim_id in binding['claim_ids'][cid]:
            events = claims.load(claims.DEFAULT_CLAIMS)
            historical = any(e.get('action') in {'RELEASED', 'RELEASE', 'DONE'} and e.get('class_id') == cid
                             and e.get('owner') == allotted['leader'] and e.get('claim_id') == claim_id for e in events)
            if not historical:
                claims.release(claims.DEFAULT_CLAIMS, cid, allotted['leader'], claim_id=claim_id)
            released.append(claim_id)
    return released


def land(plan: dict, receipt: dict) -> dict:
    dispatch.authorize(plan['batch'], receipt)
    with dispatch.lock(dispatch.index_path(plan['batch']).parent / '.release.lock', nonblocking=True):
        return _land(plan, receipt)


def _land(plan: dict, receipt: dict) -> dict:
    allotted, patches, assessments, root = prepare(plan, receipt)
    batch = plan['batch']
    try:
        committed, readbacks = observe(root, patches)
        missing = assessments_match(assessments, readbacks)
        if committed:
            if missing or any(r['history']['versions'][-1]['actor'] != allotted['leader'] for r in readbacks.values()):
                raise ValueError('landed history lacks the original actor/assessments')
        else:
            binding = dispatch.read_index(dispatch.index_path(batch))['dispatch'][
                dispatch.read_index(dispatch.index_path(batch))['flow']['plan']['adjudicator']['task']]['binding']
            dispatch.verify(binding)
            prior = dispatch.read_index(dispatch.index_path(batch))['flow']['release']
            if prior['finalize_started']:
                raise ValueError('previous finalize has no matching landing; inspected reconciliation required before a new write')
            if missing:
                ledger(root, 'assessment-add', plan['assessments'])
                _, readbacks = observe(root, patches)
                if assessments_match(assessments, readbacks):
                    raise ValueError('assessment ingestion did not store the complete payload')
            update(batch, {'finalize_started': True, 'finalize_intent_at': dispatch.now()})
            ledger(root, 'finalize', plan['patches'], '--actor', allotted['leader'],
                   '--description', plan['description'], structured=False)
            committed, readbacks = observe(root, patches)
            if not committed or assessments_match(assessments, readbacks):
                raise ValueError('finalize returned without verified landing')
        if any(r['history']['versions'][-1]['actor'] != allotted['leader'] for r in readbacks.values()):
            raise ValueError('landed history actor differs from the original release owner')
        check = ledger(root, 'check')
        if check.get('jsonl_byte_identical') is not True:
            ledger(root, 'export', structured=False)
            check = ledger(root, 'check')
        if check.get('jsonl_byte_identical') is not True:
            raise ValueError('export is not byte-identical to Neon')
        outcome = {'phase': 'VERIFIED_LEDGER_LANDED', 'research_acceptance': 'LEADER_REVIEWED',
                   'cases': len(patches), 'revisions': {cid: r['get']['revision'] for cid, r in readbacks.items()},
                   'change_set_id': next(iter(readbacks.values()))['get']['change_set_id'],
                   'jsonl_byte_identical': True, 'export_sha256': check['sha256'],
                   'endpoint': allotted['endpoint'], 'publication': 'NOT_PERFORMED'}
        update(batch, {'outcome': outcome})
        if allotted['endpoint'] == 'ledger':
            released = release_claims(batch, allotted, patches)
            outcome.update(phase='LEDGER_ENDPOINT_COMPLETE', released_claim_ids=released)
        else:
            outcome.update(phase='AWAITING_PUBLICATION', next_owner=allotted['leader'],
                           next_action='Continue the authorized site runbook; retain claims through live content verification.')
        update(batch, {'outcome': outcome})
        return outcome
    except (OSError, ValueError, KeyError, TypeError) as exc:
        document = dispatch.read_index(dispatch.index_path(batch))
        holds = document['flow']['release']['holds']
        state = {'phase': 'RELEASE_HOLD', 'at': dispatch.now(), 'next_owner': allotted['leader'], 'next_action': str(exc)}
        update(batch, {'holds': [*holds, state]})
        return state


def main() -> int:
    parser = argparse.ArgumentParser(description='Land a leader-reviewed flow, recover committed writes by readback, and release')
    parser.add_argument('plan', type=Path)
    parser.add_argument('--batch-receipt', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = land(delivery.read(args.plan), delivery.read(args.batch_receipt))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result['phase'] == 'RELEASE_HOLD' else 0


if __name__ == '__main__':
    raise SystemExit(main())
