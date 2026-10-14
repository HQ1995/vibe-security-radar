#!/usr/bin/env python3
"""Advance registered independent deliveries to their sole adjudicator.

One foreground worker at a time; the existing batch index remains authoritative.
Research methods, leader source review and publication follow the assigned skills.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import audit_delivery as delivery
import audit_dispatch as dispatch


def entry_for(batch: str, receipt: dict) -> dict:
    entry = dispatch.read_index(dispatch.index_path(batch))['dispatch'][receipt['task']]
    if (receipt['batch'] != batch or entry['sha256'] != receipt['binding_sha256']
            or dispatch.binding_hash(entry['binding']) != receipt['binding_sha256']):
        raise ValueError('wrong or changed registration receipt')
    return entry


def collect(batch: str, receipt: dict) -> dict:
    entry = entry_for(batch, receipt)
    attempts = entry.get('attempts', [])
    if not attempts or attempts[-1]['status'] != 'RETURNED' or attempts[-1]['command_exit'] != 0:
        raise ValueError('missing successful terminal receipt; inspect execution, not the research verdict')
    binding = entry['binding']
    dispatch.verify(binding)
    path = Path(binding['output']) / 'DELIVERY.json'
    value = delivery.verify(path, binding)
    seal = {'path': str(path), 'sha256': dispatch.digest(path)}
    if entry.get('delivery') not in (None, seal):
        raise ValueError('previously collected delivery changed')
    with dispatch.lock(dispatch.RESEARCH / '.dispatch.lock'):
        index = dispatch.index_path(batch)
        document = dispatch.read_index(index)
        document['dispatch'][receipt['task']]['delivery'] = seal
        dispatch.write_index(index, document)
    if entry['active']:
        dispatch.act(batch, receipt['task'], receipt['binding_sha256'], 'retire')
    return value


def run_once(batch: str, receipt: dict) -> dict:
    entry = entry_for(batch, receipt)
    if not entry['dispatched']:
        # Workers can check actual readability in their own sandbox, without seeing
        # the shared coordination index or other auditors' judgments.
        assignment = Path(entry['binding']['output']) / 'INPUT-BINDING.json'
        assignment.parent.mkdir(parents=True, exist_ok=True)
        public = {'binding': entry['binding'], 'sha256': entry['sha256']}
        if assignment.exists():
            if delivery.read(assignment) != public:
                raise ValueError('public input binding changed before execution')
        else:
            with assignment.open('x') as out:
                json.dump(public, out, sort_keys=True)
        dispatch.act(batch, receipt['task'], receipt['binding_sha256'], 'run')
    # Never retry a crash, timeout, ambiguous send or incomplete submission here.
    return collect(batch, receipt)


def advance(plan: dict, batch_receipt: dict) -> dict:
    dispatch.authorize(plan['batch'], batch_receipt)
    with dispatch.lock(dispatch.index_path(plan['batch']).parent / '.flow.lock', nonblocking=True):
        return _advance(plan, batch_receipt)


def _advance(plan: dict, batch_receipt: dict) -> dict:
    if set(plan) != {'batch', 'n', 'auditors', 'adjudicator'}:
        raise ValueError('plan needs batch, n, auditor registration receipts and adjudicator spec')
    batch = plan['batch']
    allotted = dispatch.authorize(batch, batch_receipt)
    if type(plan['n']) is not int or plan['n'] < 2 or len(plan['auditors']) != plan['n']:
        raise ValueError('every declared independent auditor is required; n must be at least 2')
    if len({r['task'] for r in plan['auditors']}) != plan['n']:
        raise ValueError('auditor tasks must be distinct')
    if len({r.get('lane', r['task']) for r in plan['auditors']}) != plan['n']:
        raise ValueError('independent lane names must be distinct')
    for receipt in plan['auditors']:
        if entry_for(batch, receipt)['binding']['role'] != 'auditor':
            raise ValueError('auditor receipt has another role')
    spec = plan['adjudicator']
    if spec['batch'] != batch or spec['role'] != 'adjudicator' or spec['leader'] != allotted['leader']:
        raise ValueError('sole adjudicator must belong to this leader and batch')
    with dispatch.lock(dispatch.RESEARCH / '.dispatch.lock'):
        path = dispatch.index_path(batch)
        document = dispatch.read_index(path)
        dispatch.require_running_scope(document)
        flow = document.setdefault('flow', {'plan': plan, 'plan_sha256': dispatch.binding_hash(plan),
                                           'contract_pins': {}, 'holds': []})
        if flow['plan'] != plan or flow['plan_sha256'] != dispatch.binding_hash(plan):
            raise ValueError('flow plan changed; preserve its existing bindings and attempts')
        if flow.get('release', {}).get('outcome'):
            for entry in document['dispatch'].values():
                if entry.get('delivery'):
                    delivery.verify(Path(entry['delivery']['path']), entry['binding'])
                    if dispatch.digest(Path(entry['delivery']['path'])) != entry['delivery']['sha256']:
                        raise ValueError('collected delivery seal changed after landing')
            return flow['release']['outcome']
        if not flow['contract_pins']:
            for key in ('brief', 'skill'):
                if key in spec:
                    flow['contract_pins'].update(dispatch.snapshot(Path(spec[key])))
        for file, sha in flow['contract_pins'].items():
            if dispatch.digest(Path(file)) != sha:
                raise ValueError('adjudicator contract changed before handoff')
        dispatch.write_index(path, document)
    try:
        for receipt in plan['auditors']:
            run_once(batch, receipt)
        # Registration itself rejects inputs with an active writer. Also require
        # all complete sealed report/evidence trees to be passed, not just votes.
        for receipt in plan['auditors']:
            output = Path(entry_for(batch, receipt)['binding']['output'])
            if str(output) not in spec['inputs']:
                raise ValueError('adjudicator inputs must include each complete sealed auditor output')
        tasks = dispatch.read_index(dispatch.index_path(batch))['dispatch']
        if spec['task'] not in tasks:
            adjudicator = dispatch.register(spec, batch_receipt=batch_receipt)
        else:
            adjudicator = {'batch': batch, 'task': spec['task'],
                           'binding_sha256': tasks[spec['task']]['sha256']}
            bound = tasks[spec['task']]['binding']
            if any(bound[k] != spec[k] for k in ('agent', 'role', 'leader', 'endpoint', 'cwd', 'output', 'command')):
                raise ValueError('adjudicator differs from registered plan')
        run_once(batch, adjudicator)
        state = {'phase': 'AWAITING_LEADER_SOURCE_REVIEW', 'n': plan['n'],
                 'cases': len(allotted['case_ids']), 'next_owner': allotted['leader'],
                 'next_action': 'Review primary evidence and counterfactuals; then prepare pinned release plan.',
                 'research_acceptance': 'PENDING', 'publication': 'NOT_PERFORMED'}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        state = {'phase': 'HOLD', 'n': plan['n'], 'cases': len(allotted['case_ids']),
                 'next_owner': allotted['leader'], 'next_action': str(exc),
                 'research_acceptance': 'PENDING', 'publication': 'NOT_PERFORMED'}
    with dispatch.lock(dispatch.RESEARCH / '.dispatch.lock'):
        path = dispatch.index_path(batch)
        document = dispatch.read_index(path)
        flow = document['flow']
        if state['phase'] == 'HOLD':
            flow['holds'].append({'at': dispatch.now(), **state})
        flow['checkpoint'] = {'at': dispatch.now(), **state}
        dispatch.write_index(path, document)
    return state


def inputs(path: Path, expected_hash: str) -> dict:
    assignment = delivery.read(path)
    binding = assignment['binding']
    if assignment['sha256'] != expected_hash or dispatch.binding_hash(binding) != expected_hash:
        raise ValueError('wrong public input binding')
    for root, hashes in binding['inputs'].items():
        if dispatch.snapshot(Path(root)) != hashes:
            raise ValueError(f'missing, unreadable or changed mounted input: {root}')
    if dispatch.digest(Path(binding['manifest']['path'])) != binding['manifest']['sha256']:
        raise ValueError('missing or changed mounted manifest')
    return {'task': binding['task'], 'binding_sha256': expected_hash, 'inputs_readable_and_pinned': True}


def migrate(plan: dict, batch_receipt: dict, inspection: Path) -> dict:
    """Leader-only, inspected replacement of one failed lane or same-owner adjudication.

Keep every original binding, attempt and plan. This never dispatches a worker or
changes a sealed valid blind submission, manifest, endpoint, N or safety stop.
"""
    batch = plan['batch']
    dispatch.authorize(batch, batch_receipt)
    with dispatch.lock(dispatch.index_path(batch).parent / '.flow.lock', nonblocking=True):
        with dispatch.lock(dispatch.RESEARCH / '.dispatch.lock'):
            path = dispatch.index_path(batch)
            document = dispatch.read_index(path)
            dispatch.require_running_scope(document)
            flow = document['flow']
            old = flow['plan']
            if flow.get('release') or dispatch.binding_hash(old) != flow['plan_sha256']:
                raise ValueError('release already started or original flow plan changed')
            if (set(plan) != set(old) or plan['batch'] != old['batch'] or plan['n'] != old['n']
                    or len(plan['auditors']) != len(old['auditors'])):
                raise ValueError('migration cannot change the original batch or N')
            changed = [i for i, (a, b) in enumerate(zip(old['auditors'], plan['auditors'])) if a != b]
            if len(changed) > 1 or (not changed and plan['adjudicator'] == old['adjudicator']):
                raise ValueError('migrate one failed lane or one adjudicator continuation at a time')
            if changed:
                if old['adjudicator']['task'] in document['dispatch']:
                    raise ValueError('adjudication already registered; preserve its original blind inputs')
                before, after = old['auditors'][changed[0]], plan['auditors'][changed[0]]
                previous = entry_for(batch, before)
                replacement = entry_for(batch, after)
                if after.get('lane', after['task']) != before.get('lane', before['task']):
                    raise ValueError('replacement must retain the original independent lane name')
                if replacement['binding']['role'] != 'auditor':
                    raise ValueError('replacement lane must be a registered auditor')
                dispatch.verify(replacement['binding'])
                original_seal = Path(previous['binding']['output']) / 'DELIVERY.json'
                if original_seal.exists():
                    try:
                        delivery.verify(original_seal, previous['binding'])
                    except (OSError, ValueError, KeyError, TypeError):
                        pass
                    else:
                        raise ValueError('valid sealed blind submission stays original; use adjudication for corrections')
                for receipt in plan['auditors']:
                    output = entry_for(batch, receipt)['binding']['output']
                    if output not in plan['adjudicator']['inputs']:
                        raise ValueError('replacement handoff must include every complete lane output')
            else:
                name = old['adjudicator']['task']
                if name not in document['dispatch']:
                    raise ValueError('adjudicator continuation requires its original registered attempt')
                previous = document['dispatch'][name]
                if previous['binding']['output'] not in plan['adjudicator']['inputs']:
                    raise ValueError('same-owner continuation must pin the original adjudication artifacts')
            if previous['active']:
                raise ValueError('inspect stopped work and retire the exact old assignment before migration')
            if (plan['adjudicator']['agent'] != old['adjudicator']['agent']
                    or any(plan['adjudicator'][key] != old['adjudicator'][key]
                           for key in ('batch', 'role', 'leader', 'endpoint', 'manifest'))):
                raise ValueError('retain the sole adjudicator owner and original research scope')
            if not changed and (plan['adjudicator']['task'] == old['adjudicator']['task']
                                or plan['adjudicator']['output'] == old['adjudicator']['output']):
                raise ValueError('continuation needs a new task and fresh owned output')
            reviewed = delivery.read(inspection)
            attempts = previous.get('attempts', [])
            prior = previous['binding']
            if (reviewed.get('batch') != batch or reviewed.get('task') != prior['task']
                    or reviewed.get('binding_sha256') != previous['sha256']
                    or reviewed.get('attempt_id') != (attempts[-1]['attempt_id'] if attempts else None)
                    or reviewed.get('classification') not in {'runtime_fault', 'delivery_fault', 'research_followup'}
                    or (changed and reviewed['classification'] == 'research_followup')
                    or reviewed.get('previous_work_stopped') is not True or not reviewed.get('evidence')
                    or not reviewed.get('next_question')):
                raise ValueError('migration needs inspected original-attempt evidence and the next decisive question')
            for pin in reviewed['evidence']:
                if dispatch.digest(Path(pin['path'])) != pin['sha256']:
                    raise ValueError('migration evidence changed')
            flow.setdefault('migrations', []).append({'at': dispatch.now(), 'previous_plan': old,
                    'previous_plan_sha256': flow['plan_sha256'],
                    'inspection': {'path': str(inspection.resolve()), 'sha256': dispatch.digest(inspection)}})
            flow.update(plan=plan, plan_sha256=dispatch.binding_hash(plan), contract_pins={})
            for key in ('brief', 'skill'):
                if key in plan['adjudicator']:
                    flow['contract_pins'].update(dispatch.snapshot(Path(plan['adjudicator'][key])))
            flow['checkpoint'] = {'at': dispatch.now(), 'phase': 'READY_FOR_INSPECTED_CONTINUATION',
                                  'next_action': reviewed['next_question']}
            dispatch.write_index(path, document)
    return {'phase': 'READY_FOR_INSPECTED_CONTINUATION', 'plan_sha256': dispatch.binding_hash(plan)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    advancing = sub.add_parser('advance')
    advancing.add_argument('plan', type=Path)
    advancing.add_argument('--batch-receipt', type=Path, required=True)
    migrating = sub.add_parser('migrate', help='leader connects one inspected fresh attempt without rewriting history')
    migrating.add_argument('plan', type=Path)
    migrating.add_argument('--batch-receipt', type=Path, required=True)
    migrating.add_argument('--inspection', type=Path, required=True)
    checking = sub.add_parser('inputs', help='run inside the worker sandbox before research')
    checking.add_argument('assignment', type=Path)
    checking.add_argument('--binding', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'advance':
            result = advance(delivery.read(args.plan), delivery.read(args.batch_receipt))
        elif args.action == 'migrate':
            result = migrate(delivery.read(args.plan), delivery.read(args.batch_receipt), args.inspection)
        else:
            result = inputs(args.assignment, args.binding)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get('phase') == 'HOLD' else 0


if __name__ == '__main__':
    raise SystemExit(main())
