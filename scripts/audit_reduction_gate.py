#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from audit_envelope import PROSE_KEYS, has_prose
from audit_record_gates import AI_VERDICTS, check_record, check_record_strict, load_record, review_signals
from compare_slots import RESEARCH_FIELDS, lane_paths, load_snapshot, research_differences_many

PIN_ROLES = ('manifest', 'audit_protocol', 'reducer_protocol', 'schema', 'brief',
             'record_gate', 'comparison', 'reduction_gate')
RESEARCH_CONTRACT = 'causal-work-v1'
WORK_DIMENSIONS = tuple(name for name in RESEARCH_FIELDS if name != 'residual')
TERMINAL_ROUTES = {'ANSWERED', 'UNAVAILABLE', 'EXHAUSTED', 'PROHIBITED'}


def text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def check_research_work(research, label, receipt):
    problems, worklist, boundaries = [], [], []
    counts = collections.Counter()
    if not isinstance(research, dict):
        return [f'{label}: research needs an object'], counts, worklist, boundaries
    if set(research) != set(WORK_DIMENSIONS):
        problems.append(f'{label}: research needs exactly {list(WORK_DIMENSIONS)}')

    def evidence(value, where):
        if not isinstance(value, list) or not value:
            problems.append(f'{where}: needs retained evidence receipts')
        else:
            for item in value:
                receipt(item, where)

    for dimension in WORK_DIMENSIONS:
        if dimension not in research:
            continue
        detail = research[dimension]
        where = f'{label} research {dimension}'
        if not isinstance(detail, dict):
            problems.append(f'{where}: needs an object')
            continue
        grade, state = detail.get('evidence_grade'), detail.get('work_state')
        if grade not in ('BOUND', 'QUALIFIED_BOUNDARY', 'UNRESOLVED'):
            problems.append(f'{where}: invalid evidence_grade')
        if state not in ('COMPLETE', 'UNFINISHED'):
            problems.append(f'{where}: invalid work_state')
        if not text(detail.get('finding')):
            problems.append(f'{where}: needs the supported finding and its scope')
        evidence(detail.get('evidence'), where)
        if grade != 'BOUND' and not text(detail.get('missing_fact')):
            problems.append(f'{where}: an unbound conclusion needs missing_fact')
        if grade == 'BOUND' and detail.get('missing_fact') is not None:
            problems.append(f'{where}: BOUND cannot retain a decisive missing_fact')
        routes = detail.get('routes')
        if not isinstance(routes, list):
            problems.append(f'{where}: routes must be a list')
            routes = []
        route_ids, identities, pending = set(), set(), set()
        for route in routes:
            if not isinstance(route, dict):
                problems.append(f'{where}: each route must be an object')
                continue
            route_id = route.get('id')
            if not text(route_id) or route_id in route_ids:
                problems.append(f'{where}: route IDs must be nonempty and unique')
                continue
            route_ids.add(route_id)
            identity = tuple(route.get(key) for key in ('question', 'source', 'evidence_type'))
            if not all(text(part) for part in identity):
                problems.append(f'{where} route {route_id}: needs question, source and evidence_type')
            else:
                identity = tuple(part.strip() for part in identity)
                if identity in identities:
                    problems.append(f'{where}: duplicate evidence route {route_id}')
                identities.add(identity)
            outcome = route.get('status')
            if outcome in ('PENDING', 'FAILED'):
                pending.add(route_id)
            elif not text(outcome) or outcome not in TERMINAL_ROUTES:
                problems.append(f'{where} route {route_id}: invalid status')
            if outcome != 'PENDING':
                if not text(route.get('observation')):
                    problems.append(f'{where} route {route_id}: needs its actual observation')
                evidence(route.get('evidence'), f'{where} route {route_id}')
        next_route = detail.get('next_permitted_route')
        if state == 'COMPLETE':
            counts['COMPLETE'] += 1
            if pending or 'next_permitted_route' not in detail or next_route is not None:
                problems.append(f'{where}: COMPLETE contradicts unfinished routes or a next route')
            if grade != 'BOUND':
                boundaries.append(dimension)
                if not routes:
                    problems.append(f'{where}: an unbound COMPLETE finding needs a recorded evidence frontier')
        elif state == 'UNFINISHED':
            counts['UNFINISHED'] += 1
            if not text(next_route) or next_route not in pending:
                problems.append(f'{where}: UNFINISHED needs a next_permitted_route naming a PENDING or FAILED route')
            worklist.append({'dimension': dimension, 'next_permitted_route': next_route})
    return problems, counts, worklist, boundaries


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_ids(path: Path) -> set[str]:
    ids = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        value = load_record(line).get('class_id') if line.lstrip().startswith('{') else line.strip()
        if not isinstance(value, str) or not value.strip():
            raise ValueError('manifest: each row needs a class_id')
        ids.append(value)
    if not ids or len(ids) != len(set(ids)):
        raise ValueError('manifest: empty or duplicate case IDs')
    return set(ids)


def check_delivery(manifest: Path, accepted: Path, decisions: Path, lanes: dict[str, Path],
                   research_contract: str | None = None) -> dict:
    paths = lane_paths([f'{name}={path}' for name, path in lanes.items()])
    if accepted.resolve() in {path.resolve() for path in paths.values()}:
        raise ValueError('accepted output must be separate from independent inputs')
    problems, observed = [], {manifest.resolve(): digest(manifest)}
    expected = manifest_ids(manifest)
    decision_bytes = decisions.read_bytes()
    document = load_record(decision_bytes.decode('utf-8'))
    index = document.get('reduction', document)
    if not isinstance(index, dict):
        raise ValueError('reduction must be an object')

    def receipt(value, label):
        if not isinstance(value, dict) or not text(value.get('path')):
            problems.append(f'{label}: needs path and sha256')
            return
        path = (decisions.parent / value['path']).resolve()
        try:
            data = path.read_bytes()
            actual = hashlib.sha256(data).hexdigest()
            if not data or actual != value.get('sha256'):
                problems.append(f'{label}: empty or changed file {path}')
            if path in observed and observed[path] != actual:
                problems.append(f'{label}: changed while checking {path}')
            observed[path] = actual
        except OSError as exc:
            problems.append(f'{label}: {exc}')

    if not text(index.get('reducer')):
        problems.append('reducer: name the sole accountable owner')
    auditors = index.get('auditors')
    if (not isinstance(auditors, list) or not auditors or not all(text(name) for name in auditors)
            or len(auditors) != len(set(auditors))):
        problems.append('auditors: freeze a unique list of all assigned lane names')
    elif set(auditors) != set(paths):
        problems.append(f'auditors: supplied lanes {sorted(paths)} differ from assigned lanes {sorted(auditors)}')
    pins = index.get('pins')
    if not isinstance(pins, dict):
        pins = {}
    for role in sorted(set(PIN_ROLES) | set(pins)):
        receipt(pins.get(role), f'pin {role}')
    runtime_files = {'manifest': manifest, 'record_gate': Path(__file__).with_name('audit_record_gates.py'),
                     'comparison': Path(__file__).with_name('compare_slots.py'),
                     'reduction_gate': Path(__file__)}
    for role, path in runtime_files.items():
        pin = pins.get(role)
        actual = digest(path)
        if path.resolve() in observed and observed[path.resolve()] != actual:
            problems.append(f'pin {role}: changed while checking')
        observed[path.resolve()] = actual
        if isinstance(pin, dict) and pin.get('sha256') != actual:
            problems.append(f'pin {role}: differs from the input or code used for this check')

    roots = {**paths, 'accepted': accepted}
    snapshots = {name: load_snapshot(path) for name, path in roots.items()}
    cases = index.get('cases')
    if not isinstance(cases, dict):
        raise ValueError('decisions need a cases object keyed by class_id')
    contract = index.get('research_contract')
    if contract == RESEARCH_CONTRACT and any(
        key in document or key in index for key in ('dispatch', 'allocation')
    ):
        problems.append('decisions: keep frozen research decisions separate from the mutable dispatch index')
    if research_contract is not None and contract != research_contract:
        problems.append('research_contract: missing or different from the explicitly required contract')
    if contract is not None and contract != RESEARCH_CONTRACT:
        problems.append(f'research_contract: unsupported version {contract!r}')
    if research_contract is not None and research_contract != RESEARCH_CONTRACT:
        problems.append(f'research_contract: unsupported required version {research_contract!r}')
    if contract is None and any(isinstance(case, dict) and 'research' in case for case in cases.values()):
        problems.append('research_contract: research objects require explicit contract adoption')
    for name, keys in [('decisions', set(cases))] + [
        (name, set(records)) for name, (records, _) in snapshots.items()
    ]:
        if keys != expected:
            problems.append(f'{name}: missing={sorted(expected - keys)} extra={sorted(keys - expected)}')

    counts, work_counts = collections.Counter(), collections.Counter()
    worklist, boundaries, unassessed_work = [], [], []
    for cid in sorted(expected):
        decision = cases.get(cid)
        if contract == RESEARCH_CONTRACT:
            before = len(problems)
            errors, dimension_counts, pending, limited = check_research_work(
                decision.get('research') if isinstance(decision, dict) else None, cid, receipt)
            problems.extend(errors)
            work_counts.update(dimension_counts)
            worklist.extend({'class_id': cid, **item} for item in pending)
            boundaries.extend({'class_id': cid, 'dimension': name} for name in limited)
            if len(problems) != before:
                unassessed_work.append(cid)
            if isinstance(decision, dict) and decision.get('status') == 'ACCEPTED' and pending:
                problems.append(f'{cid}: ACCEPTED contradicts unfinished research')
        if not isinstance(decision, dict) or any(cid not in records for records, _ in snapshots.values()):
            counts['PENDING'] += 1
            problems.append(f'{cid}: missing decision or audit record')
            continue
        inputs = {name: snapshots[name][0][cid] for name in paths}
        final = snapshots['accepted'][0][cid]
        bound = decision.get('sha256')
        if not isinstance(bound, dict) or set(bound) != set(roots):
            problems.append(f'{cid}: digest bindings must include exactly all auditor inputs and accepted')
        for name, (records, hashes) in snapshots.items():
            if records[cid].get('class_id') != cid:
                problems.append(f'{cid}: {name} record needs its explicit class_id')
            if not text(records[cid].get('verdict')):
                problems.append(f'{cid}: {name} verdict must be a nonempty string')
            if not isinstance(bound, dict) or bound.get(name) != hashes[cid]:
                problems.append(f'{cid}: {name} digest missing or changed since adjudication')
        problems.extend(check_record(final) + check_record_strict(final))
        if final.get('verdict') != 'FALSE_POSITIVE' and not has_prose(final):
            problems.append(f'{cid}: the accepted record needs its prose in one of {", ".join(PROSE_KEYS)}')
        status = decision.get('status')
        counts[str(status)] += 1
        if status == 'BLOCKED':
            if not text(decision.get('next_question')):
                problems.append(f'{cid}: BLOCKED needs the next decisive question')
            problems.append(f'{cid}: research remains BLOCKED')
        elif status != 'ACCEPTED':
            problems.append(f'{cid}: status must be ACCEPTED or BLOCKED')
        elif final.get('verdict') in ('EVIDENCE_GAP', 'BLOCKED'):
            problems.append(f'{cid}: an open verdict cannot be research ACCEPTED')
        if not text(decision.get('basis')):
            problems.append(f'{cid}: needs the reducer\'s whole-chain acceptance basis')
        reviewed = decision.get('reviewed_dimensions')
        if not isinstance(reviewed, list) or set(map(str, reviewed)) != set(RESEARCH_FIELDS):
            problems.append(f'{cid}: explicitly review every research dimension')
        required = set(research_differences_many({**inputs, 'accepted': final}))
        all_records = [*inputs.values(), final]
        if any(text(r.get('verdict')) and r['verdict'] in AI_VERDICTS for r in all_records):
            required.update(('bic', 'ai', 'fix'))
        if any(review_signals(r) for r in all_records):
            required.add('residual')
        if any(check_record(r) + check_record_strict(r) for r in inputs.values()):
            required.add('input_quality')
        resolutions = decision.get('resolutions')
        if not isinstance(resolutions, dict):
            resolutions = {}
        if contract == RESEARCH_CONTRACT:
            required.update(resolutions)
        for dimension in sorted(required):
            resolution = resolutions.get(dimension)
            if contract == RESEARCH_CONTRACT:
                if not isinstance(resolution, dict):
                    problems.append(f'{cid}: unresolved {dimension}; needs structured claims, observation, reasoning and conclusion')
                    continue
                claims = resolution.get('claims')
                if not isinstance(claims, dict) or set(claims) != set(paths) or not all(text(v) for v in claims.values()):
                    problems.append(f'{cid}: {dimension} claims must account for every assigned lane')
                for key in ('observation', 'reasoning', 'conclusion'):
                    if not text(resolution.get(key)):
                        problems.append(f'{cid}: {dimension} resolution needs {key}')
                if not isinstance(resolution.get('evidence'), list) or not resolution['evidence']:
                    problems.append(f'{cid}: {dimension} resolution needs primary receipts')
                else:
                    for item in resolution['evidence']:
                        receipt(item, f'{cid} {dimension} resolution evidence')
            elif not text(resolution):
                problems.append(f'{cid}: unresolved {dimension}; explain the competing readings and evidence')
        evidence = decision.get('evidence')
        if not isinstance(evidence, list) or not evidence:
            problems.append(f'{cid}: retain primary evidence receipts')
        else:
            for item in evidence:
                receipt(item, f'{cid} evidence')

    for name, path in roots.items():
        if load_snapshot(path)[1] != snapshots[name][1]:
            problems.append(f'{name}: records changed while checking')
    if decisions.read_bytes() != decision_bytes:
        problems.append('decisions changed while checking')
    for path, original in observed.items():
        try:
            if digest(path) != original:
                problems.append(f'{path}: changed while checking')
        except OSError as exc:
            problems.append(str(exc))
    return {'cases': len(expected), 'auditors': list(paths), 'research_status': dict(counts),
            'research_work': {'contract': contract, 'checked': contract == RESEARCH_CONTRACT,
                              'dimension_counts': dict(work_counts),
                              'worklist': worklist, 'evidence_boundaries': boundaries,
                              'unassessed_cases': unassessed_work,
                              'scope': 'declared work only; route discovery and causal truth require review'},
            'delivery_valid': not problems, 'problems': problems,
            'decisions_sha256': hashlib.sha256(decision_bytes).hexdigest(),
            'scope': 'delivery integrity; causal truth and publication require separate review'}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a reducer's evidence-backed decisions against exact input/output bytes")
    for name in ('manifest', 'accepted', 'decisions'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--lane', action='append', help='NAME=PATH; repeat for all assigned auditors')
    parser.add_argument('--research-contract', choices=[RESEARCH_CONTRACT],
                        help='require the explicitly adopted research-work contract')
    args = parser.parse_args()
    try:
        report = check_delivery(args.manifest, args.accepted, args.decisions, lane_paths(args.lane),
                                research_contract=args.research_contract)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['delivery_valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
