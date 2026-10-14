#!/usr/bin/env python3
"""Bind a foreground audit command to a batch before dispatch or resumption.

Task bindings live under `dispatch` in research/<batch>/index.json. This is a
coordination guard, not a filesystem sandbox or a research-acceptance gate.
"""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

import claims
from audit_record_gates import load_record
from audit_reduction_gate import digest, manifest_ids

RESEARCH = Path(__file__).resolve().parents[1] / 'research'
ROLES = {'auditor', 'adjudicator'}
ENDPOINTS = {'research', 'ledger', 'site'}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def authorize(batch: str, receipt: dict) -> dict:
    """Check the original leader credential, without adopting an existing directory."""
    allotted = allocation(batch)
    binding = allotted['binding']
    if (receipt.get('batch') != batch
            or receipt.get('allocation_sha256') != allotted['sha256']
            or not isinstance(receipt.get('batch_token'), str)
            or hashlib.sha256(receipt['batch_token'].encode()).hexdigest() != binding['receipt_sha256']):
        raise ValueError('original leader batch receipt required')
    return binding


def stop(batch: str, receipt: dict, reason: str, evidence: Path) -> dict:
    """Block new research; process shutdown and stopped-work handoffs remain explicit."""
    if reason not in {'safety_refusal', 'operating_stop'}:
        raise ValueError('stop reason must be safety_refusal or operating_stop')
    with lock(RESEARCH / '.dispatch.lock'):
        authorize(batch, receipt)
        path = index_path(batch)
        document = read_index(path)
        record = {'at': now(), 'reason': reason, 'evidence': snapshot(evidence),
                  'status': 'STOP_REQUESTED', 'scope': 'new research dispatch; not process shutdown or claim release'}
        document.setdefault('stops', []).append(record)
        write_index(path, document)
    return record


def require_running_scope(document: dict) -> None:
    if document.get('stops'):
        raise ValueError('batch stopped: preserve the refusal/stop; no new research or resumption')


def binding_hash(binding: dict) -> str:
    return hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()


def read_index(path: Path) -> dict:
    return load_record(path.read_text()) if path.exists() else {}


def write_index(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.index-')
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, indent=2, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextlib.contextmanager
def lock(path: Path, *, nonblocking: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        except BlockingIOError as exc:
            raise ValueError('agent already has a running dispatch') from exc
        yield


def index_path(batch: str) -> Path:
    if not isinstance(batch, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', batch):
        raise ValueError('batch must be a stable directory identifier')
    path = RESEARCH / batch / 'index.json'
    if path.resolve() != path.absolute():
        raise ValueError('batch index must not be redirected by a symlink')
    return path


def overlap(a: Path, b: Path) -> bool:
    return a == b or a in b.parents or b in a.parents


def snapshot(path: Path) -> dict[str, str]:
    if not path.exists() or path.is_symlink():
        raise ValueError(f'missing or symlinked input: {path}')
    files = sorted(path.rglob('*')) if path.is_dir() else [path]
    if any(p.is_symlink() for p in files):
        raise ValueError(f'input tree contains a symlink: {path}')
    result = {str(p.resolve()): digest(p) for p in files if p.is_file()}
    if not result:
        raise ValueError(f'empty input: {path}')
    return result


def claim_tokens(batch: str, leader: str, ids: set[str]) -> dict[str, list[str]]:
    current = claims.state(claims.load(claims.DEFAULT_CLAIMS))
    tokens = {}
    for cid in ids:
        holders = claims.occupancy(current, cid)['holders']
        if not holders or any(h['owner'] != leader or h['scope'] != batch for h in holders):
            raise ValueError(f'{cid}: leader must hold the canonical claim for this exact batch')
        tokens[cid] = sorted(h['claim_id'] for h in holders)
    return tokens


def create(spec: dict) -> dict:
    """Create a fresh batch; return its registration credential only to the leader."""
    if (set(spec) != {'batch', 'leader', 'endpoint', 'manifest'}
            or not all(isinstance(v, str) and v.strip() for v in spec.values())
            or spec['endpoint'] not in ENDPOINTS):
        raise ValueError('batch spec needs batch, leader, endpoint and source manifest')
    path = index_path(spec['batch'])
    source = Path(spec['manifest'])
    content = source.read_bytes()
    ids = manifest_ids(source)
    if source.read_bytes() != content:
        raise ValueError('source manifest changed while creating batch')
    manifest = path.parent / ('manifest.jsonl' if source.suffix == '.jsonl' else 'manifest.txt')
    token = secrets.token_hex(32)
    binding = {**spec, 'manifest': {'path': str(manifest), 'sha256': hashlib.sha256(content).hexdigest()},
               'case_ids': sorted(ids), 'receipt_sha256': hashlib.sha256(token.encode()).hexdigest()}
    with lock(RESEARCH / '.dispatch.lock'):
        if path.parent.exists():
            raise ValueError('batch directory already exists; a new task cannot adopt it')
        current = claims.state(claims.load(claims.DEFAULT_CLAIMS))
        for cid in sorted(ids):
            if claims.occupancy(current, cid)['claimed']:
                raise ValueError(f'{cid}: already claimed; select an unoccupied case for the new batch')
        path.parent.mkdir()
        with manifest.open('xb') as out:
            out.write(content)
        write_index(path, {'allocation': {'binding': binding, 'sha256': binding_hash(binding)}})
    return {'batch': spec['batch'], 'manifest': str(manifest), 'cases': len(ids),
            'allocation_sha256': binding_hash(binding), 'batch_token': token}


def allocation(batch: str) -> dict:
    entry = read_index(index_path(batch)).get('allocation')
    if (not isinstance(entry, dict) or not isinstance(entry.get('binding'), dict)
            or entry.get('sha256') != binding_hash(entry['binding'])
            or entry['binding'].get('batch') != batch):
        raise ValueError('missing or changed batch allocation; never infer ownership from existing files')
    return entry


def verify(binding: dict) -> None:
    allotted = allocation(binding['batch'])
    if (binding.get('allocation_sha256') != allotted['sha256']
            or any(binding[k] != allotted['binding'][k]
                   for k in ('batch', 'leader', 'endpoint', 'manifest', 'case_ids'))):
        raise ValueError('task differs from the leader-created batch allocation')
    batch_root = index_path(binding['batch']).parent
    manifest = Path(binding['manifest']['path'])
    if manifest.resolve().parent != batch_root or digest(manifest) != binding['manifest']['sha256']:
        raise ValueError('manifest path or bytes changed; do not silently re-pin')
    ids = manifest_ids(manifest)
    cwd, output = Path(binding['cwd']), Path(binding['output'])
    if (not cwd.is_dir() or cwd.resolve() != cwd or output.resolve() != output
            or batch_root not in output.parents or (output.exists() and not output.is_dir())
            or overlap(output, manifest) or overlap(output, index_path(binding['batch']))):
        raise ValueError('cwd/output moved or output is outside the assigned batch')
    for path, hashes in binding['inputs'].items():
        if overlap(output, Path(path)):
            raise ValueError('output overlaps a frozen input')
        if snapshot(Path(path)) != hashes:
            raise ValueError(f'input changed since registration: {path}')
    if sorted(ids) != binding['case_ids'] or claim_tokens(binding['batch'], binding['leader'], ids) != binding['claim_ids']:
        raise ValueError('case ownership changed; the old task cannot use a new claim acquisition')


def check_peers(binding: dict) -> None:
    for path in RESEARCH.glob('*/index.json'):
        for name, entry in read_index(path).get('dispatch', {}).items():
            other = entry['binding']
            if entry['sha256'] != binding_hash(other):
                raise ValueError(f'changed peer binding: {path}/{name}')
            if path == index_path(binding['batch']) and name == binding['task']:
                continue
            if overlap(Path(binding['output']), Path(other['output'])):
                raise ValueError(f'output already owned by {other["batch"]}/{name}; use a new attempt directory')
            if not entry['active']:
                continue
            if (any(overlap(Path(binding['output']), Path(p)) for p in other['inputs'])
                    or any(overlap(Path(other['output']), Path(p)) for p in binding['inputs'])):
                raise ValueError('an input is still owned by an active writer; seal and retire its assignment first')
            if binding['agent'] == other['agent']:
                raise ValueError(f'agent already assigned to {other["batch"]}/{name}; stop and retire it before rebinding')
            if binding['batch'] == other['batch']:
                if any(binding[k] != other[k] for k in ('manifest', 'leader', 'endpoint')):
                    raise ValueError('same batch has conflicting manifest, leader or endpoint')
                if binding['role'] == other['role'] == 'adjudicator':
                    raise ValueError('batch already has an adjudicator')
            elif set(binding['case_ids']) & set(other['case_ids']):
                raise ValueError(f'case IDs overlap active batch {other["batch"]}; independent lanes belong to one batch')


def runner_ready(binding: dict) -> None:
    if binding['command'][:3] != ['herdr', 'agent', 'prompt']:
        return
    if os.environ.get('HERDR_ENV') != '1':
        raise ValueError('Herdr dispatch requires HERDR_ENV=1')
    result = subprocess.run(['herdr', 'agent', 'get', binding['agent']], capture_output=True,
                            text=True, check=False, timeout=10)
    if result.returncode:
        raise ValueError('cannot verify the Herdr target; inspect it before dispatch')
    agent = json.loads(result.stdout)['result']['agent']
    if (agent.get('pane_id') != binding['agent'] or agent.get('cwd') != binding['cwd']
            or agent.get('agent_status') not in {'idle', 'done'}):
        raise ValueError('Herdr target must be the bound pane/cwd and idle or done; inspect before resuming')


def register(spec: dict, *, batch_receipt: dict) -> dict:
    required = {'batch', 'task', 'agent', 'role', 'leader', 'endpoint', 'manifest',
                'cwd', 'output', 'brief', 'inputs', 'command'}
    if set(spec) not in (required, required | {'skill'}):
        raise ValueError(f'task spec needs {sorted(required)} and optional skill')
    for key in set(spec) - {'inputs', 'command'}:
        if not isinstance(spec[key], str) or not spec[key].strip():
            raise ValueError(f'{key} must be nonempty text')
    if spec['role'] not in ROLES or spec['endpoint'] not in ENDPOINTS:
        raise ValueError('invalid role or authorized endpoint')
    command = spec['command']
    if not isinstance(command, list) or not all(isinstance(x, str) and x for x in command) or command.count('{brief}') != 1:
        raise ValueError('command must be an argv list with exactly one {brief} argument')
    if command[:3] == ['herdr', 'agent', 'prompt'] and (
            len(command) < 6 or command[3] != spec['agent'] or command[4] != '{brief}'
            or '--wait' not in command or '--until' in command):
        raise ValueError('Herdr target must equal agent, text must be {brief}, and use default --wait')
    if not isinstance(spec['inputs'], list) or not all(isinstance(p, str) and p for p in spec['inputs']):
        raise ValueError('inputs must be a list of files or small sealed directories')
    if not Path(spec['brief']).read_text().strip():
        raise ValueError('brief must contain the assigned work')
    if 'skill' in spec and (not Path(spec['skill']).is_file() or not Path(spec['skill']).read_text().strip()):
        raise ValueError('skill must be a nonempty file')
    binding = dict(spec)
    for key in ('manifest', 'cwd', 'output', 'brief', 'skill'):
        if key in spec:
            binding[key] = str(Path(spec[key]).resolve())
    binding['inputs'] = {}
    sources = [spec['brief'], *spec['inputs']]
    if 'skill' in spec:
        sources.append(spec['skill'])
    for value in sources:
        source = Path(value).absolute()
        binding['inputs'][str(source.resolve())] = snapshot(source)
    binding['manifest'] = {'path': binding['manifest'], 'sha256': digest(Path(binding['manifest']))}
    binding['case_ids'] = sorted(manifest_ids(Path(binding['manifest']['path'])))
    path = index_path(binding['batch'])
    # ponytail: one short project lock; shard only if registration becomes a bottleneck.
    with lock(RESEARCH / '.dispatch.lock'):
        allotted = allocation(binding['batch'])
        token = batch_receipt.get('batch_token') if isinstance(batch_receipt, dict) else None
        if (not isinstance(token, str) or batch_receipt.get('batch') != binding['batch']
                or batch_receipt.get('allocation_sha256') != allotted['sha256']
                or not secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(),
                                              allotted['binding']['receipt_sha256'])):
            raise ValueError('registration requires the original leader batch receipt')
        binding['allocation_sha256'] = allotted['sha256']
        document = read_index(path)
        require_running_scope(document)
        tasks = document.setdefault('dispatch', {})
        if binding['task'] in tasks:
            raise ValueError('task already registered; check/resume its original binding or name a new attempt')
        binding['claim_ids'] = claim_tokens(binding['batch'], binding['leader'], set(binding['case_ids']))
        verify(binding)
        check_peers(binding)
        tasks[binding['task']] = {'binding': binding, 'sha256': binding_hash(binding), 'active': True, 'dispatched': False}
        write_index(path, document)
    return {'index': str(path), 'batch': binding['batch'], 'task': binding['task'], 'binding_sha256': binding_hash(binding)}


def checked(batch: str, task: str, expected_hash: str) -> tuple[Path, dict, dict]:
    path = index_path(batch)
    document = read_index(path)
    entry = document.get('dispatch', {}).get(task)
    if not isinstance(entry, dict) or not entry.get('active'):
        raise ValueError('task is absent or retired in the requested batch')
    binding = entry['binding']
    if binding['batch'] != batch or binding['task'] != task or binding_hash(binding) != expected_hash or entry['sha256'] != expected_hash:
        raise ValueError('wrong or changed task binding; recover the original registration receipt')
    return path, document, entry


def act(batch: str, task: str, expected_hash: str, action: str, *, resume: bool = False,
        inspection: Path | None = None) -> dict:
    if action not in {'check', 'run', 'retire'}:
        raise ValueError('invalid dispatch action')
    with contextlib.ExitStack() as running:
        with lock(RESEARCH / '.dispatch.lock'):
            path, document, entry = checked(batch, task, expected_hash)
            binding = entry['binding']
            receipt = {'batch': batch, 'task': task, 'role': binding['role'], 'agent': binding['agent'],
                       'cases': len(binding['case_ids']), 'binding_sha256': expected_hash, 'action': action}
            if action != 'retire':
                verify(binding)
                check_peers(binding)
            if action == 'run':
                require_running_scope(document)
            if action == 'check':
                return receipt
            agent_key = hashlib.sha256(binding['agent'].encode()).hexdigest()
            running.enter_context(lock(RESEARCH / '.dispatch-locks' / agent_key, nonblocking=True))
            if action == 'retire':
                entry['active'] = False
                write_index(path, document)
                return receipt
            if entry['dispatched'] != resume:
                raise ValueError('already dispatched: inspect the runner then use --resume; a first dispatch must omit --resume')
            previous = entry.get('attempts', [])
            needs_inspection = resume and (not previous or previous[-1].get('command_exit') != 0)
            if needs_inspection and inspection is None:
                raise ValueError('failed or ambiguous execution: inspect original receipts and surviving workers; supply --inspection')
            if inspection is not None:
                reviewed = load_record(inspection.read_text())
                if (reviewed.get('batch') != batch or reviewed.get('task') != task
                        or reviewed.get('binding_sha256') != expected_hash
                        or reviewed.get('attempt_id') != (previous[-1]['attempt_id'] if previous else None)
                        or reviewed.get('classification') not in {'runtime_fault', 'delivery_fault'}
                        or reviewed.get('previous_work_stopped') is not True or not reviewed.get('evidence')):
                    raise ValueError('inspection must bind the original attempt, eligible fault and stopped-work evidence')
                for pin in reviewed['evidence']:
                    if digest(Path(pin['path'])) != pin['sha256']:
                        raise ValueError('inspection evidence changed')
            inspected = snapshot(inspection) if inspection is not None else None
            runner_ready(binding)
            entry['dispatched'] = True  # Persist before sending: ambiguous delivery must never auto-retry.
            attempt = {**receipt, 'attempt_id': secrets.token_hex(16), 'started_at': now(),
                       'mode': 'resume' if resume else 'start', 'status': 'STARTED',
                       'command_exit': None, 'inspection': inspected}
            entry.setdefault('attempts', []).append(attempt)
            write_index(path, document)
            brief_bytes = Path(binding['brief']).read_bytes()
            expected_brief = next(hashes[binding['brief']] for hashes in binding['inputs'].values() if binding['brief'] in hashes)
            if hashlib.sha256(brief_bytes).hexdigest() != expected_brief:
                raise ValueError('brief changed while preparing dispatch')
            brief = brief_bytes.decode('utf-8')
            header = (f'Task binding: {expected_hash}\nBatch: {batch}\nTask: {task}\n'
                      f'Role: {binding["role"]}\nManifest: {binding["manifest"]["path"]}\n'
                      f'Manifest SHA256: {binding["manifest"]["sha256"]}\n'
                      f'Owned output: {binding["output"]}\nAuthorized endpoint: {binding["endpoint"]}\n'
                      f'Pinned inputs: {", ".join(binding["inputs"])}\nMode: {"resume" if resume else "start"}\n'
                      + (f'Read and apply the frozen role skill: {binding["skill"]}\n' if 'skill' in binding else '') +
                      'Read the frozen protocols, schema and gate code in the pinned inputs; they govern.\n' +
                      'Keep this task identity on resumption. Do not infer scope from tab names or neighboring reports.\n\n')
            command = [header + brief if part == '{brief}' else part for part in binding['command']]
        try:
            completed = subprocess.run(command, cwd=binding['cwd'], check=False)
        except OSError as exc:
            attempt.update(status='LAUNCH_FAILED', finished_at=now(), error=str(exc))
            persist_attempt(batch, task, expected_hash, attempt)
            raise
        attempt.update(status='RETURNED', finished_at=now(), command_exit=completed.returncode,
                       scope='command execution only; not research acceptance or publication')
        persist_attempt(batch, task, expected_hash, attempt)
        return attempt


def persist_attempt(batch: str, task: str, expected_hash: str, attempt: dict) -> None:
    with lock(RESEARCH / '.dispatch.lock'):
        path, document, entry = checked(batch, task, expected_hash)
        if entry['attempts'][-1]['attempt_id'] != attempt['attempt_id']:
            raise ValueError('attempt changed while runner was active')
        entry['attempts'][-1] = attempt
        write_index(path, document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('create', help='leader creates a new batch; existing directories are refused').add_argument('spec', type=Path)
    registration = sub.add_parser('register', help='leader assigns a task within its created batch')
    registration.add_argument('spec', type=Path)
    registration.add_argument('--batch-receipt', type=Path, required=True,
                              help='leader-only JSON receipt returned by create')
    stopping = sub.add_parser('stop', help='leader records a refusal/operating stop; does not signal processes')
    stopping.add_argument('--batch', required=True)
    stopping.add_argument('--batch-receipt', type=Path, required=True)
    stopping.add_argument('--reason', choices=['safety_refusal', 'operating_stop'], required=True)
    stopping.add_argument('--evidence', type=Path, required=True)
    for action in ('check', 'run', 'retire'):
        p = sub.add_parser(action)
        for key in ('batch', 'task', 'binding'):
            p.add_argument('--' + key, required=True)
        if action == 'run':
            p.add_argument('--resume', action='store_true')
            p.add_argument('--inspection', type=Path, help='retained diagnosis and verification that prior work stopped')
    args = parser.parse_args()
    try:
        if args.action == 'create':
            result = create(load_record(args.spec.read_text()))
        elif args.action == 'register':
            result = register(load_record(args.spec.read_text()),
                              batch_receipt=load_record(args.batch_receipt.read_text()))
        elif args.action == 'stop':
            result = stop(args.batch, load_record(args.batch_receipt.read_text()), args.reason, args.evidence)
        else:
            result = act(args.batch, args.task, args.binding, args.action,
                         resume=getattr(args, 'resume', False), inspection=getattr(args, 'inspection', None))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, claims.ClaimsError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return result.get('command_exit', 0)


if __name__ == '__main__':
    raise SystemExit(main())
