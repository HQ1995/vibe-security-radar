#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import time
import urllib.error
import urllib.request
import uuid

import audit_delivery as delivery
import audit_dispatch as dispatch
import claims
import ledger_store
import radar_flow
import radar_release

REPO = Path(__file__).resolve().parents[1]
RUNS = REPO / '.ai-slop' / 'runs'
BRIEFS = REPO / '.agents' / 'skills' / 'radar-lead' / 'briefs'
CONTRACT_VERSION = '2026-10-14.1'
LANES = ('auditor1', 'auditor2')
ROLE_SKILL = {'auditor': 'radar-audit', 'adjudicator': 'radar-adjudicate', 'reviewer': 'radar-lead'}
ROLE_SKILLS = {'auditor': ['radar-audit'], 'adjudicator': ['radar-adjudicate', 'radar-audit'],
               'reviewer': ['radar-lead', 'radar-adjudicate', 'radar-audit']}
LEADER_ONLY = {'radar-lead'}
WORKER_SCRIPTS = ('audit_record_gates', 'audit_reduction_gate', 'compare_slots', 'audit_delivery', 'radar_flow')
AI_STATUSES = {'AI_ROOT_CAUSE', 'AI_CODE_FLAWED'}
LANDABLE = ledger_store.TERMINAL_STATUSES - {'BLOCKED'}
FINISHED = {'LANDED', 'BLOCKED_CLOSED', 'FOREIGN_HOLD', 'RESEARCH_HANDOFF'}
WAITING = {'SAFETY_STOP', 'READY_TO_LAND', 'RETURNED'}
GITHUB_API_VERSION = '2026-03-10'
RESOURCE_WAITS = 20


def save(path: Path, value: dict, *, exclusive: bool = False) -> None:
    if exclusive:
        with path.open('x') as out:
            json.dump(value, out, indent=2, sort_keys=True)
            out.write('\n')
    else:
        dispatch.write_index(path, value)


def run_dir(name: str) -> Path:
    dispatch.index_path(name)
    return RUNS / name


def cases(name: str) -> list[Path]:
    return sorted(p for p in (run_dir(name) / 'cases').glob('[0-9][0-9][0-9]') if (p / 'case.json').exists())


def set_state(case: Path, phase: str, **detail) -> dict:
    state = {'phase': phase, 'at': dispatch.now(), **detail}
    save(case / 'state.json', state)
    return state


def state_of(case: Path) -> dict:
    path = case / 'state.json'
    return delivery.read(path) if path.exists() else {'phase': 'ADMITTED'}


def import_closure(roots, scripts: Path = REPO / 'scripts') -> list[str]:
    seen, todo = set(), list(roots)
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for node in ast.walk(ast.parse((scripts / f'{name}.py').read_text())):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module]
            else:
                continue
            todo += [n for n in names if (scripts / f'{n}.py').is_file()]
    return sorted(seen)


def freeze_contract(dest: Path) -> dict:
    scripts = [f'scripts/{name}.py' for name in import_closure(WORKER_SCRIPTS)]
    for role, skills in ROLE_SKILLS.items():
        docs = []
        for skill in skills:
            root = REPO / '.agents' / 'skills' / skill
            references = [] if skill in LEADER_ONLY else sorted((root / 'references').glob('*.md'))
            docs += [str(p.relative_to(REPO)) for p in [root / 'SKILL.md', *references]]
        for rel in [*docs, *scripts]:
            target = dest / role / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / rel, target)
    for name in ('auditor.md', 'adjudicator.md', 'reviewer.md', 'workspace-AGENTS.md'):
        (dest / 'briefs').mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BRIEFS / name, dest / 'briefs' / name)
    return dispatch.snapshot(dest)


def command(profile: dict, role: str, lane: str, cwd: Path, output: Path, ro_paths: list[Path]) -> list[str]:
    values = {'timeout': str(profile['timeout_seconds'][role]), 'memory_bytes': str(profile['memory_bytes']),
              'model': profile['models'][lane], 'output': str(output), 'cwd': str(cwd)}

    def fill(part: str) -> str:
        return part if part == '{brief}' else part.format_map(values)

    argv = [fill(part) for part in profile.get('prefix', [])]
    box = profile.get('sandbox')
    if box:
        if box.get('kind') != 'bwrap':
            raise ValueError('only the bwrap sandbox is supported')
        argv += ['bwrap', '--die-with-parent', '--unshare-pid', '--ro-bind', '/', '/']
        for masked in box.get('mask', []):
            argv += ['--tmpfs', masked]
        argv += ['--ro-bind', str(cwd), str(cwd), '--bind', str(output), str(output)]
        if box.get('home'):
            home = output / 'runtime-home'
            home.mkdir(parents=True, exist_ok=True)
            argv += ['--bind', str(home), box['home']]
        for path in [*box.get('ro_binds', []), *map(str, ro_paths), *profile.get('shared_clones', [])]:
            argv += ['--ro-bind', path, path]
        argv += ['--dev-bind', '/dev', '/dev', '--proc', '/proc', '--chdir', str(cwd), '--']
    argv += [fill(part) for part in profile['agent']]
    if argv.count('{brief}') != 1:
        raise ValueError('runner profile must pass {brief} exactly once')
    return argv


def fetch_advisory(advisory_id: str, path: Path) -> dict:
    upper = advisory_id.upper()
    if upper.startswith('GHSA-'):
        url = 'https://api.github.com/advisories/' + advisory_id
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': GITHUB_API_VERSION}
        if os.environ.get('GITHUB_TOKEN'):
            headers['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
        pause = 0.3
    elif upper.startswith('CVE-'):
        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + upper
        headers = {'Accept': 'application/json'}
        if os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        pause = 0.7 if 'apiKey' in headers else 6.1
    else:
        return {'retained': False, 'note': 'unrecognized identifier; retrieve the official record yourself'}
    time.sleep(pause)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    started = dispatch.now()
    try:
        response = urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, headers=headers), timeout=45)
        status, body = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        return {'retained': False, 'url': url, 'started_at': started, 'error': str(exc)}
    path.write_bytes(body)
    return {'retained': status == 200, 'url': url, 'status': status, 'file': path.name,
            'sha256': dispatch.digest(path), 'started_at': started, 'captured_at': dispatch.now()}


def neutral_packet(dest: Path, row: dict, cutoff: str, fetch) -> None:
    dest.mkdir(parents=True)
    sources = []
    for number, advisory in enumerate(row['advisory_ids']):
        if fetch:
            entry = fetch(advisory, dest / f'{number:02d}-{advisory}.json')
        else:
            entry = {'retained': False, 'note': 'not retained at admission; retrieve the official record yourself'}
        sources.append({'id': advisory, **entry})
    save(dest / 'SOURCES.json', {'cutoff': cutoff, 'sources': sources})
    (dest / 'README.md').write_text(
        f"# Case {row['class_id']}\n\n"
        f"Advisory IDs: {', '.join(row['advisory_ids'])}\n"
        f"Advisory-side repository: {row.get('repo') or 'not recorded'}\n"
        f"Source coverage cutoff: {cutoff}\n\n"
        "Answer the four questions of the audit protocol for this advisory cluster: cause,\n"
        "impact, history (introduction, exposure, repair, release) and AI role. SOURCES.json\n"
        "lists the advisory records retained here; retrieve anything else from primary sources.\n")


def brief(run: dict, template: str, **values) -> str:
    text = (run_dir(run['run']) / 'contract' / 'briefs' / template).read_text()
    clones = run['profile'].get('shared_clones', [])
    shared = ('Shared read-only product clones (primary sources, not judgments): ' + ', '.join(clones) + '\n'
              if clones else '')
    return text.format_map({'leader': run['leader'], 'cutoff': run['cutoff'], 'contract_version': CONTRACT_VERSION,
                            'shared_clones': shared, **values})


def task_spec(run: dict, case: dict, task: str, role: str, extra_inputs: list[Path], **values) -> dict:
    batch_root = dispatch.index_path(case['batch']).parent
    cwd = (batch_root / task / 'workspace').resolve()
    cwd.mkdir(parents=True)
    frozen = run_dir(run['run']) / 'contract'
    shutil.copytree(frozen / role, cwd / 'contract')
    shutil.copytree(run_dir(run['run']) / 'cases' / case['key'] / 'neutral', cwd / 'inputs')
    shutil.copyfile(frozen / 'briefs' / 'workspace-AGENTS.md', cwd / 'AGENTS.md')
    output = cwd / 'output'
    output.mkdir()
    briefs = batch_root / 'briefs'
    briefs.mkdir(exist_ok=True)
    skill = cwd / 'contract' / '.agents' / 'skills' / ROLE_SKILL[role] / 'SKILL.md'
    agent = f"{case['batch']}-{task}"
    text = brief(run, f'{role}.md', agent=agent, lane=task, case_id=case['class_id'], batch=case['batch'],
                 advisory_ids=', '.join(case['advisory_ids']), repo=case.get('repo') or 'not recorded',
                 output=output, cwd=cwd, manifest=case['manifest'], skill_path=skill,
                 minutes=run['profile']['timeout_seconds'][role] // 60, **values)
    (briefs / f'{task}.md').write_text(text)
    inputs = [cwd / 'contract', cwd / 'inputs', cwd / 'AGENTS.md', *extra_inputs]
    ro_paths = [briefs / f'{task}.md', Path(case['manifest']), *extra_inputs]
    return {'batch': case['batch'], 'task': task, 'agent': agent, 'role': role, 'leader': run['leader'],
            'endpoint': run['endpoint'], 'manifest': case['manifest'], 'cwd': str(cwd), 'output': str(output),
            'brief': str(briefs / f'{task}.md'), 'skill': str(skill), 'inputs': [str(p) for p in inputs],
            'command': command(run['profile'], role, task, cwd, output, ro_paths)}


def ledger(case: Path, *args: str, structured: bool = True):
    return radar_release.ledger(case / 'ledger-receipts', *args, structured=structured)


def load_run(name: str) -> dict:
    return delivery.read(run_dir(name) / 'run.json')


def admit(name: str, manifest: Path, leader: str, endpoint: str, profile_path: Path, cutoff: str,
          fetch: bool = True) -> list[dict]:
    root = run_dir(name)
    if not (root / 'run.json').exists():
        if endpoint not in {'research', 'ledger'}:
            raise ValueError('a run ends at research handoff or ledger landing; publication follows the runbook')
        root.mkdir(parents=True)
        profile = delivery.read(profile_path)
        contract = freeze_contract(root / 'contract')
        save(root / 'run.json', {'run': name, 'leader': leader, 'endpoint': endpoint, 'cutoff': cutoff,
                                 'profile': profile, 'profile_source': str(profile_path.resolve()),
                                 'contract_version': CONTRACT_VERSION, 'contract': contract,
                                 'created_at': dispatch.now()}, exclusive=True)
    run = load_run(name)
    if run['leader'] != leader or run['endpoint'] != endpoint:
        raise ValueError('an existing run keeps its leader and endpoint')
    for path, sha in run['contract'].items():
        if dispatch.digest(Path(path)) != sha:
            raise ValueError('frozen run contract changed; start a new run')
    known = {delivery.read(c / 'case.json')['class_id'] for c in cases(name)}
    wanted = [line.strip() for line in manifest.read_text().splitlines() if line.strip()]
    results = []
    for class_id in wanted:
        if class_id in known:
            continue
        key = f'{len(list((root / "cases").glob("[0-9][0-9][0-9]"))) + 1:03d}'
        known.add(class_id)
        results.append(admit_case(run, key, class_id, fetch_advisory if fetch else None))
    return results


def admit_case(run: dict, key: str, class_id: str, fetch) -> dict:
    case_dir = run_dir(run['run']) / 'cases' / key
    case_dir.mkdir(parents=True)
    current = ledger(case_dir, 'get', class_id)
    row = current['row']
    batch = f"{run['run']}-{key}"
    case = {'key': key, 'class_id': class_id, 'batch': batch, 'advisory_ids': row['advisory_ids'],
            'repo': row.get('repo'), 'admitted_at': dispatch.now()}
    occupancy = claims.state(claims.load(claims.DEFAULT_CLAIMS))
    names = {class_id, *row['advisory_ids'], *(a.lower() for a in row['advisory_ids'])}
    holders = [claims.occupancy(occupancy, n) for n in sorted(names) if claims.occupancy(occupancy, n)['claimed']]
    save(case_dir / 'case.json', case, exclusive=True)
    if holders:
        return {'case': key, **set_state(case_dir, 'FOREIGN_HOLD', holders=holders,
                                         next_action='Arrange a real handoff with the holder; expiry is not release.')}
    (case_dir / 'manifest.txt').write_text(class_id + '\n')
    receipt = dispatch.create({'batch': batch, 'leader': run['leader'], 'endpoint': run['endpoint'],
                               'manifest': str(case_dir / 'manifest.txt')})
    save(case_dir / 'batch-receipt.json', receipt, exclusive=True)
    (case_dir / 'batch-receipt.json').chmod(0o600)
    save(case_dir / 'claim.json', claims.claim(claims.DEFAULT_CLAIMS, class_id, run['leader'], scope=batch),
         exclusive=True)
    save(case_dir / 'base.json', {'revision': current['revision'], 'change_set_id': current['change_set_id'],
                                  'row_sha256': ledger_store.sha256(ledger_store.raw_row(row))}, exclusive=True)
    neutral_packet(case_dir / 'neutral', row, run['cutoff'], fetch)
    case['manifest'] = receipt['manifest']
    save(case_dir / 'case.json', case)
    auditors = []
    for lane in LANES:
        spec = task_spec(run, case, lane, 'auditor', [])
        auditors.append({**dispatch.register(spec, batch_receipt=receipt), 'lane': lane})
    outputs = [Path(dispatch.read_index(dispatch.index_path(batch))['dispatch'][lane]['binding']['output'])
               for lane in LANES]
    lanes = '\n'.join(f'  {lane}: {out}' for lane, out in zip(LANES, outputs))
    lane_args = ' '.join(f'--lane {lane}={out}/{class_id}/record.json' for lane, out in zip(LANES, outputs))
    adjudicator = task_spec(run, case, 'adjudicator', 'adjudicator', outputs, n=len(LANES), lanes=lanes,
                            lane_names=json.dumps(list(LANES)), lane_args=lane_args)
    save(case_dir / 'plan.json', {'batch': batch, 'n': len(LANES), 'auditors': auditors,
                                  'adjudicator': adjudicator}, exclusive=True)
    return {'case': key, **set_state(case_dir, 'ADMITTED', class_id=class_id, batch=batch)}


def node_capacity(node: int) -> int:
    fields = {}
    for line in Path(f'/sys/devices/system/node/node{node}/meminfo').read_text().splitlines():
        parts = line.split()
        fields[parts[2].rstrip(':')] = int(parts[3]) * 1024
    return fields['MemFree'] + fields['FilePages'] + fields['SReclaimable'] - fields['Shmem']


def refusal(run: dict, batch: str) -> dict | None:
    markers = [m.lower() for m in run['profile'].get('refusal_markers', [])]
    for path in sorted((dispatch.index_path(batch).parent / '.logs').glob('*.std*')):
        text = path.read_text(errors='replace').lower()
        found = next((m for m in markers if m in text), None)
        if found:
            return {'path': str(path), 'sha256': dispatch.digest(path), 'marker': found}
    return None


def stop_for_refusal(run: dict, case_dir: Path, case: dict, found: dict) -> dict:
    receipt = delivery.read(case_dir / 'batch-receipt.json')
    if not dispatch.read_index(dispatch.index_path(case['batch'])).get('stops'):
        dispatch.stop(case['batch'], receipt, 'safety_refusal', Path(found['path']))
    stop = run_dir(run['run']) / 'STOP'
    if not stop.exists():
        stop.write_text(json.dumps({'at': dispatch.now(), 'case': case['key'], **found}) + '\n')
    return set_state(case_dir, 'SAFETY_STOP', evidence=found,
                     next_action='Preserve the refusal; resolve the upstream configuration with the user before any resumption.')


def advance_case(run: dict, case_dir: Path) -> dict:
    case = delivery.read(case_dir / 'case.json')
    phase = state_of(case_dir)['phase']
    if phase in FINISHED | WAITING:
        return state_of(case_dir)
    receipt = delivery.read(case_dir / 'batch-receipt.json')
    plan = delivery.read(case_dir / 'plan.json')
    set_state(case_dir, 'RUNNING')
    try:
        flow = radar_flow.advance(plan, receipt)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        flow = {'phase': 'HOLD', 'next_action': str(exc)}
    found = refusal(run, case['batch'])
    if found:
        return stop_for_refusal(run, case_dir, case, found)
    if flow['phase'] != 'AWAITING_LEADER_SOURCE_REVIEW':
        return set_state(case_dir, 'HOLD', flow=flow, next_action=flow.get('next_action'))
    try:
        state = review_case(run, case_dir, case, receipt)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        state = set_state(case_dir, 'HOLD', next_action=f'leader review: {exc}')
    found = refusal(run, case['batch'])
    return stop_for_refusal(run, case_dir, case, found) if found else state


def review_case(run: dict, case_dir: Path, case: dict, receipt: dict) -> dict:
    tasks = dispatch.read_index(dispatch.index_path(case['batch']))['dispatch']
    adjudicated = Path(tasks['adjudicator']['binding']['output'])
    lanes = [Path(tasks[lane]['binding']['output']) for lane in LANES]
    if 'reviewer' not in tasks:
        spec = task_spec(run, case, 'reviewer', 'reviewer', [adjudicated, *lanes], adjudicator_output=adjudicated,
                         lanes=', '.join(map(str, lanes)))
        dispatch.register(spec, batch_receipt=receipt)
        tasks = dispatch.read_index(dispatch.index_path(case['batch']))['dispatch']
    entry = tasks['reviewer']
    if not entry['dispatched']:
        dispatch.act(case['batch'], 'reviewer', entry['sha256'], 'run')
        entry = dispatch.read_index(dispatch.index_path(case['batch']))['dispatch']['reviewer']
    attempt = entry['attempts'][-1]
    if attempt['status'] != 'RETURNED' or attempt['command_exit'] != 0:
        raise ValueError('reviewer did not return successfully; inspect its receipts before resuming')
    if entry['active']:
        dispatch.act(case['batch'], 'reviewer', entry['sha256'], 'retire')
    seal = adjudicated / 'DELIVERY.json'
    accepted = delivery.verify(seal)
    review = delivery.read(Path(entry['binding']['output']) / 'leader-review.json')
    verdict = review.get('cases', {}).get(case['class_id'], {})
    if (review.get('batch') != case['batch'] or review.get('leader') != run['leader']
            or review.get('delivery_sha256') != dispatch.digest(seal) or set(review.get('cases', {})) != {case['class_id']}
            or verdict.get('decision') not in {'ACCEPT', 'RETURN'} or not str(verdict.get('basis') or '').strip()
            or not verdict.get('evidence')
            or any(accepted['files'].get(item.get('path')) != item.get('sha256') for item in verdict['evidence'])):
        raise ValueError('leader review must bind this case, the final seal and evidence from that delivery')
    if not (case_dir / 'leader-review.json').exists():
        save(case_dir / 'leader-review.json', review, exclusive=True)
    if verdict['decision'] == 'RETURN':
        return set_state(case_dir, 'RETURNED', next_question=verdict.get('next_question'),
                         next_action='Continue with the same adjudicator: radar_flow.py migrate a labeled continuation.')
    research = delivery.read(Path(accepted['decisions']))['reduction']['cases'][case['class_id']]['status']
    record = delivery.read(Path(accepted['records'][case['class_id']]))
    return set_state(case_dir, 'READY_TO_LAND', research=research, verdict=record.get('verdict'))


def run_cases(name: str, parallel: int, only: set[str] | None = None) -> list[dict]:
    run = load_run(name)
    profile = run['profile']
    pending = [c for c in cases(name) if (not only or c.name in only)
               and state_of(c)['phase'] not in FINISHED | WAITING]
    results, waits = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        running = {}
        while pending or running:
            if (run_dir(name) / 'STOP').exists():
                pending = []
            while pending and len(running) < parallel:
                if profile.get('resource_gate', True) and node_capacity(profile.get('numa_node', 1)) < (
                        (len(running) + 1) * profile['memory_bytes']):
                    break
                case = pending.pop(0)
                running[pool.submit(advance_case, run, case)] = case
            if not running:
                waits += 1
                if waits > RESOURCE_WAITS:
                    for case in pending:
                        results.append({'case': case.name, **set_state(
                            case, 'HOLD', next_action='node memory stayed below the declared bound')})
                    pending = []
                elif pending:
                    time.sleep(30)
                continue
            done, _ = concurrent.futures.wait(running, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                case = running.pop(future)
                results.append({'case': case.name, **future.result()})
    return results


def assessment(run: dict, case: dict, task: str, entry: dict, base_revision: int) -> dict:
    binding, sha = entry['binding'], entry['sha256']
    output = Path(binding['output'])
    attempts = entry.get('attempts', [])

    def text(pin: dict | None) -> str:
        return Path(pin['path']).read_text(errors='replace') if pin and Path(pin['path']).exists() else ''

    record, report = None, ''
    if (output / 'DELIVERY.json').exists():
        sealed = delivery.read(output / 'DELIVERY.json')
        record = delivery.read(Path(sealed['records'][case['class_id']]))
        report = Path(sealed['report']).read_text()
    elif (output / 'leader-review.json').exists():
        report = (output / 'leader-review.json').read_text()
    final = (output / 'runner-final.txt').read_text() if (output / 'runner-final.txt').exists() else ''
    succeeded = bool(attempts) and attempts[-1]['status'] == 'RETURNED' and attempts[-1]['command_exit'] == 0
    if not succeeded:
        verdict = 'EXECUTION_FAILURE'
    elif record:
        verdict = record.get('verdict') or 'UNSPECIFIED'
    elif binding['role'] == 'reviewer' and (output / 'leader-review.json').exists():
        verdict = 'REVIEW_' + delivery.read(output / 'leader-review.json')['cases'][case['class_id']]['decision']
    else:
        verdict = 'NO_DELIVERY'
    return {'assessment_id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'radar-assessment:' + sha)),
            'run_id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'radar-run:' + sha)),
            'class_id': case['class_id'], 'base_ledger_revision': base_revision, 'agent_id': binding['agent'],
            'verdict': verdict,
            'reasoning': report or final or 'No report or final message was produced; see raw_output.',
            'raw_output': json.dumps({'final': final, 'attempts': [
                {**a, 'stdout': text(a.get('logs', {}).get('stdout')), 'stderr': text(a.get('logs', {}).get('stderr'))}
                for a in attempts]}, ensure_ascii=False),
            'causal_chain': record or {},
            'evidence': {'delivery': {'path': str(output / 'DELIVERY.json'),
                                      'sha256': dispatch.digest(output / 'DELIVERY.json')}}
                        if (output / 'DELIVERY.json').exists() else {},
            'metadata': {'batch': case['batch'], 'task': task, 'role': binding['role'], 'binding_sha256': sha,
                         'model': run['profile']['models'].get(task), 'runner': run['profile'].get('name'),
                         'contract_version': CONTRACT_VERSION, 'source_cutoff': run['cutoff'],
                         'attempt_ids': [a['attempt_id'] for a in attempts]}}


def start_runs(run: dict, case_dir: Path, case: dict, items: list[tuple[str, dict, dict]]) -> dict:
    path = case_dir / 'runs.json'
    started = delivery.read(path) if path.exists() else {}
    for task, entry, item in items:
        if task in started:
            continue
        logs = entry['attempts'][0].get('logs', {}) if entry.get('attempts') else {}
        prompt = Path(logs['prompt']['path']) if 'prompt' in logs else Path(entry['binding']['brief'])
        ledger(case_dir, 'run-start', '--run-id', item['run_id'],
               '--model-provider', run['profile'].get('provider', 'unrecorded'),
               '--model-name', str(run['profile']['models'].get(task)),
               '--model-version', 'unverified upstream route/version', '--prompt-file', str(prompt),
               '--scanner-version', f"{run['profile'].get('name', 'runner')}; contract {CONTRACT_VERSION}",
               '--actor', run['leader'], '--metadata-json', json.dumps(item['metadata']))
        started[task] = {'run_id': item['run_id'], 'completed': False}
        save(path, started)
    return started


def complete_runs(case_dir: Path, started: dict) -> None:
    for task, entry in started.items():
        if not entry['completed']:
            ledger(case_dir, 'run-complete', entry['run_id'], structured=False)
            entry['completed'] = True
            save(case_dir / 'runs.json', started)


def duplicate_tps(row: dict) -> list[str]:
    ids = {a.upper() for a in row['advisory_ids']}
    duplicates = []
    for _, other in ledger_store.read_jsonl(ledger_store.DEFAULT_LEDGER):
        if (other['class_id'] != row['class_id'] and other.get('status') in AI_STATUSES
                and ids & {a.upper() for a in other.get('advisory_ids', [])}):
            duplicates.append(other['class_id'])
    return duplicates


def land_case(run: dict, case_dir: Path) -> dict:
    case = delivery.read(case_dir / 'case.json')
    if state_of(case_dir)['phase'] != 'READY_TO_LAND':
        return state_of(case_dir)
    if run['endpoint'] != 'ledger':
        return set_state(case_dir, 'RESEARCH_HANDOFF', next_action='The run endpoint is research; nothing is landed.')
    receipt = delivery.read(case_dir / 'batch-receipt.json')
    base = delivery.read(case_dir / 'base.json')
    document = dispatch.read_index(dispatch.index_path(case['batch']))
    tasks = document['dispatch']
    if any(entry['active'] for entry in tasks.values()):
        raise ValueError('every assignment must be sealed and retired before landing')
    accepted = delivery.verify(Path(tasks['adjudicator']['binding']['output']) / 'DELIVERY.json')
    record = delivery.read(Path(accepted['records'][case['class_id']]))
    research = delivery.read(Path(accepted['decisions']))['reduction']['cases'][case['class_id']]['status']
    current = ledger(case_dir, 'get', case['class_id'])
    if current['revision'] != base['revision']:
        return set_state(case_dir, 'HOLD', next_action='canonical row changed since admission; reconcile before landing')
    items = [(task, entry, assessment(run, case, task, entry, base['revision'])) for task, entry in sorted(tasks.items())]
    release = case_dir / 'release'
    release.mkdir(exist_ok=True)
    (release / 'assessments.jsonl').write_text(
        ''.join(json.dumps(item, ensure_ascii=False, sort_keys=True) + '\n' for _, _, item in items))
    if research == 'BLOCKED':
        radar_release.gate(case['batch'], document['flow']['plan'], accepted, release / 'gate', expect='BLOCKED')
        started = start_runs(run, case_dir, case, items)
        ledger(case_dir, 'assessment-add', str(release / 'assessments.jsonl'))
        complete_runs(case_dir, started)
        if ledger(case_dir, 'get', case['class_id'])['revision'] != base['revision']:
            raise ValueError('canonical row changed while closing a researched blocker')
        claim = delivery.read(case_dir / 'claim.json')
        claims.release(claims.DEFAULT_CLAIMS, case['class_id'], run['leader'], claim_id=claim['claim_id'])
        return set_state(case_dir, 'BLOCKED_CLOSED', remaining_gap=record.get('remaining_gap'),
                         next_action='Researched blocker; assessments stored, row unchanged, claim released.')
    if research != 'ACCEPTED' or record.get('verdict') not in LANDABLE:
        return set_state(case_dir, 'HOLD', next_action=f'research {research} with verdict {record.get("verdict")} has no landing path')
    row = copy.deepcopy(current['row'])
    row.update(status=record['verdict'], causal_research=record)
    if 'remaining_gap' in record:
        row['remaining_gap'] = record['remaining_gap']
    if record['verdict'] in AI_STATUSES:
        check = ledger(case_dir, 'check')
        if check.get('jsonl_byte_identical') is not True:
            return set_state(case_dir, 'HOLD', next_action='local export differs from Neon; refresh it before the duplicate-TP check')
        duplicates = duplicate_tps(row)
        if duplicates:
            return set_state(case_dir, 'HOLD', next_action=f'duplicate TP aliases with {duplicates}; fold identities first')
    else:
        row.update(site_scope=None, site_tier=None)
    ledger_store.validate_update(current['row'], row)
    patches = release / 'patches.jsonl'
    if not patches.exists():
        patches.write_text(json.dumps({'expected_revision': base['revision'], 'row': row,
                                       'assessment_ids': [item['assessment_id'] for _, _, item in items]},
                                      ensure_ascii=False, sort_keys=True) + '\n')
    plan = {'batch': case['batch'], 'description': f"{run['run']} case {case['key']}: independent N=2 research, "
                                                   'sole adjudication and leader source review',
            'patches': str(patches), 'assessments': str(release / 'assessments.jsonl'),
            'leader_review': str(case_dir / 'leader-review.json')}
    if not (release / 'plan.json').exists():
        save(release / 'plan.json', plan, exclusive=True)
    started = start_runs(run, case_dir, case, items)
    outcome = radar_release.land(delivery.read(release / 'plan.json'), receipt)
    if outcome['phase'] != 'LEDGER_ENDPOINT_COMPLETE':
        return set_state(case_dir, 'HOLD', release=outcome, next_action=outcome.get('next_action'))
    complete_runs(case_dir, started)
    return set_state(case_dir, 'LANDED', verdict=record['verdict'], revision=outcome['revisions'][case['class_id']],
                     change_set_id=outcome['change_set_id'],
                     publication='NOT_PERFORMED' if record['verdict'] in AI_STATUSES else 'NOT_PUBLIC')


def land(name: str, only: set[str] | None = None) -> list[dict]:
    run = load_run(name)
    results = []
    for case_dir in cases(name):
        if only and case_dir.name not in only:
            continue
        try:
            results.append({'case': case_dir.name, **land_case(run, case_dir)})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            results.append({'case': case_dir.name, **set_state(case_dir, 'HOLD', next_action=f'landing: {exc}')})
    return results


def resume(name: str, key: str, task: str, inspection: Path) -> dict:
    case_dir = run_dir(name) / 'cases' / key
    case = delivery.read(case_dir / 'case.json')
    entry = dispatch.read_index(dispatch.index_path(case['batch']))['dispatch'][task]
    result = dispatch.act(case['batch'], task, entry['sha256'], 'run', resume=True, inspection=inspection)
    set_state(case_dir, 'ADMITTED', resumed=task)
    return result


def status(name: str) -> list[dict]:
    rows = []
    for case_dir in cases(name):
        case = delivery.read(case_dir / 'case.json')
        rows.append({'case': case_dir.name, 'class_id': case['class_id'], 'batch': case['batch'], **state_of(case_dir)})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description='Drive case research end to end: admit, run, review, land and report status')
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('admit', help='claim cases, build neutral packets and register both auditors')
    p.add_argument('--run', required=True)
    p.add_argument('--manifest', type=Path, required=True, help='one class_id per line')
    p.add_argument('--leader', required=True)
    p.add_argument('--endpoint', choices=['research', 'ledger'], required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--cutoff', default=dispatch.now())
    p.add_argument('--no-fetch', action='store_true', help='do not retain advisory records at admission')
    p = sub.add_parser('run', help='advance admitted cases through auditors, adjudicator and review')
    p.add_argument('--run', required=True)
    p.add_argument('--parallel', type=int, default=4)
    p.add_argument('--case', action='append')
    p = sub.add_parser('land', help='land reviewed cases in the canonical ledger')
    p.add_argument('--run', required=True)
    p.add_argument('--case', action='append')
    p = sub.add_parser('resume', help='rerun one inspected failed task')
    p.add_argument('--run', required=True)
    p.add_argument('--case', required=True)
    p.add_argument('--task', required=True)
    p.add_argument('--inspection', type=Path, required=True)
    p = sub.add_parser('status', help='one line per case')
    p.add_argument('--run', required=True)
    p = sub.add_parser('stop', help='launch no further cases in this run')
    p.add_argument('--run', required=True)
    p.add_argument('--reason', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'admit':
            result = admit(args.run, args.manifest, args.leader, args.endpoint, args.profile, args.cutoff,
                           fetch=not args.no_fetch)
        elif args.action == 'run':
            result = run_cases(args.run, args.parallel, set(args.case or []))
        elif args.action == 'land':
            result = land(args.run, set(args.case or []))
        elif args.action == 'resume':
            result = resume(args.run, args.case, args.task, args.inspection)
        elif args.action == 'stop':
            (run_dir(args.run) / 'STOP').write_text(json.dumps({'at': dispatch.now(), 'reason': args.reason}) + '\n')
            result = {'stopped': args.run}
        else:
            result = status(args.run)
    except (OSError, ValueError, KeyError, TypeError, claims.ClaimsError) as exc:
        parser.error(str(exc))
    for item in result if isinstance(result, list) else [result]:
        print(json.dumps(item, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
