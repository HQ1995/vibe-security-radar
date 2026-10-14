#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

import claims
import ledger_store
from audit_record_gates import check_record, check_record_strict, load_record
from audit_reduction_gate import RESEARCH_CONTRACT, check_delivery, check_research_work, digest

REPO = Path(__file__).resolve().parents[1]
RESEARCH = REPO / 'research'
SKILLS = REPO / '.agents' / 'skills'
ASSIGNMENTS = SKILLS / 'radar-lead' / 'assignments'
CLONES = REPO / '.ai-slop' / 'state' / 'repos'
CONTRACT_VERSION = '2026-10-14.1'
LANES = ('auditor1', 'auditor2')
ROLES = (*LANES, 'adjudicator', 'reviewer')
LANE_FILES = ('REPORT.md', 'record.json', 'research.json', 'SUMMARY.md')
MINUTES = {'auditor1': 25, 'auditor2': 25, 'adjudicator': 25, 'reviewer': 15}
AI_STATUSES = {'AI_ROOT_CAUSE', 'AI_CODE_FLAWED'}
LANDABLE = ledger_store.TERMINAL_STATUSES - {'BLOCKED'}
CLOSED = {'LANDED', 'BLOCKED_CLOSED', 'FOREIGN_HOLD', 'STOPPED', 'RETURNED'}
GITHUB_API_VERSION = '2026-03-10'


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read(path: Path) -> dict:
    return load_record(Path(path).read_text())


def write(path: Path, value: dict) -> None:
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n')
    temporary.replace(path)


def run_dir(run: str) -> Path:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', run or ''):
        raise ValueError('run must be a plain identifier')
    return RESEARCH / run


def case_dir(run: str, key: str) -> Path:
    case = run_dir(run) / key
    if not (case / 'case.json').is_file():
        raise ValueError(f'no prepared case {run}/{key}')
    return case


def cases(run: str) -> list[Path]:
    return sorted(p for p in run_dir(run).glob('[0-9][0-9][0-9]') if (p / 'case.json').is_file())


def state_of(case: Path) -> dict:
    path = case / 'state.json'
    return read(path) if path.exists() else {'phase': 'PREPARED'}


def set_state(case: Path, phase: str, **detail) -> dict:
    state = {'phase': phase, 'at': now(), **detail}
    write(case / 'state.json', state)
    return {'case': case.name, **state}


def ledger(case: Path, *args: str, structured: bool = True):
    receipts = case / 'land' / 'receipts'
    receipts.mkdir(parents=True, exist_ok=True)
    stem = receipts / f'{len(list(receipts.glob("*.json"))):03d}-{args[0]}'
    argv = [sys.executable, '-B', str(REPO / 'scripts' / 'ledger_store.py'), *args]
    result = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, check=False)
    Path(f'{stem}.stdout').write_text(result.stdout)
    Path(f'{stem}.stderr').write_text(result.stderr)
    write(Path(f'{stem}.json'), {'argv': argv, 'exit_code': result.returncode, 'at': now()})
    if result.returncode:
        raise ValueError(f'ledger {args[0]} failed; see {stem}.json')
    return load_record(result.stdout) if structured else result.stdout


def contract() -> dict:
    def git(*args):
        return subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True).stdout.strip()
    return {'version': CONTRACT_VERSION, 'commit': git('rev-parse', 'HEAD') or None,
            'uncommitted_changes': bool(git('status', '--porcelain', '--', '.agents/skills', 'scripts'))}


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

    started = now()
    try:
        response = urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, headers=headers), timeout=45)
        status, body = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        return {'retained': False, 'url': url, 'started_at': started, 'error': str(exc)}
    path.write_bytes(body)
    return {'retained': status == 200, 'url': url, 'status': status, 'file': path.name,
            'sha256': digest(path), 'started_at': started, 'captured_at': now()}


def neutral_packet(dest: Path, row: dict, cutoff: str, fetch) -> None:
    dest.mkdir()
    sources = []
    for number, advisory in enumerate(row['advisory_ids']):
        entry = (fetch(advisory, dest / f'{number:02d}-{advisory}.json') if fetch else
                 {'retained': False, 'note': 'not retained when the case was prepared; retrieve the official record yourself'})
        sources.append({'id': advisory, **entry})
    write(dest / 'SOURCES.json', {'cutoff': cutoff, 'sources': sources})
    (dest / 'README.md').write_text(
        f"# Case {row['class_id']}\n\n"
        f"Advisory IDs: {', '.join(row['advisory_ids'])}\n"
        f"Advisory-side repository: {row.get('repo') or 'not recorded'}\n"
        f"Source coverage cutoff: {cutoff}\n\n"
        "Answer the four questions of the audit protocol for this advisory cluster: cause,\n"
        "impact, history (introduction, exposure, repair, release) and AI role. SOURCES.json\n"
        "lists the advisory records retained here; retrieve anything else from primary sources.\n")


def prepare(run: str, manifest: Path, leader: str, cutoff: str, fetch: bool = True) -> list[dict]:
    root = run_dir(run)
    if (root / 'STOP').exists():
        raise ValueError('run stopped; resolve the stop with the user first')
    if not (root / 'run.json').exists():
        if root.exists():
            raise ValueError('directory exists without run.json; choose a new run name')
        root.mkdir(parents=True)
        write(root / 'run.json', {'run': run, 'leader': leader, 'cutoff': cutoff, 'created_at': now()})
    meta = read(root / 'run.json')
    if meta['leader'] != leader:
        raise ValueError('a run keeps its leader')
    known = {read(c / 'case.json')['class_id'] for c in cases(run)}
    results = []
    for class_id in [line.strip() for line in manifest.read_text().splitlines() if line.strip()]:
        if class_id in known:
            continue
        known.add(class_id)
        key = f'{len(list(root.glob("[0-9][0-9][0-9]"))) + 1:03d}'
        results.append(prepare_case(meta, root / key, class_id, fetch_advisory if fetch else None))
    return results


def prepare_case(meta: dict, case: Path, class_id: str, fetch) -> dict:
    case.mkdir()
    current = ledger(case, 'get', class_id)
    row = current['row']
    info = {'run': meta['run'], 'key': case.name, 'class_id': class_id, 'advisory_ids': row['advisory_ids'],
            'repo': row.get('repo'), 'leader': meta['leader'], 'cutoff': meta['cutoff'], 'contract': contract(),
            'base': {'revision': current['revision'], 'change_set_id': current['change_set_id'],
                     'row_sha256': ledger_store.sha256(ledger_store.raw_row(row))},
            'prepared_at': now(), 'roles': {}}
    names = {class_id, *row['advisory_ids'], *(a.lower() for a in row['advisory_ids'])}
    occupancy = claims.state(claims.load(claims.DEFAULT_CLAIMS))
    holders = [claims.occupancy(occupancy, n) for n in sorted(names) if claims.occupancy(occupancy, n)['claimed']]
    write(case / 'case.json', info)
    if holders:
        return set_state(case, 'FOREIGN_HOLD', class_id=class_id, holders=holders,
                         next='Arrange a real handoff with the holder; lease expiry is not release.')
    info['claim'] = claims.claim(claims.DEFAULT_CLAIMS, class_id, meta['leader'], scope=f"{meta['run']}-{case.name}")
    (case / 'manifest.txt').write_text(class_id + '\n')
    neutral_packet(case / 'inputs', row, meta['cutoff'], fetch)
    for name in (*ROLES, 'assignments'):
        (case / name).mkdir()
    write(case / 'case.json', info)
    return set_state(case, 'PREPARED', class_id=class_id, next='Prompt both auditors.')


def prompt(run: str, key: str, role: str, model: str | None = None, host: str | None = None) -> str:
    if role not in ROLES:
        raise ValueError(f'role must be one of {ROLES}')
    root = run_dir(run)
    if (root / 'STOP').exists():
        raise ValueError('run stopped; resolve the stop with the user first')
    case = case_dir(run, key)
    info = read(case / 'case.json')
    if 'claim' not in info:
        raise ValueError('case is not claimed; see status')
    if role == 'adjudicator' and not (case / 'SEAL.json').exists():
        raise ValueError('seal both auditor lanes first')
    if role == 'reviewer' and not (case / 'gate.json').exists():
        raise ValueError('check the adjudication first')
    values = {'role': role, 'case_id': info['class_id'], 'advisory_ids': ', '.join(info['advisory_ids']),
              'repo': info.get('repo') or 'not recorded', 'case': case, 'run_dir': root, 'inputs': case / 'inputs',
              'out': case / role, 'scratch': case / 'scratch' / role, 'clones': CLONES, 'skills': SKILLS,
              'repo_root': REPO, 'cutoff': info['cutoff'], 'contract_version': CONTRACT_VERSION,
              'minutes': MINUTES[role], 'run': run, 'key': key,
              'lanes': '\n'.join(f'- {lane}: {case / lane}' for lane in LANES)}
    text = (ASSIGNMENTS / f"{'auditor' if role in LANES else role}.md").read_text().format_map(values)
    path = case / 'assignments' / f'{role}.md'
    if path.exists():
        path.rename(path.with_name(f'{role}-{len(list(path.parent.glob(role + "*.md")))}.md'))
    path.write_text(text)
    (case / 'scratch' / role).mkdir(parents=True, exist_ok=True)
    info['roles'][role] = {'model': model or 'unrecorded', 'host': host or 'unrecorded',
                           'assignment_sha256': digest(path), 'at': now()}
    write(case / 'case.json', info)
    return text


def lint(directory: Path, class_id: str) -> list[str]:
    missing = [f'{directory.name}: missing {name}' for name in LANE_FILES
               if not (directory / name).is_file() or not (directory / name).read_text().strip()]
    if missing:
        return missing
    try:
        record, research = read(directory / 'record.json'), read(directory / 'research.json')
    except (OSError, ValueError) as exc:
        return [f'{directory.name}: {exc}']
    problems = []
    if record.get('class_id') != class_id:
        problems.append(f'{directory.name}: record class_id must be {class_id}')
    if record.get('protocol_version') != CONTRACT_VERSION:
        problems.append(f'{directory.name}: record protocol_version must be {CONTRACT_VERSION}')

    def receipt(item, label):
        if not isinstance(item, dict) or set(item) != {'path', 'sha256'}:
            problems.append(f'{directory.name}: {label}: receipt needs exactly path and sha256')
            return
        target = Path(item['path']) if Path(item['path']).is_absolute() else directory / item['path']
        if not target.is_file() or digest(target) != item['sha256']:
            problems.append(f'{directory.name}: {label}: missing or changed {item["path"]}')

    errors, _, _, _ = check_research_work(research.get('research', research), class_id, receipt)
    return problems + [f'{directory.name}: {error}' for error in errors]


def files_of(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob('*') if p.is_file() and '.git' not in p.relative_to(directory).parts)


def freeze(directory: Path) -> dict[str, str]:
    pins = {}
    for path in files_of(directory):
        pins[str(path)] = digest(path)
        path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    return pins


def changes(case: Path) -> list[str]:
    seal = case / 'SEAL.json'
    if not seal.exists():
        return []
    problems = []
    for name, entry in read(seal).items():
        if name == 'at':
            continue
        current = {str(p): digest(p) for p in files_of(case / name)}
        for path in sorted(set(current) | set(entry['files'])):
            if current.get(path) != entry['files'].get(path):
                problems.append(f'{name}: sealed file added, removed or changed: {path}')
    return problems


def seal(run: str, key: str) -> dict:
    case = case_dir(run, key)
    info = read(case / 'case.json')
    if (case / 'SEAL.json').exists():
        return {'case': key, **state_of(case)}
    problems = [p for lane in LANES for p in lint(case / lane, info['class_id'])]
    if problems:
        return set_state(case, 'HOLD', stage='seal', problems=problems,
                         next='Send the problems back to the same auditor; nothing is sealed yet.')
    sealed = {'at': now()}
    for lane in LANES:
        record = read(case / lane / 'record.json')
        sealed[lane] = {'record_gate': check_record(record) + check_record_strict(record), 'files': freeze(case / lane)}
    write(case / 'SEAL.json', sealed)
    return set_state(case, 'SEALED', next='Prompt the adjudicator.')


def absolute(value, base: Path):
    if isinstance(value, list):
        return [absolute(item, base) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {'path', 'sha256'} and isinstance(value['path'], str) and not Path(value['path']).is_absolute():
        return {'path': str(base / value['path']), 'sha256': value['sha256']}
    return {key: absolute(item, base) for key, item in value.items()}


def decisions(case: Path, info: dict) -> dict:
    adjudicated = case / 'adjudicator'
    research = read(adjudicated / 'research.json')
    entry = absolute({**read(adjudicated / 'decision.json'), 'research': research.get('research', research)}, adjudicated)
    entry['sha256'] = {**{lane: digest(case / lane / 'record.json') for lane in LANES},
                       'accepted': digest(adjudicated / 'record.json')}
    pinned = {'manifest': case / 'manifest.txt',
              'audit_protocol': SKILLS / 'radar-audit' / 'references' / 'protocol.md',
              'reducer_protocol': SKILLS / 'radar-adjudicate' / 'references' / 'protocol.md',
              'schema': SKILLS / 'radar-audit' / 'references' / 'record.md',
              'brief': case / 'assignments' / 'adjudicator.md',
              'record_gate': REPO / 'scripts' / 'audit_record_gates.py',
              'comparison': REPO / 'scripts' / 'compare_slots.py',
              'reduction_gate': REPO / 'scripts' / 'audit_reduction_gate.py'}
    return {'reduction': {'reducer': f"{info['run']}-{info['key']}-adjudicator", 'auditors': list(LANES),
                          'research_contract': RESEARCH_CONTRACT,
                          'pins': {name: {'path': str(p), 'sha256': digest(p)} for name, p in pinned.items()},
                          'cases': {info['class_id']: entry}}}


def outcome(result: dict, class_id: str) -> str | None:
    if result['delivery_valid'] and result['research_status'] == {'ACCEPTED': 1}:
        return 'ACCEPTED'
    if result['research_status'] == {'BLOCKED': 1} and result['problems'] == [f'{class_id}: research remains BLOCKED']:
        return 'BLOCKED'
    return None


def check(run: str, key: str, dry_run: bool = False) -> dict:
    case = case_dir(run, key)
    info = read(case / 'case.json')
    if not (case / 'SEAL.json').exists():
        raise ValueError('seal both auditor lanes first')
    if 'adjudicator' in read(case / 'SEAL.json'):
        return {'case': key, **state_of(case)}
    problems = changes(case) + lint(case / 'adjudicator', info['class_id'])
    if not (case / 'adjudicator' / 'decision.json').is_file():
        problems.append('adjudicator: missing decision.json')
    if not problems:
        target = case / ('.decisions-dry-run.json' if dry_run else 'decisions.json')
        write(target, decisions(case, info))
        result = check_delivery(case / 'manifest.txt', case / 'adjudicator' / 'record.json', target,
                                lanes={lane: case / lane / 'record.json' for lane in LANES},
                                research_contract=RESEARCH_CONTRACT)
        if dry_run:
            target.unlink()
        found = outcome(result, info['class_id'])
        problems = [] if found else result['problems']
    if dry_run:
        return {'case': key, 'ready': not problems, 'outcome': None if problems else found, 'problems': problems}
    if problems:
        return set_state(case, 'HOLD', stage='check', problems=problems,
                         next='Send the problems back to the same adjudicator.')
    write(case / 'gate.json', {**result, 'outcome': found, 'at': now()})
    sealed = read(case / 'SEAL.json')
    sealed['adjudicator'] = {'files': freeze(case / 'adjudicator')}
    write(case / 'SEAL.json', sealed)
    verdict = read(case / 'adjudicator' / 'record.json').get('verdict')
    return set_state(case, 'CHECKED', research=found, verdict=verdict, next='Prompt the reviewer.')


def reopen(run: str, key: str) -> dict:
    case = case_dir(run, key)
    sealed = read(case / 'SEAL.json')
    if ('adjudicator' not in sealed or state_of(case)['phase'] in {'LANDED', 'BLOCKED_CLOSED'}
            or (case / 'land' / 'runs.json').exists() or (case / 'land' / 'patch.jsonl').exists()):
        raise ValueError('only a checked adjudication that has not started landing can be reopened')
    sealed.pop('reviewer', None)
    version = len(list(case.glob('adjudicator-v*'))) + 1
    for name in ('adjudicator', 'reviewer'):
        (case / name).rename(case / f'{name}-v{version}')
    shutil.copytree(case / f'adjudicator-v{version}', case / 'adjudicator', copy_function=shutil.copyfile)
    (case / 'reviewer').mkdir()
    for name in ('gate.json', 'decisions.json'):
        if (case / name).exists():
            (case / name).rename(case / f'{Path(name).stem}-v{version}.json')
    del sealed['adjudicator']
    write(case / 'SEAL.json', sealed)
    return set_state(case, 'SEALED', reopened=version,
                     next='Continue the same adjudicator with the returned question; the original is kept.')


def review_of(case: Path) -> dict:
    path = case / 'reviewer' / 'review.json'
    review = read(path)
    sealed = {p: sha for name, entry in read(case / 'SEAL.json').items() if name != 'at'
              for p, sha in entry['files'].items()}
    evidence = review.get('evidence')
    if (review.get('decision') not in {'ACCEPT', 'RETURN'} or not str(review.get('basis') or '').strip()
            or not isinstance(evidence, list) or not evidence
            or any(not isinstance(item, dict) or sealed.get(str(Path(item.get('path', '')))) != item.get('sha256')
                   for item in evidence)):
        raise ValueError('review.json needs decision ACCEPT or RETURN, a basis and evidence pinned to sealed files')
    if review['decision'] == 'RETURN' and not str(review.get('next_question') or '').strip():
        raise ValueError('a RETURN review needs the next_question')
    return review


def assessment(case: Path, info: dict, role: str) -> dict:
    directory = case / role

    def text(name):
        path = directory / name
        return path.read_text() if path.is_file() else ''

    record = read(directory / 'record.json') if (directory / 'record.json').is_file() else None
    review = text('review.json')
    if record:
        verdict = record.get('verdict') or 'UNSPECIFIED'
    elif role == 'reviewer' and review:
        verdict = 'REVIEW_' + load_record(review)['decision']
    else:
        verdict = 'NO_DELIVERY'
    meta = info['roles'].get(role, {'model': 'leader session', 'host': 'unrecorded', 'assignment_sha256': None})
    seed = f"{info['run']}:{info['key']}:{role}:{meta['assignment_sha256']}"
    return {'assessment_id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'radar-assessment:' + seed)),
            'run_id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'radar-run:' + seed)),
            'class_id': info['class_id'], 'base_ledger_revision': info['base']['revision'],
            'agent_id': f"{info['run']}-{info['key']}-{role}", 'verdict': verdict,
            'reasoning': text('REPORT.md') or review or text('SUMMARY.md') or 'No report was delivered.',
            'raw_output': json.dumps({'summary': text('SUMMARY.md'), 'report': text('REPORT.md'), 'review': review},
                                      ensure_ascii=False),
            'causal_chain': record or {},
            'evidence': {'files': read(case / 'SEAL.json').get(role, {}).get('files', {})},
            'metadata': {'case': f"{info['run']}/{info['key']}", 'role': role, 'model': meta['model'],
                         'host': meta['host'], 'contract': info['contract'], 'source_cutoff': info['cutoff']}}


def start_runs(case: Path, info: dict, items: list[dict]) -> dict:
    path = case / 'land' / 'runs.json'
    started = read(path) if path.exists() else {}
    for item in items:
        role = item['metadata']['role']
        if role in started:
            continue
        prompt_file = case / 'assignments' / f'{role}.md'
        if not prompt_file.is_file():
            prompt_file = case / 'land' / f'{role}-prompt.txt'
            prompt_file.write_text('No assignment was issued; the leader recorded this work in its own session.\n')
        ledger(case, 'run-start', '--run-id', item['run_id'], '--model-provider', item['metadata']['host'],
               '--model-name', item['metadata']['model'], '--model-version', 'unverified',
               '--prompt-file', str(prompt_file), '--scanner-version', f'radar skills {CONTRACT_VERSION}',
               '--actor', info['leader'], '--metadata-json', json.dumps(item['metadata']))
        started[role] = {'run_id': item['run_id'], 'completed': False}
        write(path, started)
    return started


def complete_runs(case: Path, started: dict) -> None:
    for entry in started.values():
        if not entry['completed']:
            ledger(case, 'run-complete', entry['run_id'], structured=False)
            entry['completed'] = True
            write(case / 'land' / 'runs.json', started)


def store_assessments(case: Path, info: dict, items: list[dict]) -> dict:
    history = ledger(case, 'history', info['class_id'])
    stored = {a['assessment_id']: a for a in history['assessments']}
    started = start_runs(case, info, items)
    if any(item['assessment_id'] not in stored for item in items):
        ledger(case, 'assessment-add', str(case / 'land' / 'assessments.jsonl'))
        history = ledger(case, 'history', info['class_id'])
        stored = {a['assessment_id']: a for a in history['assessments']}
    for item in items:
        found = stored.get(item['assessment_id'])
        if not found or any(found.get(k) != v for k, v in item.items() if k != 'class_id'):
            raise ValueError(f"stored assessment {item['assessment_id']} differs from the prepared payload")
    return started


def release_claim(info: dict) -> None:
    claim_id = info['claim']['claim_id']
    holders = claims.occupancy(claims.state(claims.load(claims.DEFAULT_CLAIMS)), info['class_id'])['holders']
    if any(h.get('claim_id') == claim_id for h in holders):
        claims.release(claims.DEFAULT_CLAIMS, info['class_id'], info['leader'], claim_id=claim_id)


def duplicate_tps(row: dict) -> list[str]:
    ids = {a.upper() for a in row['advisory_ids']}
    return [other['class_id'] for _, other in ledger_store.read_jsonl(ledger_store.DEFAULT_LEDGER)
            if other['class_id'] != row['class_id'] and other.get('status') in AI_STATUSES
            and ids & {a.upper() for a in other.get('advisory_ids', [])}]


def land_case(case: Path) -> dict:
    info = read(case / 'case.json')
    if state_of(case)['phase'] in CLOSED or not (case / 'gate.json').exists():
        return {'case': case.name, **state_of(case)}
    review = review_of(case)
    if review['decision'] == 'RETURN':
        return set_state(case, 'RETURNED', next_question=review['next_question'],
                         next='Run reopen, then continue the same adjudicator with the question.')
    problems = changes(case)
    if problems:
        raise ValueError('; '.join(problems))
    sealed = read(case / 'SEAL.json')
    if 'reviewer' not in sealed:
        sealed['reviewer'] = {'files': freeze(case / 'reviewer')}
        write(case / 'SEAL.json', sealed)
    gate = read(case / 'gate.json')
    record = read(case / 'adjudicator' / 'record.json')
    (case / 'land').mkdir(exist_ok=True)
    items = [assessment(case, info, role) for role in ROLES]
    (case / 'land' / 'assessments.jsonl').write_text(
        ''.join(json.dumps(item, ensure_ascii=False, sort_keys=True) + '\n' for item in items))
    if gate['outcome'] == 'BLOCKED':
        started = store_assessments(case, info, items)
        if ledger(case, 'get', info['class_id'])['revision'] != info['base']['revision']:
            raise ValueError('the canonical row changed while closing a researched blocker')
        complete_runs(case, started)
        release_claim(info)
        return set_state(case, 'BLOCKED_CLOSED', remaining_gap=record.get('remaining_gap'),
                         next='Researched blocker: assessments stored, row unchanged, claim released.')
    if record.get('verdict') not in LANDABLE:
        return set_state(case, 'HOLD', stage='land', next=f"verdict {record.get('verdict')} has no landing path")
    return land_accepted(case, info, record, items)


def land_accepted(case: Path, info: dict, record: dict, items: list[dict]) -> dict:
    base, cid = info['base']['revision'], info['class_id']
    patch_path = case / 'land' / 'patch.jsonl'
    current = ledger(case, 'get', cid)
    if not patch_path.exists():
        if current['revision'] != base:
            return set_state(case, 'HOLD', stage='land', next='the canonical row changed since prepare; reconcile first')
        row = copy.deepcopy(current['row'])
        row.update(status=record['verdict'], causal_research=record)
        if 'remaining_gap' in record:
            row['remaining_gap'] = record['remaining_gap']
        if record['verdict'] in AI_STATUSES:
            if ledger(case, 'check').get('jsonl_byte_identical') is not True:
                return set_state(case, 'HOLD', stage='land', next='the local export differs from Neon; export it first')
            duplicates = duplicate_tps(row)
            if duplicates:
                return set_state(case, 'HOLD', stage='land', next=f'duplicate TP aliases with {duplicates}; fold first')
        else:
            row.update(site_scope=None, site_tier=None)
        ledger_store.validate_update(current['row'], row)
        patch_path.write_text(json.dumps({'expected_revision': base, 'row': row,
                                          'assessment_ids': [i['assessment_id'] for i in items]},
                                         ensure_ascii=False, sort_keys=True) + '\n')
    patch = read(patch_path)
    committed = current['revision'] == base + 1 and current['row'] == patch['row']
    if not committed and current['revision'] != base:
        return set_state(case, 'HOLD', stage='land', next='unexpected canonical revision; inspect history before any write')
    started = store_assessments(case, info, items)
    if not committed:
        intent = case / 'land' / 'finalize-intent.json'
        if intent.exists():
            return set_state(case, 'HOLD', stage='land',
                             next='a previous finalize has no matching landing; inspect history before any new write')
        write(intent, {'at': now(), 'patch_sha256': digest(patch_path)})
        ledger(case, 'finalize', str(patch_path), '--actor', info['leader'], '--description',
               f"{info['run']} case {info['key']}: two independent audits, sole adjudication and leader review",
               structured=False)
    row, history = ledger(case, 'get', cid), ledger(case, 'history', cid)
    latest = history['versions'][-1]
    if (row['revision'] != base + 1 or row['row'] != patch['row'] or latest['revision'] != row['revision']
            or latest['row'] != row['row'] or latest['actor'] != info['leader']
            or sorted(latest['source_assessment_ids']) != sorted(set(patch['assessment_ids']))
            or latest['checksum'] != ledger_store.sha256(ledger_store.raw_row(patch['row']))):
        raise ValueError('readback differs from the prepared patch')
    if ledger(case, 'check').get('jsonl_byte_identical') is not True:
        ledger(case, 'export', structured=False)
        if ledger(case, 'check').get('jsonl_byte_identical') is not True:
            raise ValueError('export is not byte-identical to Neon')
    complete_runs(case, started)
    release_claim(info)
    return set_state(case, 'LANDED', verdict=record['verdict'], revision=row['revision'],
                     change_set_id=row['change_set_id'],
                     publication='PENDING' if record['verdict'] in AI_STATUSES else 'NOT_PUBLIC')


def land(run: str, only: set[str] | None = None) -> list[dict]:
    results = []
    for case in cases(run):
        if only and case.name not in only:
            continue
        try:
            results.append(land_case(case))
        except (OSError, ValueError, KeyError, TypeError, claims.ClaimsError) as exc:
            results.append(set_state(case, 'HOLD', stage='land', next=f'landing: {exc}'))
    return results


def stop(run: str, key: str, reason: str, evidence: Path | None = None) -> dict:
    case = case_dir(run, key)
    detail = {'at': now(), 'case': key, 'reason': reason}
    if evidence:
        detail['evidence'] = {'path': str(evidence.resolve()), 'sha256': digest(evidence)}
    write(run_dir(run) / 'STOP', detail)
    return set_state(case, 'STOPPED', reason=reason,
                     next='Tell the user; do not resume, rephrase or switch models until they resolve it.')


def status(run: str) -> list[dict]:
    return [{'case': c.name, 'class_id': read(c / 'case.json')['class_id'], **state_of(c)} for c in cases(run)]


def main() -> int:
    parser = argparse.ArgumentParser(description='Prepare, seal, check and land radar cases researched by host-agent subagents')
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--run', required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--leader', required=True)
    p.add_argument('--cutoff', default=now())
    p.add_argument('--no-fetch', action='store_true')
    p = sub.add_parser('prompt')
    p.add_argument('--run', required=True)
    p.add_argument('--case', required=True)
    p.add_argument('--role', required=True, choices=ROLES)
    p.add_argument('--model')
    p.add_argument('--host')
    p = sub.add_parser('lint')
    p.add_argument('directory', type=Path)
    for name in ('seal', 'check', 'reopen'):
        p = sub.add_parser(name)
        p.add_argument('--run', required=True)
        p.add_argument('--case', required=True)
        if name == 'check':
            p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('land')
    p.add_argument('--run', required=True)
    p.add_argument('--case', action='append')
    p = sub.add_parser('status')
    p.add_argument('--run', required=True)
    p = sub.add_parser('stop')
    p.add_argument('--run', required=True)
    p.add_argument('--case', required=True)
    p.add_argument('--reason', required=True)
    p.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            result = prepare(args.run, args.manifest, args.leader, args.cutoff, fetch=not args.no_fetch)
        elif args.action == 'prompt':
            print(prompt(args.run, args.case, args.role, args.model, args.host))
            return 0
        elif args.action == 'lint':
            directory = args.directory.resolve()
            problems = lint(directory, read(directory.parent / 'case.json')['class_id'])
            result = {'directory': str(directory), 'problems': problems}
        elif args.action == 'seal':
            result = seal(args.run, args.case)
        elif args.action == 'check':
            result = check(args.run, args.case, args.dry_run)
        elif args.action == 'reopen':
            result = reopen(args.run, args.case)
        elif args.action == 'land':
            result = land(args.run, set(args.case or []))
        elif args.action == 'stop':
            result = stop(args.run, args.case, args.reason, args.evidence)
        else:
            result = status(args.run)
    except (OSError, ValueError, KeyError, TypeError, claims.ClaimsError) as exc:
        parser.error(str(exc))
    for item in result if isinstance(result, list) else [result]:
        print(json.dumps(item, sort_keys=True, ensure_ascii=False))
    return 1 if isinstance(result, dict) and result.get('problems') else 0


if __name__ == '__main__':
    raise SystemExit(main())
