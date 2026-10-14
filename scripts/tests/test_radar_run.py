"""Offline radar_run regressions: real dispatch, flow, gates and harmless workers; fake ledger."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_dispatch as dispatch
import claims
import ledger_store
import radar_release
import radar_run

SCRIPTS = Path(__file__).resolve().parents[1]
WORKER = SCRIPTS / 'tests' / 'fixtures' / 'radar_run_worker.py'
IDS = {'alias-a': 'GHSA-1234-5678-90ab', 'alias-b': 'GHSA-2345-6789-cdef'}


class FakeLedger:
    """The canonical ledger CLI as radar_release calls it, with one atomic row per patch."""

    def __init__(self, rows):
        self.rows = {cid: {'revision': 1, 'change_set_id': 'initial', 'row': row} for cid, row in rows.items()}
        self.assessments, self.runs, self.sources, self.actors, self.calls = {}, {}, {}, {}, []

    def __call__(self, root, *args, structured=True):
        command = args[0]
        self.calls.append(command)
        if command == 'get':
            return copy.deepcopy(self.rows[args[1]])
        if command == 'history':
            cid, current = args[1], self.rows[args[1]]
            return {'class_id': cid,
                    'assessments': [{k: copy.deepcopy(v) for k, v in item.items() if k != 'class_id'}
                                    for item in self.assessments.values() if item['class_id'] == cid],
                    'versions': [{**copy.deepcopy(current), 'actor': self.actors.get(cid, 'importer'),
                                  'checksum': ledger_store.sha256(ledger_store.raw_row(current['row'])),
                                  'source_assessment_ids': self.sources.get(cid, [])}]}
        if command == 'run-start':
            run_id = args[args.index('--run-id') + 1]
            assert run_id not in self.runs, 'a scan run must never start twice'
            self.runs[run_id] = 'active'
            return {'run_id': run_id}
        if command == 'run-complete':
            assert self.runs[args[1]] == 'active'
            self.runs[args[1]] = 'complete'
            return 'completed'
        if command == 'assessment-add':
            for line in Path(args[1]).read_text().splitlines():
                item = json.loads(line)
                assert self.runs.get(item['run_id']) == 'active'
                self.assessments.setdefault(item['assessment_id'], item)
            return {'inserted': list(self.assessments), 'skipped': []}
        if command == 'finalize':
            actor = args[args.index('--actor') + 1]
            for line in Path(args[1]).read_text().splitlines():
                patch = json.loads(line)
                cid = patch['row']['class_id']
                assert self.rows[cid]['revision'] == patch['expected_revision']
                self.rows[cid] = {'revision': patch['expected_revision'] + 1, 'change_set_id': 'committed',
                                  'row': copy.deepcopy(patch['row'])}
                self.sources[cid], self.actors[cid] = sorted(set(patch['assessment_ids'])), actor
            return 'applied'
        if command == 'check':
            return {'jsonl_byte_identical': True, 'sha256': 'f' * 64}
        raise AssertionError(args)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(dispatch, 'RESEARCH', tmp_path / 'research')
    monkeypatch.setattr(claims, 'DEFAULT_CLAIMS', tmp_path / 'claims.jsonl')
    monkeypatch.setattr(radar_run, 'RUNS', tmp_path / 'runs')
    fake = FakeLedger({cid: {'class_id': cid, 'status': 'UNANALYZED', 'advisory_ids': [aid], 'repo': 'example/project'}
                       for cid, aid in IDS.items()})
    monkeypatch.setattr(radar_release, 'ledger', fake)
    profile = {'name': 'fixture', 'provider': 'offline', 'prefix': [],
               'agent': [sys.executable, str(WORKER), '{output}', '{brief}'],
               'models': {lane: 'fixture-model' for lane in ('auditor1', 'auditor2', 'adjudicator', 'reviewer')},
               'timeout_seconds': {'auditor': 600, 'adjudicator': 600, 'reviewer': 600},
               'memory_bytes': 1, 'resource_gate': False,
               'refusal_markers': ['flagged for possible cybersecurity risk']}
    (tmp_path / 'profile.json').write_text(json.dumps(profile))

    def admit(*cids):
        (tmp_path / 'manifest.txt').write_text(''.join(c + '\n' for c in cids))
        return radar_run.admit('pilot', tmp_path / 'manifest.txt', 'leader', 'ledger', tmp_path / 'profile.json',
                               '2026-10-14T00:00:00Z', fetch=False)
    return fake, admit


def phases():
    return {row['class_id']: row['phase'] for row in radar_run.status('pilot')}


def occupied(cid):
    return claims.occupancy(claims.state(claims.load(claims.DEFAULT_CLAIMS)), cid)['claimed']


def test_one_case_runs_from_admission_to_a_verified_landing(env):
    fake, admit = env
    assert [r['phase'] for r in admit('alias-a')] == ['ADMITTED']
    assert occupied('alias-a')
    assert radar_run.run_cases('pilot', 1)[0]['phase'] == 'READY_TO_LAND'
    assert radar_run.land('pilot')[0]['phase'] == 'LANDED'
    landed = fake.rows['alias-a']
    assert landed['revision'] == 2 and landed['row']['status'] == 'FALSE_POSITIVE'
    assert landed['row']['causal_research']['class_id'] == 'alias-a'
    assert len(fake.assessments) == 4 and set(fake.runs.values()) == {'complete'}
    verdicts = sorted(a['verdict'] for a in fake.assessments.values())
    assert verdicts == ['FALSE_POSITIVE'] * 3 + ['REVIEW_ACCEPT']
    assert not occupied('alias-a')
    batch = dispatch.read_index(dispatch.index_path('pilot-001'))
    assert set(batch['dispatch']) == {'auditor1', 'auditor2', 'adjudicator', 'reviewer'}
    assert all(not e['active'] and e['attempts'][-1]['logs']['prompt'] for e in batch['dispatch'].values())
    # Repeating land is a no-op once the endpoint is recorded.
    assert radar_run.land('pilot')[0]['phase'] == 'LANDED'
    assert fake.calls.count('finalize') == 1


def test_cases_run_in_parallel_in_their_own_batches(env):
    _, admit = env
    admit('alias-a', 'alias-b')
    results = radar_run.run_cases('pilot', 2)
    assert sorted(r['phase'] for r in results) == ['READY_TO_LAND', 'READY_TO_LAND']
    assert phases() == {'alias-a': 'READY_TO_LAND', 'alias-b': 'READY_TO_LAND'}


def test_a_failed_task_holds_without_automatic_retry(env, monkeypatch):
    _, admit = env
    admit('alias-a')
    monkeypatch.setenv('RADAR_FIXTURE_AUDITOR2', 'fail')
    assert radar_run.run_cases('pilot', 1)[0]['phase'] == 'HOLD'
    assert radar_run.run_cases('pilot', 1)[0]['phase'] == 'HOLD'
    attempts = dispatch.read_index(dispatch.index_path('pilot-001'))['dispatch']['auditor2']['attempts']
    assert len(attempts) == 1 and attempts[0]['command_exit'] == 124
    assert radar_run.land('pilot')[0]['phase'] == 'HOLD'


def test_an_upstream_refusal_stops_the_whole_run(env, monkeypatch):
    fake, admit = env
    admit('alias-a', 'alias-b')
    monkeypatch.setenv('RADAR_FIXTURE_AUDITOR1', 'refuse')
    results = radar_run.run_cases('pilot', 1)
    assert [r['phase'] for r in results] == ['SAFETY_STOP']
    assert phases() == {'alias-a': 'SAFETY_STOP', 'alias-b': 'ADMITTED'}
    assert dispatch.read_index(dispatch.index_path('pilot-001'))['stops'][0]['reason'] == 'safety_refusal'
    assert (radar_run.RUNS / 'pilot' / 'STOP').exists()
    monkeypatch.delenv('RADAR_FIXTURE_AUDITOR1')
    assert radar_run.run_cases('pilot', 1) == []
    assert 'finalize' not in fake.calls


def test_a_returned_review_is_not_landed(env, monkeypatch):
    fake, admit = env
    admit('alias-a')
    monkeypatch.setenv('RADAR_FIXTURE_REVIEWER', 'return')
    state = radar_run.run_cases('pilot', 1)[0]
    assert state['phase'] == 'RETURNED' and state['next_question'] == 'Fixture follow-up question.'
    assert radar_run.land('pilot')[0]['phase'] == 'RETURNED'
    assert 'finalize' not in fake.calls and occupied('alias-a')


def test_role_contracts_carry_only_their_own_skill_and_worker_code(env):
    _, admit = env
    admit('alias-a')
    contract = radar_run.RUNS / 'pilot' / 'contract'
    auditor = {p.relative_to(contract / 'auditor').as_posix() for p in (contract / 'auditor').rglob('*') if p.is_file()}
    assert {'.agents/skills/radar-audit/SKILL.md', '.agents/skills/radar-audit/references/protocol.md',
            '.agents/skills/radar-audit/references/record.md'} <= auditor
    assert not any('radar-lead' in p or 'radar-adjudicate' in p or 'radar-incremental' in p for p in auditor)
    assert {'scripts/audit_dispatch.py', 'scripts/claims.py', 'scripts/radar_flow.py'} <= auditor
    assert not any(p.endswith(('ledger_store.py', 'radar_release.py', 'radar_run.py')) for p in auditor)
    adjudicator = {p.relative_to(contract / 'adjudicator').as_posix() for p in (contract / 'adjudicator').rglob('*.md')}
    assert {'.agents/skills/radar-adjudicate/references/protocol.md', '.agents/skills/radar-audit/references/record.md'} <= adjudicator
    reviewer = {p.relative_to(contract / 'reviewer').as_posix() for p in (contract / 'reviewer').rglob('*.md')}
    assert '.agents/skills/radar-lead/SKILL.md' in reviewer
    assert not any('radar-lead/references' in p for p in reviewer)


def test_sandboxed_command_binds_inputs_and_passes_the_brief_once(tmp_path):
    profile = {'prefix': ['timeout', '{timeout}s'], 'agent': ['agent', '--model', '{model}', '{brief}'],
               'models': {'adjudicator': 'm'}, 'timeout_seconds': {'adjudicator': 90}, 'memory_bytes': 1,
               'sandbox': {'kind': 'bwrap', 'mask': ['/home'], 'home': '/home/agent/.state', 'ro_binds': ['/opt/auth']},
               'shared_clones': ['/srv/repos']}
    cwd, output, lane = tmp_path / 'ws', tmp_path / 'ws' / 'output', tmp_path / 'lane'
    argv = radar_run.command(profile, 'adjudicator', 'adjudicator', cwd, output, [lane])
    assert argv[:2] == ['timeout', '90s'] and argv[-4:] == ['agent', '--model', 'm', '{brief}']
    assert argv.count('{brief}') == 1
    joined = ' '.join(argv)
    for bound in (f'--ro-bind {cwd} {cwd}', f'--bind {output} {output}', f'--ro-bind {lane} {lane}',
                  '--ro-bind /opt/auth /opt/auth', '--ro-bind /srv/repos /srv/repos', '--tmpfs /home'):
        assert bound in joined
    assert f'--bind {output / "runtime-home"} /home/agent/.state' in joined
