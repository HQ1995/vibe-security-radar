import copy
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import claims
import ledger_store
import radar_case
from audit_reduction_gate import WORK_DIMENSIONS, digest
from compare_slots import RESEARCH_FIELDS
from test_audit_record_gates import GOOD, IMPACT, REFUTED

IDS = {'alias-a': 'GHSA-1234-5678-90ab', 'alias-b': 'GHSA-2345-6789-cdef'}


class FakeLedger:
    def __init__(self, rows):
        self.rows = {cid: {'revision': 1, 'change_set_id': 'initial', 'row': row} for cid, row in rows.items()}
        self.assessments, self.runs, self.sources, self.actors, self.calls = {}, {}, {}, {}, []
        self.interrupt = False

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
            patch = json.loads(Path(args[1]).read_text())
            cid = patch['row']['class_id']
            assert self.rows[cid]['revision'] == patch['expected_revision']
            self.rows[cid] = {'revision': patch['expected_revision'] + 1, 'change_set_id': 'committed',
                              'row': copy.deepcopy(patch['row'])}
            self.sources[cid], self.actors[cid] = sorted(set(patch['assessment_ids'])), actor
            if self.interrupt:
                raise ValueError('simulated interruption after commit')
            return 'applied'
        if command in ('check', 'export'):
            return {'jsonl_byte_identical': True, 'sha256': 'f' * 64}
        raise AssertionError(args)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(radar_case, 'RESEARCH', tmp_path / 'research')
    monkeypatch.setattr(claims, 'DEFAULT_CLAIMS', tmp_path / 'claims.jsonl')
    fake = FakeLedger({cid: {'class_id': cid, 'status': 'UNANALYZED', 'advisory_ids': [aid], 'repo': 'example/project'}
                       for cid, aid in IDS.items()})
    monkeypatch.setattr(radar_case, 'ledger', fake)

    def prepare(*cids, auditors=2):
        (tmp_path / 'manifest.txt').write_text(''.join(c + '\n' for c in cids))
        return radar_case.prepare('pilot', tmp_path / 'manifest.txt', 'leader', '2026-10-14T00:00:00Z',
                                  fetch=False, auditors=auditors)
    return fake, prepare


def record(cid, **changes):
    aid = IDS[cid]
    return {**REFUTED, 'class_id': cid, 'advisory_ids': [aid], 'advisory_aliases': [{'id': aid, 'state': 'ACTIVE'}],
            'protocol_version': radar_case.CONTRACT_VERSION, **changes}


def blocked(cid):
    aid = IDS[cid]
    return {**GOOD, 'class_id': cid, 'advisory_ids': [aid], 'advisory_aliases': [{'id': aid, 'state': 'ACTIVE'}],
            'verdict': 'EVIDENCE_GAP', 'protocol_version': radar_case.CONTRACT_VERSION, 'impact': IMPACT,
            'remaining_gap': 'the fix object is not public', 'flip_condition': 'the fix object is published'}


def deliver(directory, value):
    (directory / 'evidence').mkdir(exist_ok=True)
    source = directory / 'evidence' / 'source.txt'
    source.write_text('Harmless fixture observation.\n')
    receipt = {'path': 'evidence/source.txt', 'sha256': digest(source)}
    work = {d: {'evidence_grade': 'BOUND', 'work_state': 'COMPLETE', 'finding': 'Fixture finding.',
                'missing_fact': None, 'next_permitted_route': None, 'routes': [], 'evidence': [receipt]}
            for d in WORK_DIMENSIONS}
    (directory / 'REPORT.md').write_text('Fixture report.\n')
    (directory / 'record.json').write_text(json.dumps(value))
    (directory / 'research.json').write_text(json.dumps({'research': work}))
    (directory / 'SUMMARY.md').write_text('Fixture summary.\n')
    return receipt


def audited(key, value):
    case = radar_case.case_dir('pilot', key)
    for lane in radar_case.lanes_of(json.loads((case / 'case.json').read_text())):
        radar_case.prompt('pilot', key, lane, model='model-' + lane, host='test')
        deliver(case / lane, value)
    return case


def adjudicate(case, value, **decision):
    receipt = deliver(case / 'adjudicator', value)
    body = {'status': 'ACCEPTED', 'basis': 'Fixture basis.', 'reviewed_dimensions': list(RESEARCH_FIELDS),
            'resolutions': {}, 'evidence': [receipt], **decision}
    (case / 'adjudicator' / 'decision.json').write_text(json.dumps(body))


def review(case, decision='ACCEPT'):
    cited = case / 'adjudicator' / 'REPORT.md'
    (case / 'reviewer' / 'review.json').write_text(json.dumps({
        'decision': decision, 'basis': 'Fixture review.',
        'evidence': [{'path': str(cited), 'sha256': digest(cited)}],
        'next_question': 'Fixture question.' if decision == 'RETURN' else None}))


def checked(key, value):
    case = audited(key, value)
    assert radar_case.seal('pilot', key)['phase'] == 'SEALED'
    radar_case.prompt('pilot', key, 'adjudicator')
    adjudicate(case, value)
    assert radar_case.check('pilot', key)['phase'] == 'CHECKED'
    radar_case.prompt('pilot', key, 'reviewer')
    return case


def occupied(cid):
    return claims.occupancy(claims.state(claims.load(claims.DEFAULT_CLAIMS)), cid)['claimed']


def test_case_runs_from_prepare_to_a_verified_landing(env):
    fake, prepare = env
    assert [r['phase'] for r in prepare('alias-a')] == ['PREPARED']
    assert occupied('alias-a')
    case = audited('001', record('alias-a'))
    assert radar_case.seal('pilot', '001')['phase'] == 'SEALED'
    assert not os.access(case / 'auditor1' / 'record.json', os.W_OK)
    assert str(case / 'auditor2') in radar_case.prompt('pilot', '001', 'adjudicator')
    adjudicate(case, record('alias-a'))
    assert radar_case.check('pilot', '001', dry_run=True) == {'case': '001', 'ready': True,
                                                               'outcome': 'ACCEPTED', 'problems': []}
    assert radar_case.check('pilot', '001')['phase'] == 'CHECKED'
    assert 'review.json' in radar_case.prompt('pilot', '001', 'reviewer')
    review(case)
    assert radar_case.land('pilot')[0]['phase'] == 'LANDED'
    landed = fake.rows['alias-a']
    assert landed['revision'] == 2 and landed['row']['status'] == 'FALSE_POSITIVE'
    assert landed['row']['causal_research'] == record('alias-a')
    assert len(fake.assessments) == 4 and set(fake.runs.values()) == {'complete'}
    assert sorted(a['verdict'] for a in fake.assessments.values()) == ['FALSE_POSITIVE'] * 3 + ['REVIEW_ACCEPT']
    models = {a['metadata']['role']: a['metadata']['model'] for a in fake.assessments.values()}
    assert models['auditor1'] == 'model-auditor1' and models['reviewer'] == 'unrecorded'
    assert not occupied('alias-a')
    assert radar_case.land('pilot')[0]['phase'] == 'LANDED'
    assert fake.calls.count('finalize') == 1


def test_seal_waits_for_both_lanes(env):
    _, prepare = env
    prepare('alias-a')
    case = radar_case.case_dir('pilot', '001')
    radar_case.prompt('pilot', '001', 'auditor1')
    deliver(case / 'auditor1', record('alias-a'))
    state = radar_case.seal('pilot', '001')
    assert state['phase'] == 'HOLD' and 'auditor2: missing REPORT.md' in state['problems']
    assert not (case / 'SEAL.json').exists() and os.access(case / 'auditor1' / 'record.json', os.W_OK)
    with pytest.raises(ValueError):
        radar_case.prompt('pilot', '001', 'adjudicator')


def test_a_changed_sealed_lane_stops_adjudication(env):
    _, prepare = env
    prepare('alias-a')
    case = audited('001', record('alias-a'))
    radar_case.seal('pilot', '001')
    radar_case.prompt('pilot', '001', 'adjudicator')
    (case / 'auditor2' / 'late-note.md').write_text('added after sealing\n')
    adjudicate(case, record('alias-a'))
    state = radar_case.check('pilot', '001')
    assert state['phase'] == 'HOLD' and any('late-note.md' in p for p in state['problems'])


def test_gate_problems_go_back_to_the_adjudicator(env):
    _, prepare = env
    prepare('alias-a')
    case = audited('001', record('alias-a'))
    radar_case.seal('pilot', '001')
    radar_case.prompt('pilot', '001', 'adjudicator')
    adjudicate(case, record('alias-a'), basis='')
    dry = radar_case.check('pilot', '001', dry_run=True)
    assert not dry['ready'] and any('basis' in p for p in dry['problems'])
    assert not (case / '.decisions-dry-run.json').exists()
    assert radar_case.check('pilot', '001')['phase'] == 'HOLD'
    assert os.access(case / 'adjudicator' / 'record.json', os.W_OK)
    adjudicate(case, record('alias-a'))
    assert radar_case.check('pilot', '001')['phase'] == 'CHECKED'


def test_a_returned_review_is_reopened_without_losing_the_original(env):
    fake, prepare = env
    prepare('alias-a')
    case = checked('001', record('alias-a'))
    review(case, 'RETURN')
    state = radar_case.land('pilot')[0]
    assert state['phase'] == 'RETURNED' and state['next_question'] == 'Fixture question.'
    assert 'finalize' not in fake.calls and occupied('alias-a')
    assert radar_case.reopen('pilot', '001')['phase'] == 'SEALED'
    assert (case / 'adjudicator-v1' / 'decision.json').is_file() and (case / 'reviewer-v1' / 'review.json').is_file()
    assert os.access(case / 'adjudicator' / 'record.json', os.W_OK)
    assert radar_case.check('pilot', '001')['phase'] == 'CHECKED'
    review(case)
    assert radar_case.land('pilot')[0]['phase'] == 'LANDED'


def test_a_researched_blocker_closes_without_changing_the_row(env):
    fake, prepare = env
    prepare('alias-a')
    case = audited('001', blocked('alias-a'))
    radar_case.seal('pilot', '001')
    radar_case.prompt('pilot', '001', 'adjudicator')
    adjudicate(case, blocked('alias-a'), status='BLOCKED', next_question='Is the fix object published?')
    assert radar_case.check('pilot', '001', dry_run=True)['outcome'] == 'BLOCKED'
    assert radar_case.check('pilot', '001')['research'] == 'BLOCKED'
    review(case)
    assert radar_case.land('pilot')[0]['phase'] == 'BLOCKED_CLOSED'
    assert fake.rows['alias-a']['revision'] == 1 and 'finalize' not in fake.calls
    assert len(fake.assessments) == 4 and not occupied('alias-a')


def test_an_occupied_case_is_not_researched(env):
    _, prepare = env
    claims.claim(claims.DEFAULT_CLAIMS, 'alias-a', 'someone', scope='other')
    assert prepare('alias-a')[0]['phase'] == 'FOREIGN_HOLD'
    with pytest.raises(ValueError):
        radar_case.prompt('pilot', '001', 'auditor1')


def test_a_stop_blocks_new_work_in_the_run(env):
    _, prepare = env
    prepare('alias-a', 'alias-b')
    assert radar_case.stop('pilot', '001', 'upstream safety refusal')['phase'] == 'STOPPED'
    with pytest.raises(ValueError):
        radar_case.prompt('pilot', '002', 'auditor1')
    with pytest.raises(ValueError):
        prepare('alias-a')


def test_an_interrupted_finalize_is_recovered_by_readback_never_replayed(env):
    fake, prepare = env
    prepare('alias-a', 'alias-b')
    for key, cid in (('001', 'alias-a'), ('002', 'alias-b')):
        review(checked(key, record(cid)))
    fake.interrupt = True
    assert radar_case.land('pilot', {'001'})[0]['phase'] == 'HOLD'
    fake.interrupt = False
    assert radar_case.land('pilot', {'001'})[0]['phase'] == 'LANDED'
    assert fake.calls.count('finalize') == 1
    case = radar_case.case_dir('pilot', '002')
    (case / 'land').mkdir(exist_ok=True)
    (case / 'land' / 'finalize-intent.json').write_text('{}')
    state = radar_case.land('pilot', {'002'})[0]
    assert state['phase'] == 'HOLD' and 'previous finalize' in state['next']
    assert fake.calls.count('finalize') == 1


def test_more_models_give_more_independent_lanes(env):
    fake, prepare = env
    with pytest.raises(ValueError):
        prepare('alias-a', auditors=1)
    prepare('alias-a', auditors=3)
    case = radar_case.case_dir('pilot', '001')
    assert 'one of 3 independent auditors' in radar_case.prompt('pilot', '001', 'auditor3', model='model-c')
    for lane, model in (('auditor1', 'model-a'), ('auditor2', 'model-b')):
        radar_case.prompt('pilot', '001', lane, model=model)
    for lane in ('auditor1', 'auditor2'):
        deliver(case / lane, record('alias-a'))
    deliver(case / 'auditor3', record('alias-a', false_positive_ground='ADVISORY_MISATTRIBUTED'))
    seen = radar_case.compare('pilot', '001')
    assert seen['records']['auditor3'] == {'model': 'model-c', 'verdict': 'FALSE_POSITIVE'}
    assert seen['differences']['advisory']['false_positive_ground'] == {
        'auditor1': 'MECHANISM_REFUTED', 'auditor2': 'MECHANISM_REFUTED', 'auditor3': 'ADVISORY_MISATTRIBUTED'}
    deliver(case / 'auditor3', record('alias-a'))
    radar_case.seal('pilot', '001')
    assert 'auditor3' in radar_case.prompt('pilot', '001', 'adjudicator')
    adjudicate(case, record('alias-a'))
    assert radar_case.check('pilot', '001')['phase'] == 'CHECKED'
    assert json.loads((case / 'decisions.json').read_text())['reduction']['auditors'] == ['auditor1', 'auditor2', 'auditor3']
    radar_case.prompt('pilot', '001', 'reviewer')
    review(case)
    assert radar_case.land('pilot')[0]['phase'] == 'LANDED'
    assert len(fake.assessments) == 5
