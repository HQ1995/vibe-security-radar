"""Offline end-to-end delivery/release and interrupted-transaction regressions."""
import copy
import contextlib
import io
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_delivery
import audit_dispatch as dispatch
import claims
import ledger_store
import radar_flow
import radar_release
from test_audit_record_gates import REFUTED

SCRIPTS = Path(__file__).resolve().parents[1]


@pytest.fixture
def flow(tmp_path, monkeypatch, request):
    monkeypatch.setattr(dispatch, 'RESEARCH', tmp_path / 'research')
    monkeypatch.setattr(claims, 'DEFAULT_CLAIMS', tmp_path / 'claims.jsonl')
    manifest = tmp_path / 'selection.txt'
    manifest.write_text('alias-x\n')
    endpoint = getattr(request, 'param', 'ledger')
    receipt = dispatch.create({'batch': 'pilot', 'leader': 'leader', 'endpoint': endpoint, 'manifest': str(manifest)})
    root = dispatch.index_path('pilot').parent
    claim = claims.claim(claims.DEFAULT_CLAIMS, 'alias-x', 'leader', scope='pilot')
    def spec(name, role, inputs):
        output = root / name
        brief = root / (name + '-brief.json')
        brief.write_text(json.dumps({'record': REFUTED, 'lanes': {name: str(root / name) for name in ('a', 'b')}}))
        return {'batch': 'pilot', 'task': name, 'agent': name, 'role': role, 'leader': 'leader',
                'endpoint': endpoint, 'manifest': receipt['manifest'], 'cwd': str(root), 'output': str(output),
                'brief': str(brief), 'inputs': inputs,
                'command': [sys.executable, str(SCRIPTS / 'tests/fixtures/radar_flow_worker.py'), str(SCRIPTS),
                            str(output / 'INPUT-BINDING.json'), '{brief}']}
    auditors = [dispatch.register(spec(name, 'auditor', [receipt['manifest']]), batch_receipt=receipt)
                for name in ('a', 'b')]
    adj = spec('adj', 'adjudicator', [str(root / 'a'), str(root / 'b'), receipt['manifest'],
                                     str(SCRIPTS / 'audit_reduction_gate.py')])
    plan = {'batch': 'pilot', 'n': 2, 'auditors': auditors, 'adjudicator': adj}
    return root, receipt, plan, claim


def release_plan(flow):
    root, receipt, plan, _ = flow
    assert radar_flow.advance(plan, receipt)['phase'] == 'AWAITING_LEADER_SOURCE_REVIEW'
    seal_path = Path(plan['adjudicator']['output']) / 'DELIVERY.json'
    seal = audit_delivery.read(seal_path)
    evidence = Path(seal['evidence'][0])
    review = {'batch': 'pilot', 'leader': 'leader', 'delivery_sha256': dispatch.digest(seal_path),
              'cases': {'alias-x': {'basis': 'Fixture leader independently checked the controlled observation.',
                                     'evidence': [{'path': str(evidence), 'sha256': dispatch.digest(evidence)}]}}}
    (root / 'leader-review.json').write_text(json.dumps(review))
    assessment = {'assessment_id': 'fixture-assessment', 'class_id': 'alias-x', 'run_id': 'fixture-run',
                  'base_ledger_revision': 1, 'agent_id': 'adj', 'verdict': 'FALSE_POSITIVE',
                  'reasoning': 'Fixture only.', 'raw_output': 'Fixture only.'}
    row = {'class_id': 'alias-x', 'status': 'FALSE_POSITIVE', 'advisory_ids': REFUTED['advisory_ids'],
           'causal_research': audit_delivery.read(Path(seal['records']['alias-x']))}
    patch = {'row': row, 'expected_revision': 1, 'assessment_ids': [assessment['assessment_id']]}
    (root / 'patches.jsonl').write_text(json.dumps(patch) + '\n')
    (root / 'assessments.jsonl').write_text(json.dumps(assessment) + '\n')
    return {'batch': 'pilot', 'description': 'Offline pilot', 'patches': str(root / 'patches.jsonl'),
            'assessments': str(root / 'assessments.jsonl'), 'leader_review': str(root / 'leader-review.json')}, patch, assessment


class FakeLedger:
    def __init__(self, patch, assessment):
        self.patch, self.assessment = patch, assessment
        self.row = {'revision': 1, 'change_set_id': 'initial', 'row': {'class_id': 'alias-x', 'status': 'UNANALYZED'}}
        self.assessments, self.calls = [], []
        self.identical = False
        self.interrupt = False

    def __call__(self, root, *args, structured=True):
        self.calls.append(args[0])
        if args[0] == 'get':
            return copy.deepcopy(self.row)
        if args[0] == 'history':
            # ledger_store.case_history binds class_id once at the top level;
            # individual assessment objects omit it.
            return {'class_id': 'alias-x', 'assessments': [
                {key: copy.deepcopy(value) for key, value in item.items() if key != 'class_id'}
                for item in self.assessments],
                    'versions': [{**copy.deepcopy(self.row), 'actor': 'leader',
                                  'checksum': ledger_store.sha256(ledger_store.raw_row(self.row['row'])),
                                  'source_assessment_ids': self.patch['assessment_ids'] if self.row['revision'] == 2 else []}]}
        if args[0] == 'assessment-add':
            self.assessments = [copy.deepcopy(self.assessment)]
            return {'inserted': [self.assessment['assessment_id']], 'skipped': []}
        if args[0] == 'finalize':
            self.row = {'revision': 2, 'change_set_id': 'committed', 'row': copy.deepcopy(self.patch['row'])}
            if self.interrupt:
                raise OSError('simulated controller interruption after commit, before export')
            self.identical = True
            return 'applied fixture'
        if args[0] == 'check':
            return {'jsonl_byte_identical': self.identical, 'sha256': 'f' * 64}
        if args[0] == 'export':
            self.identical = True
            return 'exported fixture'
        raise AssertionError(args)


def test_full_flow_real_workers_real_gate_fake_ledger_and_exact_release(flow, monkeypatch):
    root, receipt, plan, claim = flow
    release, patch, assessment = release_plan(flow)
    fake = FakeLedger(patch, assessment)
    monkeypatch.setattr(radar_release, 'ledger', fake)
    result = radar_release.land(release, receipt)
    assert result['phase'] == 'LEDGER_ENDPOINT_COMPLETE'
    assert result['released_claim_ids'] == [claim['claim_id']]
    assert fake.calls.count('finalize') == 1 and fake.calls.count('assessment-add') == 1
    doc = dispatch.read_index(root / 'index.json')
    assert len(doc['dispatch']) == 3 and all(not e['active'] for e in doc['dispatch'].values())
    assert all(e['attempts'][0]['status'] == 'RETURNED' for e in doc['dispatch'].values())
    assert not claims.occupancy(claims.state(claims.load(claims.DEFAULT_CLAIMS)), 'alias-x')['claimed']
    # Repeating closeout, even after a foreign owner acquires, must not write or release foreign work.
    claims.claim(claims.DEFAULT_CLAIMS, 'alias-x', 'foreign', scope='other')
    before = claims.DEFAULT_CLAIMS.read_bytes()
    assert radar_release.land(release, receipt)['phase'] == 'LEDGER_ENDPOINT_COMPLETE'
    assert fake.calls.count('finalize') == 1 and claims.DEFAULT_CLAIMS.read_bytes() == before
    assert radar_flow.advance(plan, receipt)['phase'] == 'LEDGER_ENDPOINT_COMPLETE'


def test_commit_then_interrupt_recovers_export_without_repeating_finalize(flow, monkeypatch):
    root, receipt, _, _ = flow
    release, patch, assessment = release_plan(flow)
    fake = FakeLedger(patch, assessment)
    fake.interrupt = True
    monkeypatch.setattr(radar_release, 'ledger', fake)
    assert radar_release.land(release, receipt)['phase'] == 'RELEASE_HOLD'
    assert claims.occupancy(claims.state(claims.load(claims.DEFAULT_CLAIMS)), 'alias-x')['claimed']
    assert radar_release.land(release, receipt)['phase'] == 'LEDGER_ENDPOINT_COMPLETE'
    assert fake.calls.count('finalize') == 1 and fake.calls.count('export') == 1
    assert dispatch.read_index(root / 'index.json')['flow']['release']['holds']


def test_stop_blocks_new_dispatch_and_resume_preserving_original_claims(flow):
    root, receipt, plan, _ = flow
    reason = root / 'refusal.txt'
    reason.write_text('Structured upstream safety refusal fixture; do not retry.\n')
    before = claims.DEFAULT_CLAIMS.read_bytes()
    dispatch.stop('pilot', receipt, 'safety_refusal', reason)
    with pytest.raises(ValueError, match='batch stopped'):
        radar_flow.advance(plan, receipt)
    auditor = plan['auditors'][0]
    with pytest.raises(ValueError, match='batch stopped'):
        dispatch.act('pilot', auditor['task'], auditor['binding_sha256'], 'run')
    assert claims.DEFAULT_CLAIMS.read_bytes() == before
    assert not (root / 'a/record.json').exists()


def test_changed_sealed_inputs_hold_without_repeating_any_worker(flow):
    root, receipt, plan, _ = flow
    assert radar_flow.advance(plan, receipt)['phase'] == 'AWAITING_LEADER_SOURCE_REVIEW'
    (root / 'a/evidence.txt').write_text('mutated primary bytes')
    assert radar_flow.advance(plan, receipt)['phase'] == 'HOLD'
    assert all(len(e['attempts']) == 1 for e in dispatch.read_index(root / 'index.json')['dispatch'].values())


def test_missing_lane_and_missing_sidecar_hash_are_not_accepted(flow):
    root, receipt, plan, _ = flow
    changed = {**plan, 'auditors': plan['auditors'][:1]}
    with pytest.raises(ValueError, match='every declared'):
        radar_flow.advance(changed, receipt)
    radar_flow.run_once('pilot', plan['auditors'][0])
    sidecar = root / 'a/research.json'
    work = audit_delivery.read(sidecar)
    work['research']['advisory']['evidence'][0].pop('sha256')
    sidecar.write_text(json.dumps(work))
    with pytest.raises(ValueError, match='path and sha256'):
        audit_delivery.verify(root / 'a/DELIVERY.json')


def test_worker_mount_preflight_refuses_missing_inputs(flow):
    root, _, plan, _ = flow
    entry = radar_flow.entry_for('pilot', plan['auditors'][0])
    file = root / 'public.json'
    file.write_text(json.dumps({'binding': entry['binding'], 'sha256': entry['sha256']}))
    Path(entry['binding']['brief']).unlink()
    with pytest.raises(ValueError, match='missing'):
        radar_flow.inputs(file, entry['sha256'])


def test_existing_assessment_id_with_changed_payload_cannot_finalize(flow, monkeypatch):
    _, receipt, _, _ = flow
    release, patch, assessment = release_plan(flow)
    fake = FakeLedger(patch, assessment)
    fake.assessments = [{**assessment, 'raw_output': 'different stored evidence'}]
    monkeypatch.setattr(radar_release, 'ledger', fake)
    assert radar_release.land(release, receipt)['phase'] == 'RELEASE_HOLD'
    assert 'finalize' not in fake.calls and 'assessment-add' not in fake.calls


def test_new_revision_content_conflict_cannot_be_replayed(flow, monkeypatch):
    _, receipt, _, _ = flow
    release, patch, assessment = release_plan(flow)
    fake = FakeLedger(patch, assessment)
    fake.row['revision'] = 2
    monkeypatch.setattr(radar_release, 'ledger', fake)
    assert radar_release.land(release, receipt)['phase'] == 'RELEASE_HOLD'
    assert 'finalize' not in fake.calls


@pytest.mark.parametrize('flow', ['site'], indirect=True)
def test_site_endpoint_keeps_claim_until_publication_without_claiming_it_live(flow, monkeypatch):
    _, receipt, _, _ = flow
    release, patch, assessment = release_plan(flow)
    fake = FakeLedger(patch, assessment)
    monkeypatch.setattr(radar_release, 'ledger', fake)
    result = radar_release.land(release, receipt)
    assert result['phase'] == 'AWAITING_PUBLICATION' and result['publication'] == 'NOT_PERFORMED'
    assert 'released_claim_ids' not in result
    assert claims.occupancy(claims.state(claims.load(claims.DEFAULT_CLAIMS)), 'alias-x')['claimed']


@pytest.mark.parametrize('flow', ['research'], indirect=True)
def test_research_endpoint_cannot_write_canonical(flow, monkeypatch):
    _, receipt, _, _ = flow
    release, patch, assessment = release_plan(flow)
    fake = FakeLedger(patch, assessment)
    monkeypatch.setattr(radar_release, 'ledger', fake)
    with pytest.raises(ValueError, match='does not authorize'):
        radar_release.land(release, receipt)
    assert not fake.calls


def test_failed_command_preserves_exit_and_requires_bound_inspected_recovery(flow):
    root, receipt, plan, _ = flow
    spec = dict(plan['adjudicator'])
    spec.update(task='failure', agent='failure', role='auditor', output=str(root / 'failure'), inputs=[],
                command=[sys.executable, '-c', 'raise SystemExit(124)', '{brief}'])
    reg = dispatch.register(spec, batch_receipt=receipt)
    result = dispatch.act('pilot', reg['task'], reg['binding_sha256'], 'run')
    saved = radar_flow.entry_for('pilot', reg)['attempts'][-1]
    assert saved == result and saved['command_exit'] == 124 and saved['status'] == 'RETURNED'
    with pytest.raises(ValueError, match='inspection'):
        dispatch.act('pilot', reg['task'], reg['binding_sha256'], 'run', resume=True)
    proof = root / 'inspection.json'
    proof.write_text(json.dumps({'batch': 'pilot', 'task': reg['task'], 'binding_sha256': reg['binding_sha256'],
                                'attempt_id': result['attempt_id'], 'classification': 'runtime_fault',
                                'previous_work_stopped': True,
                                'evidence': [{'path': spec['brief'], 'sha256': dispatch.digest(Path(spec['brief']))}]}))
    dispatch.act('pilot', reg['task'], reg['binding_sha256'], 'run', resume=True, inspection=proof)
    assert [a['command_exit'] for a in radar_flow.entry_for('pilot', reg)['attempts']] == [124, 124]
    dispatch.stop('pilot', receipt, 'safety_refusal', proof)
    with pytest.raises(ValueError, match='batch stopped'):
        dispatch.act('pilot', reg['task'], reg['binding_sha256'], 'run', resume=True, inspection=proof)


def test_launch_failure_keeps_null_exit_and_original_error(flow):
    root, receipt, plan, _ = flow
    spec = dict(plan['adjudicator'])
    spec.update(task='unavailable', agent='unavailable', role='auditor', output=str(root / 'unavailable'),
                inputs=[], command=[str(root / 'nonexistent-runner'), '{brief}'])
    reg = dispatch.register(spec, batch_receipt=receipt)
    with pytest.raises(OSError):
        dispatch.act('pilot', reg['task'], reg['binding_sha256'], 'run')
    attempt = radar_flow.entry_for('pilot', reg)['attempts'][-1]
    assert attempt['status'] == 'LAUNCH_FAILED' and attempt['command_exit'] is None
    assert 'nonexistent-runner' in attempt['error']


def test_unreturned_attempt_is_held_without_a_duplicate_send(flow):
    root, receipt, plan, _ = flow
    path = root / 'index.json'
    doc = dispatch.read_index(path)
    auditor = doc['dispatch']['a']
    auditor.update(dispatched=True, attempts=[{'status': 'STARTED', 'attempt_id': 'lost', 'command_exit': None}])
    dispatch.write_index(path, doc)
    assert radar_flow.advance(plan, receipt)['phase'] == 'HOLD'
    assert not (root / 'a/record.json').exists()
    assert len(radar_flow.entry_for('pilot', plan['auditors'][0])['attempts']) == 1


def test_release_lock_prevents_concurrent_writers(flow, monkeypatch):
    root, receipt, _, _ = flow
    release, patch, assessment = release_plan(flow)
    fake = FakeLedger(patch, assessment)
    monkeypatch.setattr(radar_release, 'ledger', fake)
    with dispatch.lock(root / '.release.lock'):
        with pytest.raises(ValueError, match='running dispatch'):
            radar_release.land(release, receipt)
    assert not fake.calls


def serialized_history_assessment(assessment):
    """Exercise the real serializer against a fake connection, not a hand-written response."""
    version = (1, 'initial', 'IMPORT', json.dumps({'class_id': 'alias-x', 'status': 'UNANALYZED'}),
               '0' * 64, [], 'leader', None)
    a = assessment
    row = (a['assessment_id'], a['run_id'], a['base_ledger_revision'], '0' * 64,
           a['verdict'], None, a['reasoning'], {}, {}, a['raw_output'], a['agent_id'], {},
           None, None, 'fixture', 'fixture', None, '0' * 64, 'fixture', '0' * 64)
    class Cursor:
        def __init__(self, rows):
            self.rows = rows
        def fetchall(self):
            return self.rows
    class Connection:
        def execute(self, query, args):
            return Cursor([row] if 'FROM case_assessments' in query else [version])
    @contextlib.contextmanager
    def connect():
        yield Connection()
    capture = io.StringIO()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ledger_store, 'connect', connect)
        with contextlib.redirect_stdout(capture):
            ledger_store.case_history('alias-x')
    return json.loads(capture.getvalue())['assessments']


def test_real_history_serializer_can_complete_release(flow, monkeypatch):
    _, receipt, _, _ = flow
    release, patch, assessment = release_plan(flow)
    class SerializedLedger(FakeLedger):
        def __call__(self, root, *args, structured=True):
            result = super().__call__(root, *args, structured=structured)
            if args[0] == 'history' and self.assessments:
                result['assessments'] = serialized_history_assessment(assessment)
            return result
    fake = SerializedLedger(patch, assessment)
    monkeypatch.setattr(radar_release, 'ledger', fake)
    assert radar_release.land(release, receipt)['phase'] == 'LEDGER_ENDPOINT_COMPLETE'


def test_inspected_fresh_attempt_retains_n_and_original_lineage(flow, monkeypatch):
    root, receipt, plan, _ = flow
    original_run = dispatch.subprocess.run
    failed = False
    def fail_once(argv, *args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError('benign injected launcher failure before a worker starts')
        return original_run(argv, *args, **kwargs)
    monkeypatch.setattr(dispatch.subprocess, 'run', fail_once)
    assert radar_flow.advance(plan, receipt)['phase'] == 'HOLD'
    original = plan['auditors'][0]
    entry = radar_flow.entry_for('pilot', original)
    old = entry['binding']
    dispatch.act('pilot', original['task'], original['binding_sha256'], 'retire')
    fields = ('batch', 'task', 'agent', 'role', 'leader', 'endpoint', 'manifest', 'cwd', 'output', 'brief', 'command')
    spec = {key: copy.deepcopy(old[key]) for key in fields}
    spec.update(task='a-retry', output=str(root / 'a-retry'), manifest=old['manifest']['path'], inputs=[receipt['manifest']])
    spec['command'][3] = str(root / 'a-retry/INPUT-BINDING.json')
    replacement = dispatch.register(spec, batch_receipt=receipt)
    changed = copy.deepcopy(plan)
    changed['auditors'][0] = {**replacement, 'lane': 'a'}
    changed['adjudicator']['inputs'][0] = str(root / 'a-retry')
    brief = root / 'adj-retry-brief.json'
    brief.write_text(json.dumps({'record': REFUTED, 'lanes': {'a': str(root / 'a-retry'), 'b': str(root / 'b')}}))
    changed['adjudicator']['brief'] = str(brief)
    proof = root / 'inspection.json'
    terminal = root / 'original-failure.json'
    terminal.write_text(json.dumps(entry['attempts'][-1]))
    proof.write_text(json.dumps({'batch': 'pilot', 'task': original['task'],
        'binding_sha256': original['binding_sha256'], 'attempt_id': entry['attempts'][-1]['attempt_id'],
        'classification': 'runtime_fault', 'previous_work_stopped': True,
        'next_question': 'Complete the original independent lane after inspected launcher repair.',
        'evidence': [{'path': str(terminal), 'sha256': dispatch.digest(terminal)}]}))
    with pytest.raises(ValueError, match='flow plan changed'):
        radar_flow.advance(changed, receipt)
    radar_flow.migrate(changed, receipt, proof)
    assert radar_flow.advance(changed, receipt)['phase'] == 'AWAITING_LEADER_SOURCE_REVIEW'
    doc = dispatch.read_index(root / 'index.json')
    assert doc['flow']['plan']['n'] == 2
    assert doc['flow']['migrations'][0]['previous_plan'] == plan
    assert doc['dispatch']['a']['attempts'][0]['status'] == 'LAUNCH_FAILED'
    assert len(doc['dispatch']['a']['attempts']) == 1
    assert doc['dispatch']['a-retry']['delivery']
    dispatch.stop('pilot', receipt, 'safety_refusal', terminal)
    with pytest.raises(ValueError, match='batch stopped'):
        radar_flow.migrate(plan, receipt, proof)


def test_valid_blind_input_cannot_be_replaced_with_another_research_attempt(flow):
    root, receipt, plan, _ = flow
    radar_flow.run_once('pilot', plan['auditors'][0])
    with dispatch.lock(dispatch.RESEARCH / '.dispatch.lock'):
        doc = dispatch.read_index(root / 'index.json')
        doc['flow'] = {'plan': plan, 'plan_sha256': dispatch.binding_hash(plan)}
        dispatch.write_index(root / 'index.json', doc)
    entry = radar_flow.entry_for('pilot', plan['auditors'][0])
    old = entry['binding']
    fields = ('batch', 'task', 'agent', 'role', 'leader', 'endpoint', 'manifest', 'cwd', 'output', 'brief', 'command')
    spec = {key: copy.deepcopy(old[key]) for key in fields}
    spec.update(task='other-a', output=str(root / 'other-a'), manifest=old['manifest']['path'], inputs=[receipt['manifest']])
    changed = copy.deepcopy(plan)
    changed['auditors'][0] = {**dispatch.register(spec, batch_receipt=receipt), 'lane': 'a'}
    with pytest.raises(ValueError, match='valid sealed blind'):
        radar_flow.migrate(changed, receipt, root / 'not-needed.json')


def test_sealed_uncollected_blind_input_is_recovered_without_replacement(flow, monkeypatch):
    root, receipt, plan, _ = flow
    original_collect = radar_flow.collect
    failed = False
    def fail_once(batch, reg):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError('controller interrupted after seal, before leader collection')
        return original_collect(batch, reg)
    monkeypatch.setattr(radar_flow, 'collect', fail_once)
    assert radar_flow.advance(plan, receipt)['phase'] == 'HOLD'
    old_reg = plan['auditors'][0]
    entry = radar_flow.entry_for('pilot', old_reg)
    assert entry['attempts'][-1]['command_exit'] == 0 and not entry.get('delivery')
    original_seal = (root / 'a/DELIVERY.json').read_bytes()
    dispatch.act('pilot', old_reg['task'], old_reg['binding_sha256'], 'retire')
    old = entry['binding']
    fields = ('batch', 'task', 'agent', 'role', 'leader', 'endpoint', 'manifest', 'cwd', 'output', 'brief', 'command')
    spec = {key: copy.deepcopy(old[key]) for key in fields}
    spec.update(task='other-a', output=str(root / 'other-a'), manifest=old['manifest']['path'], inputs=[receipt['manifest']])
    replacement = dispatch.register(spec, batch_receipt=receipt)
    changed = copy.deepcopy(plan)
    changed['auditors'][0] = {**replacement, 'lane': 'a'}
    with pytest.raises(ValueError, match='valid sealed blind'):
        radar_flow.migrate(changed, receipt, root / 'not-needed.json')
    dispatch.act('pilot', replacement['task'], replacement['binding_sha256'], 'retire')
    assert radar_flow.advance(plan, receipt)['phase'] == 'AWAITING_LEADER_SOURCE_REVIEW'
    assert len(radar_flow.entry_for('pilot', old_reg)['attempts']) == 1
    assert (root / 'a/DELIVERY.json').read_bytes() == original_seal


def test_same_owner_adjudicator_followup_preserves_blind_inputs_and_completes_release(flow, monkeypatch):
    root, receipt, plan, claim = flow
    assert radar_flow.advance(plan, receipt)['phase'] == 'AWAITING_LEADER_SOURCE_REVIEW'
    before = dispatch.read_index(root / 'index.json')
    blind = {name: (root / name / 'DELIVERY.json').read_bytes() for name in ('a', 'b')}
    old = before['dispatch']['adj']
    changed = copy.deepcopy(plan)
    spec = changed['adjudicator']
    spec.update(task='adj-followup', output=str(root / 'adj-followup'))
    spec['inputs'].append(str(root / 'adj'))
    spec['command'][3] = str(root / 'adj-followup/INPUT-BINDING.json')
    brief = root / 'followup-brief.json'
    brief.write_text(json.dumps({'record': REFUTED, 'lanes': {name: str(root / name) for name in ('a', 'b')}}))
    spec['brief'] = str(brief)
    terminal = root / 'adjudicator-terminal.json'
    terminal.write_text(json.dumps(old['attempts'][-1]))
    proof = root / 'adjudicator-inspection.json'
    proof.write_text(json.dumps({'batch': 'pilot', 'task': 'adj', 'binding_sha256': old['sha256'],
        'attempt_id': old['attempts'][-1]['attempt_id'], 'classification': 'research_followup',
        'previous_work_stopped': True, 'next_question': 'Resolve the leader-returned harmless fixture observation.',
        'evidence': [{'path': str(terminal), 'sha256': dispatch.digest(terminal)}]}))
    wrong_owner = copy.deepcopy(changed)
    wrong_owner['adjudicator']['agent'] = 'different-owner'
    with pytest.raises(ValueError, match='retain the sole adjudicator owner'):
        radar_flow.migrate(wrong_owner, receipt, proof)
    radar_flow.migrate(changed, receipt, proof)
    continued = root, receipt, changed, claim
    release, patch, assessment = release_plan(continued)
    fake = FakeLedger(patch, assessment)
    monkeypatch.setattr(radar_release, 'ledger', fake)
    assert radar_release.land(release, receipt)['phase'] == 'LEDGER_ENDPOINT_COMPLETE'
    after = dispatch.read_index(root / 'index.json')
    assert after['dispatch']['adj'] == old
    for name in ('a', 'b'):
        assert (root / name / 'DELIVERY.json').read_bytes() == blind[name]
        assert after['dispatch'][name]['attempts'] == before['dispatch'][name]['attempts']
    assert after['dispatch']['adj-followup']['binding']['agent'] == old['binding']['agent']
    assert all(not entry['active'] for entry in after['dispatch'].values())
    assert fake.calls.count('finalize') == 1
