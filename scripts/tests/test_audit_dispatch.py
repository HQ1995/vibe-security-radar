"""Wrong-task commands must be refused before they can write their marker."""
import copy
import json
import multiprocessing
from pathlib import Path
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_dispatch as dispatch
import claims


@pytest.fixture
def task(tmp_path, monkeypatch):
    monkeypatch.setattr(dispatch, 'RESEARCH', tmp_path / 'research')
    monkeypatch.setattr(claims, 'DEFAULT_CLAIMS', tmp_path / 'claims.jsonl')
    root = dispatch.RESEARCH / 'batch-a'
    source = tmp_path / 'selection.txt'
    source.write_text('case-a\n')
    batch_receipt = dispatch.create({'batch': 'batch-a', 'leader': 'leader',
                                     'endpoint': 'research', 'manifest': str(source)})
    (root / 'brief.md').write_text('Read only the neutral input and write your own report.\n')
    (root / 'neutral.json').write_text('{"case_id":"case-a"}\n')
    document = dispatch.read_index(root / 'index.json')
    document['execution'] = {'existing': 'preserved'}
    dispatch.write_index(root / 'index.json', document)
    output = root / 'auditor-a'
    output.mkdir()
    marker = output / 'received.txt'
    claims.claim(claims.DEFAULT_CLAIMS, 'case-a', 'leader', scope='batch-a')
    spec = {'batch': 'batch-a', 'task': 'audit-a', 'agent': 'pane-a', 'role': 'auditor',
            'leader': 'leader', 'endpoint': 'research', 'manifest': batch_receipt['manifest'],
            'cwd': str(root), 'output': str(output), 'brief': str(root / 'brief.md'),
            'inputs': [str(root / 'neutral.json')],
            'command': [sys.executable, '-c',
                        'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])',
                        str(marker), '{brief}']}
    return spec, marker, batch_receipt


def invoke(receipt, action='run', **kwargs):
    return dispatch.act(receipt['batch'], receipt['task'], receipt['binding_sha256'], action, **kwargs)


def test_real_dispatch_resume_and_retirement_preserve_claims_and_index(task):
    spec, marker, batch_receipt = task
    before = claims.DEFAULT_CLAIMS.read_bytes()
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    assert 'skill' not in dispatch.read_index(dispatch.index_path(spec['batch']))['dispatch'][spec['task']]['binding']
    assert invoke(receipt)['command_exit'] == 0
    assert 'Batch: batch-a\n' in marker.read_text()
    assert 'Mode: start\n' in marker.read_text()
    assert 'Read and apply the frozen role skill:' not in marker.read_text()
    assert invoke(receipt, 'check')['cases'] == 1
    with pytest.raises(ValueError, match='already dispatched'):
        invoke(receipt)
    assert invoke(receipt, resume=True)['command_exit'] == 0
    assert 'Mode: resume\n' in marker.read_text()
    invoke(receipt, 'retire')
    with pytest.raises(ValueError, match='retired'):
        invoke(receipt, resume=True)
    doc = json.loads(dispatch.index_path(spec['batch']).read_text())
    assert doc['execution'] == {'existing': 'preserved'}
    assert claims.DEFAULT_CLAIMS.read_bytes() == before


def test_frozen_role_skill_is_pinned_and_delivered_on_start_and_resume(task, monkeypatch):
    spec, marker, batch_receipt = task
    monkeypatch.chdir(spec['cwd'])
    skill = Path(spec['cwd']) / 'frozen-role.md'
    skill.write_text('Apply the frozen audit protocol to the assigned cases.\n')
    spec['skill'] = skill.name
    claims_before = claims.DEFAULT_CLAIMS.read_bytes()
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    index = dispatch.index_path(spec['batch'])
    binding = dispatch.read_index(index)['dispatch'][spec['task']]['binding']
    assert binding['skill'] == str(skill)
    assert binding['inputs'][str(skill)] == {str(skill): dispatch.digest(skill)}
    assert invoke(receipt, 'check')['cases'] == 1
    spec['skill'] = 'unbound-latest-skill.md'
    for resume in (False, True):
        assert invoke(receipt, resume=resume)['command_exit'] == 0
        prompt = marker.read_text()
        assert f'Read and apply the frozen role skill: {skill}\n' in prompt
        assert f'Mode: {"resume" if resume else "start"}\n' in prompt
        assert prompt.endswith(Path(spec['brief']).read_text())
    marker.unlink()
    index_before = index.read_bytes()
    skill.write_text('Changed instructions.\n')
    for action in ('check', 'run'):
        with pytest.raises(ValueError, match='input changed'):
            invoke(receipt, action, resume=True)
    assert not marker.exists()
    assert index.read_bytes() == index_before
    assert dispatch.read_index(index)['execution'] == {'existing': 'preserved'}
    assert claims.DEFAULT_CLAIMS.read_bytes() == claims_before


@pytest.mark.parametrize('invalid', ['empty-path', 'non-string', 'missing', 'directory', 'empty-file', 'symlink'])
def test_invalid_role_skill_is_not_registered(task, invalid):
    spec, marker, batch_receipt = task
    skill = Path(spec['cwd']) / 'frozen-role.md'
    if invalid == 'directory':
        skill.mkdir()
        (skill / 'SKILL.md').write_text('A populated directory is still not a skill file.\n')
    elif invalid == 'empty-file':
        skill.write_text('\n')
    elif invalid == 'symlink':
        skill.symlink_to(spec['brief'])
    spec['skill'] = '' if invalid == 'empty-path' else None if invalid == 'non-string' else str(skill)
    index = dispatch.index_path(spec['batch'])
    before = index.read_bytes(), claims.DEFAULT_CLAIMS.read_bytes()
    with pytest.raises(ValueError):
        dispatch.register(spec, batch_receipt=batch_receipt)
    assert (index.read_bytes(), claims.DEFAULT_CLAIMS.read_bytes()) == before
    assert not marker.exists()


@pytest.mark.parametrize('change', ['batch', 'binding', 'manifest', 'brief', 'input', 'output', 'claim'])
def test_drift_is_refused_before_command_execution(task, change):
    spec, marker, batch_receipt = task
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    if change == 'batch':
        receipt['batch'] = 'batch-b'
    elif change == 'binding':
        doc = json.loads(dispatch.index_path(spec['batch']).read_text())
        doc['dispatch'][spec['task']]['binding']['command'][0] = '/wrong-runner'
        dispatch.write_index(dispatch.index_path(spec['batch']), doc)
    elif change in {'manifest', 'brief', 'input'}:
        path = Path(spec['inputs'][0] if change == 'input' else spec[change])
        path.write_text(path.read_text() + '\n')
    elif change == 'output':
        Path(spec['output']).rmdir()
        Path(spec['output']).symlink_to(Path(spec['cwd']).parent, target_is_directory=True)
    else:
        holder = claims.occupancy(claims.state(claims.load(claims.DEFAULT_CLAIMS)), 'case-a')['holders'][0]
        claims.release(claims.DEFAULT_CLAIMS, 'case-a', 'leader', claim_id=holder['claim_id'])
        claims.claim(claims.DEFAULT_CLAIMS, 'case-a', 'leader', scope='batch-a')
    with pytest.raises(ValueError):
        invoke(receipt)
    assert not marker.exists()


def test_added_sealed_input_and_foreign_claim_are_refused(task):
    spec, marker, batch_receipt = task
    sealed = Path(spec['cwd']) / 'sealed'
    sealed.mkdir()
    (sealed / 'a.txt').write_text('primary evidence')
    spec['inputs'] = [str(sealed)]
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    (sealed / 'b.txt').write_text('later evidence')
    with pytest.raises(ValueError, match='input changed'):
        invoke(receipt)
    (sealed / 'b.txt').unlink()
    holder = claims.load(claims.DEFAULT_CLAIMS)[0]
    claims.release(claims.DEFAULT_CLAIMS, 'case-a', 'leader', claim_id=holder['claim_id'])
    claims.claim(claims.DEFAULT_CLAIMS, 'case-a', 'someone-else', scope='batch-b')
    with pytest.raises(ValueError, match='canonical claim'):
        invoke(receipt)
    assert not marker.exists()
    # A broken input/claim must not trap a stopped assignment in active forever.
    invoke(receipt, 'retire')


@pytest.mark.parametrize('conflict', ['agent', 'output', 'adjudicator', 'batch'])
def test_registration_rejects_conflicting_ownership(task, conflict):
    spec, _, batch_receipt = task
    if conflict == 'adjudicator':
        spec['role'] = 'adjudicator'
    dispatch.register(spec, batch_receipt=batch_receipt)
    second = copy.deepcopy(spec)
    second.update(task='other-task', agent='pane-b', output=str(Path(spec['cwd']) / 'other-output'))
    if conflict == 'agent':
        second['agent'] = spec['agent']
    elif conflict == 'output':
        second['output'] = str(Path(spec['output']) / 'nested')
    elif conflict == 'batch':
        other = dispatch.RESEARCH / 'batch-b'
        holder = claims.load(claims.DEFAULT_CLAIMS)[0]
        claims.release(claims.DEFAULT_CLAIMS, 'case-a', 'leader', claim_id=holder['claim_id'])
        batch_receipt = dispatch.create({'batch': 'batch-b', 'leader': 'leader',
                                         'endpoint': 'research', 'manifest': spec['manifest']})
        second.update(batch='batch-b', manifest=batch_receipt['manifest'], output=str(other / 'output'))
        claims.claim(claims.DEFAULT_CLAIMS, 'case-a', 'leader', scope='batch-b')
    before = dispatch.index_path(spec['batch']).read_bytes()
    with pytest.raises(ValueError):
        dispatch.register(second, batch_receipt=batch_receipt)
    assert dispatch.index_path(spec['batch']).read_bytes() == before
    assert not dispatch.read_index(dispatch.index_path('batch-b')).get('dispatch')


def test_handoff_requires_sealing_and_preserves_original_output_ownership(task):
    spec, _, batch_receipt = task
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    (Path(spec['output']) / 'report.json').write_text('{"class_id":"case-a"}\n')
    second = copy.deepcopy(spec)
    second.update(task='adjudicate', agent='pane-b', role='adjudicator',
                  output=str(Path(spec['cwd']) / 'adjudication'), inputs=[spec['output']])
    with pytest.raises(ValueError, match='active writer'):
        dispatch.register(second, batch_receipt=batch_receipt)
    invoke(receipt, 'retire')
    adjudication = dispatch.register(second, batch_receipt=batch_receipt)
    assert invoke(adjudication, 'check')['role'] == 'adjudicator'
    second.update(task='reused-output', role='auditor', agent='pane-c', output=spec['output'], inputs=[])
    with pytest.raises(ValueError, match='owned'):
        dispatch.register(second, batch_receipt=batch_receipt)


def test_running_command_cannot_be_replayed_or_retired(task):
    spec, marker, batch_receipt = task
    release = marker.parent / 'release'
    spec['command'] = [sys.executable, '-c',
                       ('import pathlib,sys,time\npathlib.Path(sys.argv[1]).write_text("started")\n'
                        'deadline=time.monotonic()+5\n'
                        'while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<deadline: time.sleep(.01)\n'),
                       str(marker), str(release), '{brief}']
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    result = []
    thread = threading.Thread(target=lambda: result.append(invoke(receipt)))
    thread.start()
    import time
    deadline = time.monotonic() + 3
    try:
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert marker.exists()
        for action in ('run', 'retire'):
            with pytest.raises(ValueError, match='running dispatch'):
                invoke(receipt, action, resume=True)
    finally:
        release.touch()
        thread.join(timeout=6)
    assert not thread.is_alive() and result[0]['command_exit'] == 0


def test_concurrent_registration_has_one_winner(task):
    spec, _, batch_receipt = task
    ctx = multiprocessing.get_context('fork')
    queue = ctx.Queue()
    def compete(name):
        other = copy.deepcopy(spec)
        other.update(task=name, output=str(Path(spec['cwd']) / name))
        try:
            dispatch.register(other, batch_receipt=batch_receipt)
            queue.put('registered')
        except ValueError:
            queue.put('refused')
    workers = [ctx.Process(target=compete, args=(name,)) for name in ('one', 'two')]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert worker.exitcode == 0
    assert sorted(queue.get(timeout=1) for _ in workers) == ['refused', 'registered']


def test_cli_wrong_batch_does_not_execute(task, monkeypatch, capsys):
    spec, marker, batch_receipt = task
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    monkeypatch.setattr(sys, 'argv', ['audit_dispatch.py', 'run', '--batch', 'wrong-batch',
                                     '--task', spec['task'], '--binding', receipt['binding_sha256']])
    with pytest.raises(SystemExit) as exc:
        dispatch.main()
    assert exc.value.code == 2 and 'absent or retired' in capsys.readouterr().err
    assert not marker.exists()


def test_herdr_resume_checks_actual_pane_before_sending(task, monkeypatch):
    spec, _, batch_receipt = task
    spec['agent'] = 'w8:pTEST'
    spec['command'] = ['herdr', 'agent', 'prompt', spec['agent'], '{brief}', '--wait']
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    monkeypatch.setenv('HERDR_ENV', '1')
    calls = []
    def get_only(command, **kwargs):
        calls.append(command)
        assert command == ['herdr', 'agent', 'get', spec['agent']]
        return dispatch.subprocess.CompletedProcess(command, 0, json.dumps({'result': {'agent': {
            'pane_id': spec['agent'], 'cwd': spec['cwd'], 'agent_status': 'working'}}}))
    monkeypatch.setattr(dispatch.subprocess, 'run', get_only)
    with pytest.raises(ValueError, match='idle or done'):
        invoke(receipt)
    assert len(calls) == 1
    assert not json.loads(dispatch.index_path(spec['batch']).read_text())['dispatch'][spec['task']]['dispatched']


@pytest.mark.parametrize('invalid', ['empty-brief', 'wrong-target'])
def test_invalid_dispatch_spec_is_not_registered(task, invalid):
    spec, marker, batch_receipt = task
    if invalid == 'empty-brief':
        Path(spec['brief']).write_text('\n')
    else:
        spec['command'] = ['herdr', 'agent', 'prompt', 'neighboring-pane', '{brief}', '--wait']
    before = dispatch.index_path(spec['batch']).read_bytes()
    with pytest.raises(ValueError):
        dispatch.register(spec, batch_receipt=batch_receipt)
    assert dispatch.index_path(spec['batch']).read_bytes() == before
    assert not marker.exists()


def test_new_group_cannot_adopt_existing_batch_or_invent_leader_receipt(task, tmp_path):
    spec, marker, batch_receipt = task
    index = dispatch.index_path(spec['batch'])
    before = index.read_bytes(), claims.DEFAULT_CLAIMS.read_bytes()
    creation = {k: spec[k] for k in ('batch', 'leader', 'endpoint', 'manifest')}
    with pytest.raises(ValueError, match='directory already exists'):
        dispatch.create(creation)
    with pytest.raises(ValueError, match='already claimed'):
        dispatch.create({**creation, 'batch': 'group3'})
    assert not (dispatch.RESEARCH / 'group3').exists()

    source = tmp_path / 'other-selection.txt'
    source.write_text('case-b\n')
    other = dispatch.create({**creation, 'batch': 'group3', 'manifest': str(source)})
    # Batch names, owner names and public hashes do not grant registration authority.
    guessed = {**batch_receipt, 'batch_token': dispatch.allocation(spec['batch'])['binding']['receipt_sha256']}
    intruder = {**spec, 'task': 'group3-review', 'agent': 'pane-group3',
                'output': str(Path(spec['cwd']) / 'group3-output')}
    for supplied in ({}, other, guessed):
        with pytest.raises(ValueError, match='original leader batch receipt'):
            dispatch.register(intruder, batch_receipt=supplied)
    assert (index.read_bytes(), claims.DEFAULT_CLAIMS.read_bytes()) == before
    assert not marker.exists()

    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    assert invoke(receipt)['command_exit'] == 0
    assert batch_receipt['batch_token'] not in index.read_text() + marker.read_text() + json.dumps(receipt)


def test_existing_unregistered_directory_cannot_be_silently_adopted(task):
    spec, _, batch_receipt = task
    root = dispatch.RESEARCH / 'legacy'
    root.mkdir()
    (root / 'index.json').write_text('{"execution":"old work"}\n')
    before = (root / 'index.json').read_bytes()
    with pytest.raises(ValueError, match='directory already exists'):
        dispatch.create({'batch': 'legacy', 'leader': spec['leader'],
                         'endpoint': spec['endpoint'], 'manifest': spec['manifest']})
    with pytest.raises(ValueError, match='missing or changed batch allocation'):
        dispatch.register({**spec, 'batch': 'legacy'}, batch_receipt=batch_receipt)
    assert (root / 'index.json').read_bytes() == before


def test_allocation_cannot_be_changed_after_registration(task):
    spec, marker, batch_receipt = task
    receipt = dispatch.register(spec, batch_receipt=batch_receipt)
    index = dispatch.index_path(spec['batch'])
    document = dispatch.read_index(index)
    document['allocation']['binding']['leader'] = 'another-leader'
    document['allocation']['sha256'] = dispatch.binding_hash(document['allocation']['binding'])
    dispatch.write_index(index, document)
    with pytest.raises(ValueError, match='leader-created batch allocation'):
        invoke(receipt)
    assert not marker.exists()


def test_concurrent_batch_creation_has_one_winner(task, tmp_path):
    spec, _, _ = task
    source = tmp_path / 'new-selection.jsonl'
    source.write_text('{"class_id":"case-b","neutral_metadata":"preserved"}\n')
    creation = {'batch': 'batch-b', 'leader': spec['leader'], 'endpoint': spec['endpoint'],
                'manifest': str(source)}
    ctx = multiprocessing.get_context('fork')
    queue = ctx.Queue()
    def compete():
        try:
            queue.put(dispatch.create(creation))
        except ValueError:
            queue.put(None)
    workers = [ctx.Process(target=compete) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert worker.exitcode == 0
    receipts = [queue.get(timeout=1) for _ in workers]
    assert receipts.count(None) == 1
    winner = next(r for r in receipts if r)
    assert Path(winner['manifest']).read_bytes() == source.read_bytes()
    assert dispatch.allocation('batch-b')['sha256'] == winner['allocation_sha256']


def test_cli_creates_batch_and_requires_receipt_file(task, tmp_path, monkeypatch, capsys):
    spec, _, batch_receipt = task
    monkeypatch.setattr(sys, 'argv', ['audit_dispatch.py', 'register', 'unused-spec.json'])
    with pytest.raises(SystemExit) as exc:
        dispatch.main()
    assert exc.value.code == 2 and '--batch-receipt' in capsys.readouterr().err
    source = tmp_path / 'selection-b.txt'
    source.write_text('case-b\n')
    creation = tmp_path / 'batch.json'
    creation.write_text(json.dumps({'batch': 'batch-b', 'leader': 'leader',
                                    'endpoint': 'research', 'manifest': str(source)}))
    monkeypatch.setattr(sys, 'argv', ['audit_dispatch.py', 'create', str(creation)])
    assert dispatch.main() == 0
    assert json.loads(capsys.readouterr().out)['cases'] == 1
    task_spec, receipt_file = tmp_path / 'task.json', tmp_path / 'leader-receipt.json'
    task_spec.write_text(json.dumps(spec))
    receipt_file.write_text(json.dumps(batch_receipt))
    monkeypatch.setattr(sys, 'argv', ['audit_dispatch.py', 'register', str(task_spec),
                                     '--batch-receipt', str(receipt_file)])
    assert dispatch.main() == 0
    registered = json.loads(capsys.readouterr().out)
    assert invoke(registered, 'check')['cases'] == 1
