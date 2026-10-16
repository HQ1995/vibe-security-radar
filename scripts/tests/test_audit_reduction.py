import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_reduction_gate import PIN_ROLES, RESEARCH_CONTRACT, WORK_DIMENSIONS, check_delivery, digest
from compare_slots import RESEARCH_FIELDS, compare_many, lane_paths, load, research_differences_many


@pytest.fixture
def delivery(tmp_path):
    record = {
        'class_id': 'alias-x', 'verdict': 'NOT_AI',
        'advisory_ids': ['GHSA-1234-5678-90ab'], 'advisory_disposition': 'ACTIVE',
        'advisory_aliases': [{'id': 'GHSA-1234-5678-90ab', 'state': 'ACTIVE'}],
        'introducer_sha': 'a' * 40, 'landing_commit': None,
        'bic_granularity': 'ATOMIC', 'fix_sha': 'b' * 40,
        'fix_granularity': 'ATOMIC', 'fix_ai_marker': {'state': 'ABSENT'},
        'ai_marker': {'state': 'ABSENT'}, 'ai_on_bic': False,
        'identity_class': 'human', 'disclosure_convention': 'CONVENTION_NOT_OBSERVED',
        'flip_condition': 'First-party attribution bound to the introducing change.',
        'remaining_gap': None,
        'flaw_origin': 'A human-authored change added the unguarded path.',
    }
    paths = {}
    for name in ('a', 'b', 'accepted'):
        paths[name] = tmp_path / name
        paths[name].mkdir()
        (paths[name] / 'case.json').write_text(json.dumps(record))
    paths['manifest'] = tmp_path / 'batch.txt'
    paths['manifest'].write_text('alias-x\n')
    paths['decisions'] = tmp_path / 'index.json'
    evidence = tmp_path / 'evidence.txt'
    evidence.write_text('Repository: fixture; object: aaaa; argv: git cat-file; exit: 0; observation: named human author.\n')
    scripts = Path(__file__).resolve().parents[1]
    pin_files = {role: evidence for role in PIN_ROLES}
    pin_files.update(manifest=paths['manifest'], record_gate=scripts / 'audit_record_gates.py',
                     comparison=scripts / 'compare_slots.py', reduction_gate=scripts / 'audit_reduction_gate.py')
    index = {'reducer': 'test-reducer', 'auditors': ['a', 'b'],
             'pins': {role: {'path': str(path), 'sha256': digest(path)} for role, path in pin_files.items()},
             'cases': {'alias-x': {
                 'sha256': {name: digest(paths[name] / 'case.json') for name in ('a', 'b', 'accepted')},
                 'status': 'ACCEPTED', 'basis': 'The final mechanism and attribution were independently checked.',
                 'reviewed_dimensions': list(RESEARCH_FIELDS), 'resolutions': {},
                 'evidence': [{'path': 'evidence.txt', 'sha256': digest(evidence)}],
             }}}
    paths['decisions'].write_text(json.dumps({'reduction': index}))
    return paths, index


def gate(paths, lanes=None, **kwargs):
    return check_delivery(paths['manifest'], paths['accepted'], paths['decisions'],
                          lanes or {'a': paths['a'], 'b': paths['b']}, **kwargs)


def cli_args(paths):
    return [part for name in ('manifest', 'accepted', 'decisions') for part in ('--' + name, str(paths[name]))
            ] + ['--lane', f'a={paths["a"]}', '--lane', f'b={paths["b"]}']


def save_index(paths, index):
    paths['decisions'].write_text(json.dumps({'reduction': index}))


@pytest.mark.parametrize('field', ['evidence', 'reasoning'])
def test_observed_objects_and_contrary_accounts_need_resolution(delivery, field):
    from test_audit_record_gates import REFUTED

    paths, index = delivery
    adopt_research_contract(paths, index)
    observations = {
        'a': {'sha': 'a' * 40, 'observation': 'The endpoint always returns a count.'},
        'b': {'sha': 'b' * 40, 'observation': 'Only count mode omits message bodies.'},
        'accepted': 'The allegation is refuted.',
    }
    for lane, observation in observations.items():
        path = paths[lane] / 'case.json'
        path.write_text(json.dumps({**REFUTED, field: observation}))
        index['cases']['alias-x']['sha256'][lane] = digest(path)
    save_index(paths, index)
    result = gate(paths, research_contract='causal-work-v1')
    assert not result['delivery_valid']
    assert any('unresolved mechanism' in problem for problem in result['problems'])


def test_fix_vs_null_and_entire_chain_are_reported(delivery):
    paths, index = delivery
    file = paths['b'] / 'case.json'
    original = json.loads(file.read_text())
    changed = {**original, 'fix_sha': None, 'fix_granularity': 'NO_FIX_OBJECT',
               'atomic_repair_sha': 'c' * 40, 'versions': {'fixed': 'v2'},
               'ai_marker': {'state': 'UNKNOWN'}, 'remaining_gap': 'No repair recovered.'}
    file.write_text(json.dumps(changed))
    report = compare_many({'a': paths['a'], 'b': paths['b']})
    assert set(report['research_differences']['alias-x']) == {'fix', 'versions', 'ai', 'residual'}
    index['cases']['alias-x']['sha256']['b'] = digest(file)
    save_index(paths, index)
    assert 'unresolved fix' in '\n'.join(gate(paths)['problems'])


def test_valid_frozen_delivery_and_cli(delivery):
    paths, _ = delivery
    assert gate(paths)['delivery_valid']
    script = Path(__file__).resolve().parents[1] / 'audit_reduction_gate.py'
    result = subprocess.run([sys.executable, str(script)] + [
        part for name in ('manifest', 'accepted', 'decisions') for part in ('--' + name, str(paths[name]))
    ] + ['--lane', f'a={paths["a"]}', '--lane', f'b={paths["b"]}'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)['research_status'] == {'ACCEPTED': 1}


def test_only_the_accepted_record_needs_the_prose_the_ledger_requires(delivery):
    paths, index = delivery
    for lane in ('a', 'accepted'):
        path = paths[lane] / 'case.json'
        record = json.loads(path.read_text())
        del record['flaw_origin']
        path.write_text(json.dumps(record))
        index['cases']['alias-x']['sha256'][lane] = digest(path)
    save_index(paths, index)
    problems = gate(paths)['problems']
    assert any('accepted record needs its prose' in p for p in problems)
    assert not any('input_quality' in p for p in problems)


def test_explicit_evidence_backed_resolution_can_close_a_difference(delivery):
    paths, index = delivery
    file = paths['b'] / 'case.json'
    record = json.loads(file.read_text())
    record['fix_sha'] = 'c' * 40
    file.write_text(json.dumps(record))
    decision = index['cases']['alias-x']
    decision['sha256']['b'] = digest(file)
    save_index(paths, index)
    assert not gate(paths)['delivery_valid']
    decision['resolutions']['fix'] = 'A names the first default landing; B names its member. The retained parent/tree receipt distinguishes those roles and supports A for fix_sha.'
    save_index(paths, index)
    assert gate(paths)['delivery_valid']


@pytest.mark.parametrize('target', ['a', 'b', 'accepted', 'receipt', 'extra_pin'])
def test_any_changed_accepted_dependency_invalidates_delivery(delivery, target):
    paths, index = delivery
    if target == 'extra_pin':
        file = paths['decisions'].parent / 'staging.jsonl'
        file.write_text('{}\n')
        index['pins']['staging'] = {'path': str(file), 'sha256': digest(file)}
        save_index(paths, index)
    elif target == 'receipt':
        file = paths['decisions'].parent / 'evidence.txt'
    else:
        file = paths[target] / 'case.json'
    file.write_text(file.read_text() + '\n')
    result = gate(paths)
    assert not result['delivery_valid']
    assert any('changed' in p for p in result['problems'])


def test_missing_on_both_lanes_cannot_disappear_from_denominator(delivery):
    paths, index = delivery
    paths['manifest'].write_text('alias-x\nalias-y\n')
    index['pins']['manifest']['sha256'] = digest(paths['manifest'])
    save_index(paths, index)
    result = gate(paths)
    assert result['cases'] == 2 and not result['delivery_valid']
    assert result['research_status']['PENDING'] == 1


def test_duplicate_case_ids_are_not_last_writer_wins(delivery):
    paths, _ = delivery
    (paths['a'] / 'duplicate.json').write_bytes((paths['a'] / 'case.json').read_bytes())
    with pytest.raises(ValueError, match='duplicate class_id'):
        load(paths['a'])


def test_exact_record_inputs_preserve_all_lanes_with_raw_json_evidence(delivery):
    paths, _ = delivery
    evidence = paths['a'] / 'evidence'
    evidence.mkdir()
    (evidence / 'api-response.json').write_text('[{"id": 1}]')
    with pytest.raises(ValueError, match='JSON object'):
        load(paths['a'])
    records = {**paths, **{lane: paths[lane] / 'case.json'
                          for lane in ('a', 'b', 'accepted')}}
    result = gate(records)
    assert result['delivery_valid'] and result['cases'] == 1
    assert set(result['auditors']) == {'a', 'b'}
    records['b'].write_text(records['b'].read_text() + '\n')
    assert not gate(records)['delivery_valid']


def test_blocked_is_not_all_accepted(delivery):
    paths, index = delivery
    index['cases']['alias-x'].update(status='BLOCKED', next_question='Which release actually contains the repair?')
    save_index(paths, index)
    result = gate(paths)
    assert result['research_status']['BLOCKED'] == 1 and not result['delivery_valid']


def test_tp_agreement_still_requires_primary_adjudication(delivery):
    paths, index = delivery
    for name in ('a', 'b', 'accepted'):
        file = paths[name] / 'case.json'
        record = json.loads(file.read_text())
        record.update(verdict='AI_ROOT_CAUSE', ai_on_bic=True, ai_marker={'state': 'PRESENT'})
        file.write_text(json.dumps(record))
        index['cases']['alias-x']['sha256'][name] = digest(file)
    save_index(paths, index)
    result = gate(paths)
    for dimension in ('bic', 'ai', 'fix'):
        assert any('unresolved ' + dimension in p for p in result['problems'])


def test_different_member_roles_do_not_cancel_each_other():
    assert 'bic' in research_differences_many({'a': {'decomposed_shas': ['a' * 40]}, 'b': {'candidate_set': ['a' * 40]}})


def test_third_auditor_dissent_is_required_even_when_first_two_agree(delivery):
    paths, index = delivery
    third = paths['a'].parent / 'third'
    third.mkdir()
    record = json.loads((paths['a'] / 'case.json').read_text())
    record['fix_sha'] = 'c' * 40
    (third / 'case.json').write_text(json.dumps(record))
    lanes = {'a': paths['a'], 'b': paths['b'], 'third': third}
    index['auditors'].append('third')
    index['cases']['alias-x']['sha256']['third'] = digest(third / 'case.json')
    save_index(paths, index)
    report = compare_many(lanes)
    assert report['shared'] == 1
    assert report['research_differences']['alias-x']['fix']['fix_sha']['third'] == 'c' * 40
    result = gate(paths, lanes=lanes)
    assert any('unresolved fix' in p for p in result['problems'])
    index['cases']['alias-x']['resolutions']['fix'] = 'The third report names the repair member; the other reports name the default landing. The retained tree receipt supports the landing for fix_sha.'
    save_index(paths, index)
    assert gate(paths, lanes=lanes)['delivery_valid']
    assert not gate(paths)['delivery_valid']
    (third / 'case.json').write_text(json.dumps(record) + '\n')
    assert not gate(paths, lanes=lanes)['delivery_valid']


def test_named_lane_cli_and_invalid_lane_arguments(delivery):
    paths, _ = delivery
    scripts = Path(__file__).resolve().parents[1]
    named = ['--lane', f'a={paths["a"]}', '--lane', f'b={paths["b"]}']
    for script, extra in [
        ('compare_slots.py', []),
        ('audit_reduction_gate.py', [part for key in ('manifest', 'accepted', 'decisions')
                                    for part in ('--' + key, str(paths[key]))]),
    ]:
        result = subprocess.run([sys.executable, str(scripts / script), *named, *extra], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr + result.stdout
    for values in [['a=x', 'a=y'], ['accepted=x'], ['a=x', 'b=x'], ['not-a-pair']]:
        with pytest.raises(ValueError):
            lane_paths(values)
    with pytest.raises(ValueError):
        lane_paths([])


def adopt_research_contract(paths, index):
    index['research_contract'] = RESEARCH_CONTRACT
    evidence = index['cases']['alias-x']['evidence']
    research = {dimension: {
        'evidence_grade': 'BOUND', 'work_state': 'COMPLETE',
        'finding': f'The fixture {dimension} conclusion is supported within its stated scope.',
        'evidence': evidence, 'missing_fact': None,
        'next_permitted_route': None, 'routes': [],
    } for dimension in WORK_DIMENSIONS}
    index['cases']['alias-x']['research'] = research
    save_index(paths, index)
    return research


def proposed_route():
    return {'id': 'repair-parent-child', 'question': 'Does the repair close the rollback defect?',
            'source': 'upstream repository', 'evidence_type': 'parent/child diff', 'status': 'PENDING'}


def test_new_contract_requires_explicit_adoption_and_does_not_change_legacy(delivery):
    paths, index = delivery
    assert gate(paths)['delivery_valid']
    assert not gate(paths, research_contract=RESEARCH_CONTRACT)['delivery_valid']
    adopt_research_contract(paths, index)
    result = gate(paths, research_contract=RESEARCH_CONTRACT)
    assert result['delivery_valid']
    assert result['research_work']['dimension_counts'] == {'COMPLETE': len(WORK_DIMENSIONS)}
    assert result['research_work']['worklist'] == []
    index.pop('research_contract')
    save_index(paths, index)
    assert not gate(paths)['delivery_valid']


def test_frozen_decisions_do_not_share_the_mutable_dispatch_index(delivery):
    paths, index = delivery
    paths['decisions'].write_text(json.dumps({'reduction': index, 'dispatch': {}}))
    assert gate(paths)['delivery_valid']
    adopt_research_contract(paths, index)
    for field in ('dispatch', 'allocation'):
        paths['decisions'].write_text(json.dumps({'reduction': index, field: {}}))
        result = gate(paths, research_contract=RESEARCH_CONTRACT)
        assert not result['delivery_valid']
        assert any('mutable dispatch index' in p for p in result['problems'])
    save_index(paths, index)
    frozen = paths['decisions'].read_bytes()
    execution = paths['decisions'].parent / 'execution-index.json'
    execution.write_text(json.dumps({'dispatch': {'a': {'status': 'returned'}}}))
    assert gate(paths, research_contract=RESEARCH_CONTRACT)['delivery_valid']
    execution.write_text(json.dumps({'dispatch': {'a': {'status': 'receipt-recorded'}}}))
    assert paths['decisions'].read_bytes() == frozen
    assert gate(paths, research_contract=RESEARCH_CONTRACT)['delivery_valid']


@pytest.mark.parametrize('grade', ['QUALIFIED_BOUNDARY', 'UNRESOLVED'])
def test_worklist_does_not_filter_by_evidence_grade(delivery, grade):
    paths, index = delivery
    research = adopt_research_contract(paths, index)
    research['fix'].update(evidence_grade=grade, work_state='UNFINISHED',
                           missing_fact='The contents of the repair.',
                           next_permitted_route='repair-parent-child', routes=[proposed_route()])
    save_index(paths, index)
    result = gate(paths)
    assert result['research_work']['worklist'] == [
        {'class_id': 'alias-x', 'dimension': 'fix', 'next_permitted_route': 'repair-parent-child'}]
    assert any('ACCEPTED contradicts unfinished' in p for p in result['problems'])


@pytest.mark.parametrize('outcome', ['PENDING', 'FAILED', 'TIMEOUT', 'AUTHORITY_ABSENCE', [], None])
def test_false_route_terminality_never_counts_as_completion(delivery, outcome):
    paths, index = delivery
    research = adopt_research_contract(paths, index)
    route = {**proposed_route(), 'status': outcome, 'observation': 'Original operation result retained.',
             'evidence': index['cases']['alias-x']['evidence']}
    research['fix'].update(evidence_grade='QUALIFIED_BOUNDARY',
                           missing_fact='Complete repair contents.', routes=[route])
    save_index(paths, index)
    result = gate(paths)
    assert not result['delivery_valid']
    assert result['research_work']['unassessed_cases'] == ['alias-x']


@pytest.mark.parametrize('outcome', ['ANSWERED', 'UNAVAILABLE', 'EXHAUSTED', 'PROHIBITED'])
def test_recorded_frontier_does_not_upgrade_a_grade_or_protocol_acceptance(delivery, outcome):
    paths, index = delivery
    research = adopt_research_contract(paths, index)
    decision = index['cases']['alias-x']
    decision.update(status='BLOCKED', next_question='Where is the original pre-import contribution?')
    research['bic'].update(evidence_grade='QUALIFIED_BOUNDARY', missing_fact='Pre-import authoring change.',
                          routes=[{**proposed_route(), 'status': outcome,
                                   'observation': 'The recorded source inquiry does not recover the member.',
                                   'evidence': decision['evidence']}])
    save_index(paths, index)
    result = gate(paths)
    assert not result['delivery_valid']
    assert result['research_work']['worklist'] == []
    assert result['research_work']['unassessed_cases'] == []
    assert result['research_work']['evidence_boundaries'] == [{'class_id': 'alias-x', 'dimension': 'bic'}]
    assert result['research_status'] == {'BLOCKED': 1}
    assert json.loads(paths['decisions'].read_text())['reduction']['cases']['alias-x']['research']['bic']['evidence_grade'] == 'QUALIFIED_BOUNDARY'


def test_route_aliases_and_stale_receipts_are_rejected(delivery):
    paths, index = delivery
    research = adopt_research_contract(paths, index)
    route = {**proposed_route(), 'status': 'ANSWERED', 'observation': 'Read the repair.',
             'evidence': index['cases']['alias-x']['evidence']}
    research['fix']['routes'] = [route, {**route, 'id': 'another-label'}]
    save_index(paths, index)
    assert any('duplicate evidence route' in p for p in gate(paths)['problems'])
    research['fix']['routes'] = [route]
    route['evidence'] = [{'path': 'evidence.txt', 'sha256': '0' * 64}]
    save_index(paths, index)
    assert any('empty or changed file' in p for p in gate(paths)['problems'])


def test_missing_independent_lane_does_not_hide_declared_unfinished_work(delivery):
    paths, index = delivery
    research = adopt_research_contract(paths, index)
    research['fix'].update(work_state='UNFINISHED', routes=[proposed_route()],
                           next_permitted_route='repair-parent-child')
    (paths['b'] / 'case.json').unlink()
    save_index(paths, index)
    result = gate(paths)
    assert not result['delivery_valid']
    assert result['research_work']['worklist'][0]['dimension'] == 'fix'
    assert result['research_status'] == {'PENDING': 1}


def test_new_resolution_accounts_for_each_lane_and_binds_primary_observation(delivery):
    paths, index = delivery
    adopt_research_contract(paths, index)
    file = paths['b'] / 'case.json'
    record = json.loads(file.read_text())
    record['fix_sha'] = 'c' * 40
    file.write_text(json.dumps(record))
    decision = index['cases']['alias-x']
    decision['sha256']['b'] = digest(file)
    decision['resolutions']['fix'] = 'Both repaired it.'
    save_index(paths, index)
    assert not gate(paths)['delivery_valid']
    resolution = {'claims': {'a': 'Default landing b.', 'b': 'Repair member c.'},
                  'observation': 'The member diff matches the repaired tree in the landing.',
                  'reasoning': 'The reports name different causal roles, not different repairs.',
                  'conclusion': 'Keep b as the default landing and c as the member.',
                  'evidence': decision['evidence']}
    decision['resolutions']['fix'] = resolution
    save_index(paths, index)
    assert gate(paths)['delivery_valid']
    resolution['claims'].pop('b')
    save_index(paths, index)
    assert not gate(paths)['delivery_valid']


def test_new_contract_cli_and_missing_research_do_not_report_zero_work_as_complete(delivery):
    paths, index = delivery
    adopt_research_contract(paths, index)
    script = Path(__file__).resolve().parents[1] / 'audit_reduction_gate.py'
    args = [sys.executable, str(script), '--research-contract', RESEARCH_CONTRACT]
    args += cli_args(paths)
    assert subprocess.run(args, capture_output=True, text=True).returncode == 0
    index['cases']['alias-x']['research'].pop('fix')
    save_index(paths, index)
    result = gate(paths)
    assert not result['delivery_valid']
    assert result['research_work']['unassessed_cases'] == ['alias-x']


def test_missing_dimension_preserves_known_pending_work(delivery):
    paths, index = delivery
    research = adopt_research_contract(paths, index)
    research.pop('versions')
    research['fix'].update(work_state='UNFINISHED', routes=[proposed_route()],
                           next_permitted_route='repair-parent-child')
    save_index(paths, index)
    result = gate(paths)
    assert not result['delivery_valid']
    assert result['research_work']['unassessed_cases'] == ['alias-x']
    assert result['research_work']['worklist'] == [
        {'class_id': 'alias-x', 'dimension': 'fix', 'next_permitted_route': 'repair-parent-child'}]


def test_supplied_resolution_is_checked_even_when_every_record_agrees(delivery):
    paths, index = delivery
    adopt_research_contract(paths, index)
    decision = index['cases']['alias-x']
    decision['resolutions']['fix'] = {
        'claims': {'a': 'Repair b.', 'b': 'Repair b.'},
        'observation': 'Primary comparison.', 'reasoning': 'Shared premise checked.',
        'conclusion': 'b closes this source mechanism.',
        'evidence': [{'path': 'missing.txt', 'sha256': '0' * 64}],
    }
    save_index(paths, index)
    result = gate(paths)
    assert not result['delivery_valid']
    assert any('fix resolution evidence' in p and 'missing.txt' in p for p in result['problems'])


def test_adjudicator_change_to_unanimous_reports_requires_resolution(delivery):
    paths, index = delivery
    adopt_research_contract(paths, index)
    file = paths['accepted'] / 'case.json'
    record = json.loads(file.read_text())
    record['fix_sha'] = 'c' * 40
    file.write_text(json.dumps(record))
    index['cases']['alias-x']['sha256']['accepted'] = digest(file)
    save_index(paths, index)
    assert any('unresolved fix' in p for p in gate(paths)['problems'])


@pytest.mark.parametrize('lane', ['a', 'accepted'])
@pytest.mark.parametrize('verdict', [[], {}, 42, False])
def test_malformed_verdict_reports_case_and_lane_without_cli_crash(delivery, lane, verdict):
    paths, index = delivery
    file = paths[lane] / 'case.json'
    record = json.loads(file.read_text())
    record['verdict'] = verdict
    file.write_text(json.dumps(record))
    index['cases']['alias-x']['sha256'][lane] = digest(file)
    save_index(paths, index)
    result = gate(paths)
    assert not result['delivery_valid']
    assert any(f'alias-x: {lane} verdict' in p for p in result['problems'])
    script = Path(__file__).resolve().parents[1] / 'audit_reduction_gate.py'
    args = [sys.executable, str(script)] + cli_args(paths)
    run = subprocess.run(args, capture_output=True, text=True)
    assert run.returncode == 1 and 'Traceback' not in run.stderr
    assert json.loads(run.stdout)['delivery_valid'] is False


def test_bound_fact_cannot_simultaneously_declare_a_decisive_gap(delivery):
    paths, index = delivery
    research = adopt_research_contract(paths, index)
    research['fix']['missing_fact'] = 'Whether the fix actually closes this mechanism.'
    save_index(paths, index)
    assert any('BOUND cannot retain' in p for p in gate(paths)['problems'])
