import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
scripts = Path.cwd() / 'contract' / 'scripts'
sys.path.insert(0, str(scripts))
import audit_delivery
from audit_reduction_gate import PIN_ROLES, WORK_DIMENSIONS, digest
from compare_slots import RESEARCH_FIELDS

output, prompt = Path(sys.argv[1]), sys.argv[2]
header = dict(line.split(': ', 1) for line in prompt.split('\n\n', 1)[0].splitlines() if ': ' in line)
task, role = header['Task'], header['Role']
mode = os.environ.get('RADAR_FIXTURE_' + task.upper(), '')
if mode == 'fail':
    raise SystemExit(124)
if mode == 'refuse':
    print('Internal error: This content was flagged for possible cybersecurity risk.', file=sys.stderr)
    raise SystemExit(1)

if role == 'reviewer':
    inputs = header['Pinned inputs'].split(', ')
    adjudicated = next(Path(p) for p in inputs if (Path(p) / 'DELIVERY.json').is_file()
                       and 'decisions' in audit_delivery.read(Path(p) / 'DELIVERY.json'))
    seal = adjudicated / 'DELIVERY.json'
    sealed = audit_delivery.read(seal)
    cid = sealed['case_ids'][0]
    evidence = sealed['evidence'][0]
    leader = re.search(r'on behalf of (\S+), in a fresh session', prompt).group(1)
    decision = 'RETURN' if mode == 'return' else 'ACCEPT'
    review = {'batch': header['Batch'], 'leader': leader, 'delivery_sha256': digest(seal),
              'cases': {cid: {'decision': decision, 'basis': 'Fixture review of the controlled observation.',
                              'evidence': [{'path': evidence, 'sha256': sealed['files'][evidence]}],
                              'next_question': 'Fixture follow-up question.' if decision == 'RETURN' else None}}}
    (output / 'leader-review.json').write_text(json.dumps(review))
    raise SystemExit(0)

public = output / 'INPUT-BINDING.json'
from radar_flow import inputs
inputs(public, header['Task binding'])
binding = audit_delivery.read(public)['binding']
cid = binding['case_ids'][0]
ids = [s['id'] for s in json.loads((Path.cwd() / 'inputs' / 'SOURCES.json').read_text())['sources']]
case = output / cid
(case / 'evidence').mkdir(parents=True)
(case / 'REPORT.md').write_text('Offline control fixture. Every causal label here is test data.\n')
(case / 'evidence' / 'source.txt').write_text('Harmless fixture primary observation; no target interaction.\n')
record = {'class_id': cid, 'verdict': 'FALSE_POSITIVE', 'advisory_ids': ids, 'advisory_disposition': 'ACTIVE',
          'advisory_aliases': [{'id': ids[0], 'state': 'ACTIVE'}], 'false_positive_ground': 'MECHANISM_REFUTED',
          'introducer_sha': None, 'landing_commit': None, 'bic_granularity': None, 'fix_sha': None,
          'fix_granularity': None, 'fix_ai_marker': {'state': 'UNKNOWN'},
          'flip_condition': 'a source showing the count endpoint serializes the message body',
          'evidence': 'The keyed endpoint returns only a count; the claimed message body is never selected or serialized.'}
(case / 'record.json').write_text(json.dumps(record))
receipt = {'path': 'evidence/source.txt', 'sha256': digest(case / 'evidence' / 'source.txt')}


def research(path):
    return {dimension: {'evidence_grade': 'BOUND', 'work_state': 'COMPLETE',
                        'finding': 'The harmless fixture answers this dimension.', 'missing_fact': None,
                        'next_permitted_route': None, 'routes': [],
                        'evidence': [{'path': path, 'sha256': receipt['sha256']}]} for dimension in WORK_DIMENSIONS}


(case / 'research.json').write_text(json.dumps({'research': research(receipt['path'])}))
checks = output / 'checks'
checks.mkdir()
argv = [sys.executable, '-B', str(scripts / 'audit_record_gates.py'), '--strict', str(case / 'record.json')]
gate = subprocess.run(argv, capture_output=True, text=True)
(checks / 'strict.stdout').write_text(gate.stdout)
(checks / 'strict.json').write_text(json.dumps({'argv': argv, 'exit_code': gate.returncode, 'outputs': [
    {'path': str(checks / 'strict.stdout'), 'sha256': digest(checks / 'strict.stdout')}]}))
spec = {'batch': binding['batch'], 'task': binding['task'], 'binding_sha256': header['Task binding'],
        'manifest': binding['manifest']['path'], 'output': str(output), 'report': str(case / 'REPORT.md'),
        'records': {cid: str(case / 'record.json')}, 'research_work': {cid: str(case / 'research.json')},
        'evidence': [str(case / 'evidence' / 'source.txt')], 'checks': [str(checks / 'strict.json')]}
if role == 'adjudicator':
    lanes = {}
    for root in binding['inputs']:
        if (Path(root) / 'DELIVERY.json').is_file():
            sealed = audit_delivery.read(Path(root) / 'DELIVERY.json')
            lanes[sealed['task']] = sealed
    pins = {name: case / 'evidence' / 'source.txt' for name in PIN_ROLES}
    pins.update(manifest=Path(binding['manifest']['path']), brief=Path(binding['brief']),
                record_gate=scripts / 'audit_record_gates.py', comparison=scripts / 'compare_slots.py',
                reduction_gate=scripts / 'audit_reduction_gate.py')
    decision = {'sha256': {**{name: digest(Path(lane['records'][cid])) for name, lane in lanes.items()},
                           'accepted': digest(case / 'record.json')},
                'status': 'ACCEPTED', 'basis': 'Harmless test fixture only.',
                'reviewed_dimensions': list(RESEARCH_FIELDS), 'resolutions': {},
                'evidence': [{'path': str(case / 'evidence' / 'source.txt'), 'sha256': receipt['sha256']}],
                'research': research(f'{cid}/evidence/source.txt')}
    reduction = {'reducer': binding['agent'], 'auditors': sorted(lanes), 'research_contract': 'causal-work-v1',
                 'pins': {name: {'path': str(path), 'sha256': digest(path)} for name, path in pins.items()},
                 'cases': {cid: decision}}
    (output / 'decisions.json').write_text(json.dumps({'reduction': reduction}))
    spec['decisions'] = str(output / 'decisions.json')
audit_delivery.seal(spec)
