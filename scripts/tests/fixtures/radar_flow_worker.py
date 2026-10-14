"""Harmless foreground worker for orchestration tests; contains no vulnerability research."""
import json
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
import audit_delivery
from audit_reduction_gate import PIN_ROLES, WORK_DIMENSIONS, digest
from compare_slots import RESEARCH_FIELDS
from radar_flow import inputs

public = Path(sys.argv[2])
binding = audit_delivery.read(public)['binding']
inputs(public, audit_delivery.read(public)['sha256'])
root = public.parent
packet = audit_delivery.read(Path(binding['brief']))
if packet.get('fail'):
    raise SystemExit(124)
record = packet['record']
cid = record['class_id']
(root / 'report.md').write_text('Offline control fixture. Every causal label here is test data.\n')
(root / 'record.json').write_text(json.dumps(record))
(root / 'evidence.txt').write_text('Harmless fixture primary observation; no target interaction.\n')
evidence = {'path': 'evidence.txt', 'sha256': digest(root / 'evidence.txt')}
work = {dimension: {'evidence_grade': 'BOUND', 'work_state': 'COMPLETE',
                   'finding': 'The harmless fixture answers this dimension.',
                   'missing_fact': None, 'next_permitted_route': None, 'routes': [],
                   'evidence': [evidence]} for dimension in WORK_DIMENSIONS}
(root / 'research.json').write_text(json.dumps({'research': work}))
(root / 'check.json').write_text(json.dumps({'argv': ['offline-fixture-check'], 'exit_code': 0}))
spec = {'batch': binding['batch'], 'task': binding['task'],
        'binding_sha256': audit_delivery.read(public)['sha256'], 'manifest': binding['manifest']['path'],
        'output': str(root), 'report': str(root / 'report.md'), 'records': {cid: str(root / 'record.json')},
        'research_work': {cid: str(root / 'research.json')}, 'evidence': [str(root / 'evidence.txt')],
        'checks': [str(root / 'check.json')]}
if binding['role'] == 'adjudicator':
    auditors = {name: audit_delivery.read(Path(output) / 'DELIVERY.json')
                for name, output in packet['lanes'].items()}
    scripts = Path(sys.argv[1])
    pins = {role: root / 'evidence.txt' for role in PIN_ROLES}
    pins.update(manifest=Path(binding['manifest']['path']), brief=Path(binding['brief']),
                record_gate=scripts / 'audit_record_gates.py', comparison=scripts / 'compare_slots.py',
                reduction_gate=scripts / 'audit_reduction_gate.py')
    decision = {'sha256': {**{name: digest(Path(lane['records'][cid])) for name, lane in auditors.items()},
                           'accepted': digest(root / 'record.json')},
                'status': 'ACCEPTED', 'basis': 'Harmless test fixture only.',
                'reviewed_dimensions': list(RESEARCH_FIELDS), 'resolutions': {},
                'evidence': [evidence], 'research': work}
    reduction = {'reducer': binding['agent'], 'auditors': list(auditors), 'research_contract': 'causal-work-v1',
                 'pins': {role: {'path': str(path), 'sha256': digest(path)} for role, path in pins.items()},
                 'cases': {cid: decision}}
    (root / 'decisions.json').write_text(json.dumps({'reduction': reduction}))
    spec['decisions'] = str(root / 'decisions.json')
audit_delivery.seal(spec)
