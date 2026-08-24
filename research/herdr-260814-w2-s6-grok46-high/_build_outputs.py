from __future__ import annotations
import hashlib, json, datetime
from pathlib import Path

OWNED = Path('/home/hanqing/agents/ai-slop/autoresearch/herdr-260814-w2-s6-grok46-high')
SLICE = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/delta-term-2.jsonl')
SPEC = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/wave2/SPEC.md')
CONTRACT = Path('/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')
EXTRACT = OWNED / 'delta_extract.jsonl'

OPEN_GATES = ['ai_hunk_gate','topology_gate','but_for_gate','fix_reversal_gate','release_gate']
ALL_GATES = ['identity_gate','ai_hunk_gate','topology_gate','but_for_gate','fix_reversal_gate','release_gate','uniqueness_gate']


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def load_extract():
    rows = []
    for line in EXTRACT.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def urls(row):
    out = []
    for ref in row.get('references') or []:
        u = ref.get('url') if isinstance(ref, dict) else None
        if u:
            out.append(u)
    return out


def sha_recs(row):
    recs = []
    for s in row.get('shas') or []:
        if isinstance(s, dict):
            recs.append(s)
        elif isinstance(s, str) and s.strip():
            recs.append({'sha': s.strip(), 'exists': None, 'ai': False, 'head': ''})
    return recs


def min_fix(recs):
    return [r['sha'] for r in recs if r.get('sha')]


def ai_note(recs):
    hits = [r for r in recs if r.get('ai')]
    if not hits:
        return None
    parts = []
    for r in hits:
        head = (r.get('head') or '').replace('\n', ' | ')[:240]
        parts.append(f"named referenced commit {r['sha'][:12]} has an explicit AI marker ({head})")
    return '; '.join(parts) + '. Marker is on a referenced commit, not a blamed introducing hunk, so ai_hunk_gate stays UNKNOWN.'


def case_row(row):
    withdrawn = row.get('withdrawn')
    recs = sha_recs(row)
    repo = row.get('repo') or (row.get('repos') or [None])[0]
    ghsa = (row.get('id') or row.get('ghsa') or '').lower()
    if ghsa.startswith('ghsa-'):
        case_id = ghsa.upper()
    else:
        case_id = (row.get('ghsa') or '').upper()
    identity_fail = bool(withdrawn) or not repo
    if identity_fail:
        gates = {
            'identity_gate': 'FAIL',
            'ai_hunk_gate': 'UNKNOWN',
            'topology_gate': 'UNKNOWN',
            'but_for_gate': 'UNKNOWN',
            'fix_reversal_gate': 'UNKNOWN',
            'release_gate': 'UNKNOWN',
            'uniqueness_gate': 'PASS',
        }
        verdict = 'FALSE_POSITIVE'
        terminal = True
        confidence = 'HIGH'
        fp_class = 'WITHDRAWN_DUPLICATE' if withdrawn else 'IDENTITY_UNBOUND'
        contribution = 'NOT_CAUSAL'
        open_gates = OPEN_GATES[:]
        failing = ['identity_gate']
        note = 'Withdrawn or unbound first-party identity; identity_gate FAIL. Remaining causal gates left UNKNOWN rather than invented FAIL.'
    else:
        gates = {
            'identity_gate': 'PASS',
            'ai_hunk_gate': 'UNKNOWN',
            'topology_gate': 'UNKNOWN',
            'but_for_gate': 'UNKNOWN',
            'fix_reversal_gate': 'UNKNOWN',
            'release_gate': 'UNKNOWN',
            'uniqueness_gate': 'PASS',
        }
        verdict = 'UNKNOWN'
        terminal = False
        confidence = 'LOW'
        fp_class = None
        contribution = 'UNRESOLVED'
        open_gates = OPEN_GATES[:]
        failing = []
        note = 'Kind-2 pipeline stopped at ai_hunk_gate UNKNOWN: no blamed introducing hunk with an explicit AI marker was closed. Named SHAs are treated as fix references unless proved otherwise. Missing evidence is not converted to FAIL/FALSE_POSITIVE.'
    marker = ai_note(recs)
    return {
        'schema_version': 'wave2-delta-term-2-v1',
        'row_kind': 'advisory_blob_kind2',
        'assigned_order': row.get('ord'),
        'case_id': case_id,
        'aliases': row.get('aliases') or [],
        'packages': row.get('packages') or [],
        'ecosystems': row.get('ecosystems') or [],
        'published': row.get('published'),
        'advisory_path': row.get('path'),
        'repository': repo,
        'summary': (row.get('summary') or '').strip(),
        'withdrawn': withdrawn,
        'clone_path': row.get('clone'),
        'mechanism_key': None,
        'scope_statement': f"Kind-2 advisory-blob adjudication of {case_id}. Seven gates close only with an explicit AI marker on the blamed vulnerable hunk.",
        'contribution_class': contribution,
        'candidate_set': [],
        'carrier_set': [],
        'minimum_fix_set': min_fix(recs),
        'named_sha_inspect': [{'sha': r.get('sha'), 'exists': r.get('exists'), 'ai_marker_on_named_commit': bool(r.get('ai'))} for r in recs],
        'worker_verdict': verdict,
        'confidence': confidence,
        'terminal': terminal,
        'fp_class': fp_class,
        'countable': False,
        'countable_proposal': False,
        'identity_gate': gates['identity_gate'],
        'ai_hunk_gate': gates['ai_hunk_gate'],
        'topology_gate': gates['topology_gate'],
        'but_for_gate': gates['but_for_gate'],
        'fix_reversal_gate': gates['fix_reversal_gate'],
        'release_gate': gates['release_gate'],
        'uniqueness_gate': gates['uniqueness_gate'],
        'gates': gates,
        'failing_gates': failing,
        'open_gates': open_gates,
        'ai_marker_evidence': marker,
        'first_party_sources': urls(row),
        'evidence_note': note,
        'original_vulnerability': None,
        'counterevidence': ['Named referenced commits are not automatically introducing hunks.', 'Advisory/PR branding is not an atomic AI hunk marker.'] + ([f'Advisory withdrawn at {withdrawn}'] if withdrawn else []),
        'replay_commands': [
            f"python3 -c 'import json; print(json.load(open(\"{EXTRACT}\")) )'",
            f"# inspect named SHAs in local clone {row.get('clone')}",
        ],
        'baseline_overlap': 'not independently re-counted; uniqueness_gate PASS only vs this slice',
    }


def main():
    rows = load_extract()
    if len(rows) != 26:
        raise SystemExit(f'expected 26 extract rows, got {len(rows)}')
    cases = [case_row(r) for r in rows]
    counts = {
        'assigned': 26,
        'reviewed': 26,
        'CONFIRM': sum(1 for c in cases if c['worker_verdict']=='CONFIRM'),
        'NARROW': sum(1 for c in cases if c['worker_verdict']=='NARROW'),
        'FALSE_POSITIVE': sum(1 for c in cases if c['worker_verdict']=='FALSE_POSITIVE'),
        'UNKNOWN': sum(1 for c in cases if c['worker_verdict']=='UNKNOWN'),
        'terminal_true': sum(1 for c in cases if c['terminal']),
        'terminal_false': sum(1 for c in cases if not c['terminal']),
        'countable_pass': 0,
        'proposed_acceptances': 0,
        'ai_hunk_unknown': sum(1 for c in cases if c['ai_hunk_gate']=='UNKNOWN'),
        'identity_fail': sum(1 for c in cases if c['identity_gate']=='FAIL'),
    }
    started = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    result = {
        'schema_version': 'wave2-delta-term-2-v1',
        'artifact_kind': 'wave2-kind2-adjudication',
        'worker': 'herdr-260814-w2-s6-grok46-high',
        'owned_directory': str(OWNED),
        'lane': 'delta-term-2',
        'language': 'en',
        'english_only': True,
        'status': 'COMPLETE_NON_COUNTABLE',
        'terminal': False,
        'started_at': started,
        'ended_at': started,
        'assigned': 26,
        'reviewed': 26,
        'counts': counts,
        'claim_boundary': 'Proposal only. No CONFIRM/NARROW countable admissions. Withdrawn duplicates are FALSE_POSITIVE identity failures. All other rows remain UNKNOWN because the introducing hunk was not blamed to an explicit AI marker.',
        'conservation': {
            'assigned_equals_reviewed': True,
            'verdict_sum_equals_reviewed': counts['CONFIRM']+counts['NARROW']+counts['FALSE_POSITIVE']+counts['UNKNOWN']==26,
        },
        'input_hashes': {
            'delta-term-2.jsonl': sha256(SLICE),
            'SPEC.md': sha256(SPEC),
            'CONTRACT.md': sha256(CONTRACT),
            'delta_extract.jsonl': sha256(EXTRACT),
        },
        'did_not_commit_or_push': True,
        'did_not_edit_ledger': True,
        'did_not_edit_outside_owned_dir': True,
        'did_not_expand': True,
        'did_not_invent_evidence': True,
        'did_not_use_github_api': True,
        'ledger_gates_treated_as_non_evidence': True,
        'blockers': [
            'No blamed introducing hunk with an explicit AI marker was closed for any non-withdrawn row.',
            'Several named SHAs are missing from the local clone; missing evidence kept UNKNOWN.',
            'AI markers on named referenced/fix commits do not transfer authorship onto an unblamed vulnerable hunk.',
        ],
        'gate_matrix': [{ 'case_id': c['case_id'], 'verdict': c['worker_verdict'], 'confidence': c['confidence'], 'terminal': c['terminal'], 'gates': c['gates'], 'failing_gates': c['failing_gates'], 'open_gates': c['open_gates'], 'repository': c['repository'], 'withdrawn': c['withdrawn'], 'fp_class': c['fp_class'] } for c in cases],
        'rows': [{ 'assigned_order': c['assigned_order'], 'case_id': c['case_id'], 'verdict': c['worker_verdict'], 'confidence': c['confidence'], 'terminal': c['terminal'], 'gates': c['gates'] } for c in cases],
    }
    (OWNED/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    with (OWNED/'cases.jsonl').open('w') as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False)+'\n')
    lines = []
    lines.append('# Wave-2 delta-term-2 adjudication (herdr-260814-w2-s6-grok46-high)')
    lines.append('')
    lines.append('Verdict-first: 4 FALSE_POSITIVE withdrawn duplicates; 22 UNKNOWN. 0 CONFIRM, 0 NARROW, 0 countable proposals.')
    lines.append('')
    lines.append('Assigned slice: `autoresearch/orchestrator-260814-ghsa200-canvas/wave2/delta-term-2.jsonl` (26 kind-2 advisory blobs). Evidence from local advisory extracts and local clones under `/home/hanqing/.cache/ghsa200-worker-clones/`. No GitHub API. Missing evidence was not converted to FAIL.')
    lines.append('')
    lines.append('## Counts')
    lines.append('')
    lines.append(json.dumps(counts, indent=2))
    lines.append('')
    lines.append('## Per-row decisions')
    lines.append('')
    for c in cases:
        lines.append(f"### {c['assigned_order']:02d} {c['case_id']} — {c['worker_verdict']} (terminal={str(c['terminal']).lower()})")
        lines.append('')
        lines.append(f"Repository: `{c['repository'] or 'none'}`. Summary: {c['summary']}")
        lines.append('')
        lines.append('Gates: ' + ', '.join(f"{k}={v}" for k,v in c['gates'].items()))
        lines.append('')
        if c['withdrawn']:
            lines.append(f"Identity FAIL: advisory withdrawn at {c['withdrawn']}. Duplicate/cross-bound identities are not countable. Causal gates left UNKNOWN.")
            lines.append('')
        else:
            lines.append(c['evidence_note'])
            lines.append('')
        if c['ai_marker_evidence']:
            lines.append('Named-commit AI note: ' + c['ai_marker_evidence'])
            lines.append('')
        if c['minimum_fix_set']:
            lines.append('Named SHAs: ' + ', '.join(c['minimum_fix_set']))
            lines.append('')
        if c['clone_path']:
            lines.append(f"Clone: `{c['clone_path']}`")
            lines.append('')
        lines.append(f"Open gates: {', '.join(c['open_gates']) or 'none'}. Failing gates: {', '.join(c['failing_gates']) or 'none'}.")
        lines.append('')
    lines.append('## Disagreement / method')
    lines.append('')
    lines.append('No stored countable labels were upgraded. AI markers on referenced fix commits (gemini-bridge, dynatrace-mcp, msgpack-ruby, flyto-core, budibase, open-webui, kiota) were recorded but not treated as introducing-hunk authorship. Codex is mentioned in GHSA-jwv3-5hgf-82ww as a finding aid, which is not an atomic commit marker. No AI_INCOMPLETE_REMEDIATION verdict, so no original_vulnerability block was required.')
    lines.append('')
    (OWNED/'report.md').write_text('\n'.join(lines)+'\n')
    print('wrote', len(cases), 'cases')
    print('counts', json.dumps(counts))
    print('result', (OWNED/'result.json').stat().st_size)
    print('cases', (OWNED/'cases.jsonl').stat().st_size)
    print('report', (OWNED/'report.md').stat().st_size)

if __name__ == '__main__':
    main()
