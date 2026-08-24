#!/usr/bin/env python3
import hashlib, json, os, subprocess
from collections import Counter
from pathlib import Path

ROOT = Path('/home/hanqing/agents/ai-slop')
OUT = ROOT / 'autoresearch/herdr-260814-dr1-grok46-high'
SLICE = ROOT / 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-1.jsonl'
SPEC = ROOT / 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md'
CONTRACT = ROOT / 'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md'
TRUTH = ROOT / 'docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md'
ADV_ROOT = Path('/home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database')
POOL = Path('/home/hanqing/.cache/ghsa200-sweep-fetch')
OUT.mkdir(parents=True, exist_ok=True)

def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or ''), (p.stderr or '')
    except Exception as e:
        return 99, '', str(e)

def find_adv(case_id):
    low = case_id.lower()
    hits = list((ADV_ROOT / 'advisories' / 'github-reviewed').rglob(low + '.json'))
    if hits:
        return str(hits[0])
    return None

def adv_summary(path):
    if not path:
        return {}
    try:
        d = json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return {'path': path}
    desc = d.get('description') or ''
    sum_ = d.get('summary') or ''
    aliases = []
    for a in d.get('aliases') or []:
        aliases.append(a)
    sev = None
    try:
        sev = (((d.get('database_specific') or {}).get('severity')))
    except Exception:
        sev = None
    refs = []
    for r in d.get('references') or []:
        u = r.get('url') if isinstance(r, dict) else str(r)
        if u:
            refs.append(u)
    pkgs = []
    for aff in d.get('affected') or []:
        pkg = (aff.get('package') or {}).get('name')
        if pkg:
            pkgs.append(pkg)
    withdrawn = d.get('withdrawn')
    return {
        'path': path,
        'summary': sum_[:400],
        'description_head': desc.replace('\n', ' ')[:500],
        'aliases': aliases,
        'severity': sev,
        'packages': pkgs,
        'withdrawn': withdrawn,
        'n_refs': len(refs),
        'commit_refs': [u for u in refs if '/commit/' in u][:8],
    }

def pool_dir(repo):
    return POOL / (repo.replace('/', '__'))

def git_show(repo, sha):
    gd = pool_dir(repo)
    env = os.environ.copy()
    env['GIT_NO_LAZY_FETCH'] = '1'
    cmd = ['git', '--git-dir', str(gd), 'log', '-1', '--format=%H%n%s%n%an <%ae>%n%b', sha]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=6, env=env)
        out = p.stdout or ''
        err = p.stderr or ''
        return out[:2500], err[:400], p.returncode
    except Exception as e:
        return '', str(e), 99

rows_in = [json.loads(l) for l in SLICE.read_text(encoding='utf-8').splitlines() if l.strip()]

# Direct-root decisions. FALSE_POSITIVE only when overlap is proven unrelated
# (tests/docs/release/CI-only, or the AI commit is the closer/fix rather than
# the introducing hunk). Overlap on plausible mechanism files with unavailable
# blobs stays UNKNOWN. Never convert missing hunk evidence into FAIL.
DECISIONS = {
    'GHSA-C2J3-45GR-MQC4': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor Sync/3.4.2 is a version-sync merge. Overlap includes dist/purify.cjs.js (the sanitizer bundle) plus CI workflows. Blobless fetch could not materialize the ancestor diff, so the vulnerable hunk comparison is unclosed. Dist overlap is not proven unrelated.',
    },
    'GHSA-JFWG-RXF3-P7R9': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor is the large v2 rewrite. Overlap is cassandradb CQL/N1QL modules, which match the later parameterized-query closer. Without the ancestor diff, it is unproven whether that rewrite introduced the unparameterized queries.',
    },
    'GHSA-9Q5R-WFVF-RR7F': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor refactors JSON serializer/MemorySize and overlaps core Earley/grammar files also touched by the closer. Hunk comparison could not be closed on the blobless object.',
    },
    'GHSA-FC6G-2GCP-2QRQ': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Copilot-marked ancestor is a GetMetrics panic fix, but overlap includes admin policy handlers and storage/access.rs, which are plausible SourceIp-policy files. Diff blobs were unavailable, so this is not closed as wrong_edge.',
    },
    'GHSA-2QVQ-RJWJ-GVW9': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Ancestor is a CLI unit-test chore. Overlap is only spec/expected compiled-fixture outputs, not the Handlebars runtime sanitizer/prototype-pollution hunks named by the later security closer.',
    },
    'GHSA-2W6W-674Q-4C4Q': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Same Handlebars test-fixture ancestor as the other CLI-option edges. Overlap does not include the runtime vulnerable hunk.',
    },
    'GHSA-3MFM-83XF-C92R': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Same Handlebars test-fixture ancestor. Overlap is spec/expected outputs only.',
    },
    'GHSA-442J-39WM-28R2': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Same Handlebars test-fixture ancestor. Overlap is spec/expected outputs only.',
    },
    'GHSA-9CX6-37PM-9JFF': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Same Handlebars test-fixture ancestor. Overlap is spec/expected outputs only.',
    },
    'GHSA-XHPV-HC6G-R9C6': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Same Handlebars test-fixture ancestor. Overlap is spec/expected outputs only.',
    },
    'GHSA-XJPJ-3MR7-GCPF': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Same Handlebars test-fixture ancestor. Overlap is spec/expected outputs only.',
    },
    'GHSA-4GGG-H7PH-26QR': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor is an AI security/CodeQL patch overlapping src/http-server-single-session.ts plus dist. That is a plausible HTTP-session sink; hunk comparison did not close.',
    },
    'GHSA-C29Q-5XM7-5P62': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor adds Apple/Amazon/Qobuz embed services and overlaps AbstractEmbedService.php / EmbedServiceFactory.php. That may be a new embed surface, but the advisory mechanism vs added hunks was not closed from local blobs.',
    },
    'GHSA-X44P-GVRJ-PJ2R': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor implements reEncryptInstructionFile and overlaps S3EncryptionClient, keyrings, and GetEncryptedObjectPipeline. Plausible crypto-metadata surface; hunk comparison unclosed.',
    },
    'GHSA-XW7X-H9FJ-P2C7': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Ancestor is a 2.26.0 release-prep commit. Overlap is CHANGELOG, README, apidiff text, examples, and version.gradle.kts, not an instrumentation sink.',
    },
    'GHSA-J6V5-G24H-VG4J': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor adds bytecode serialization and overlaps engine.go/options.go plus bytecode tests. Plausible runtime surface; hunk comparison unclosed.',
    },
    'GHSA-X3F4-V83F-7WP2': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Same v2 rewrite ancestor as the Cassandra row, but overlap here is GraphQL/OAuth/url validators. Different mechanism files; introducing hunk not proven from available blobs.',
    },
    'GHSA-PR33-38XX-6R26': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'ai_ancestor equals the named closer (Better cookie storage). Direct-root requires authorship of the pre-fix vulnerable hunk, not the closing patch.',
    },
    'GHSA-Q58J-G3F4-H26H': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Ancestor is itself a pull_request_target workflow-injection fix and overlap is only .github/workflows YAML. That is a closer/CI edge, not an introducing application hunk.',
    },
    'GHSA-Q938-GHWV-8GVC': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor adds Stripe payment support and overlaps src/Functions.php plus Stripe tests. Functions.php is a plausible sink; hunk comparison unclosed.',
    },
    'GHSA-G754-HX8W-X2G6': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor updates qpack and overlaps http3 conn/headers/server/stream. Those are plausible HTTP/3 header-parsing files; not proven unrelated.',
    },
    'GHSA-56F2-HVWG-5743': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Ancestor is an explicit Slack media URL-validation security fix. Direct-root does not count AI-authored closers; a later SHA is the assigned fix_ref.',
    },
    'GHSA-WFP2-V9C7-FH79': {
        'final_verdict': 'FALSE_POSITIVE',
        'fp_class': 'wrong_edge',
        'reason': 'Same OpenClaw Slack-media security-fix ancestor as GHSA-56F2. Direct-root still requires the introducing hunk, which this closer-style ancestor is not.',
    },
    'GHSA-H395-GR6Q-CPJC': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Ancestor decouples crypto backends and overlaps src/validation.rs (the JWT validation sink) plus errors.rs. Hunk comparison unclosed.',
    },
    'GHSA-2CF7-HPWF-47H9': {
        'final_verdict': 'UNKNOWN',
        'fp_class': None,
        'reason': 'Subject is a docs note, but overlap includes src/mcp/handlers-n8n-manager.ts and dist handler maps. Docs-only wrong_edge is therefore not proven.',
    },
}

cases = []
result_rows = []
report_lines = []

def gates_for(verdict, identity, uniqueness='PASS'):
    if verdict == 'FALSE_POSITIVE':
        return {
            'identity_gate': identity,
            'ai_hunk_gate': 'FAIL',
            'topology_gate': 'PASS',
            'but_for_gate': 'FAIL',
            'fix_reversal_gate': 'PASS',
            'release_gate': 'UNKNOWN',
            'uniqueness_gate': uniqueness,
        }
    return {
        'identity_gate': identity,
        'ai_hunk_gate': 'UNKNOWN',
        'topology_gate': 'PASS',
        'but_for_gate': 'UNKNOWN',
        'fix_reversal_gate': 'UNKNOWN',
        'release_gate': 'UNKNOWN',
        'uniqueness_gate': uniqueness,
    }

for rec in rows_in:
    cid = rec['case_id']
    dec = DECISIONS[cid]
    adv_path = find_adv(cid)
    adv = adv_summary(adv_path)
    msg, gerr, grc = git_show(rec['repository'], rec['ai_ancestor'])
    marker = None
    for line in (msg or '').splitlines():
        low = line.lower()
        if 'co-authored-by:' in low and any(k in low for k in ['copilot', 'claude', 'cursor', 'chatgpt', 'openai', 'anthropic', 'gemini', 'codex']):
            marker = line.strip()
            break
        if 'generated by' in low or 'assisted by' in low:
            marker = line.strip()
    identity = 'PASS' if adv_path and not adv.get('withdrawn') else ('FAIL' if adv.get('withdrawn') else 'UNKNOWN')
    verdict = dec['final_verdict']
    g = gates_for(verdict, identity)
    if identity == 'UNKNOWN':
        # keep identity unknown; do not fail other closed FP gates
        pass
    countable = False
    contrib = 'FALSE_POSITIVE_WRONG_EDGE' if verdict == 'FALSE_POSITIVE' else 'UNCLOSED_HUNK_COMPARISON'
    case = {
        'schema_version': 1,
        'lane': 'direct-root-slice-1',
        'case_id': cid,
        'aliases': adv.get('aliases') or [],
        'repository': rec['repository'],
        'published': rec.get('published'),
        'fix_ref': rec['fix_ref'],
        'ai_ancestor': rec['ai_ancestor'],
        'subject': rec.get('subject'),
        'overlap_files': rec.get('overlap_files') or [],
        'overlap_n': rec.get('overlap_n'),
        'final_verdict': verdict,
        'fp_class': dec.get('fp_class'),
        'contribution_class': contrib,
        'countable_proposal': countable,
        'terminal': True,
        'gates': g,
        'exact_ai_marker': marker,
        'ancestor_subject_evidence': (msg.splitlines()[:12] if msg else []),
        'git_error_head': (gerr or '')[:240],
        'advisory': adv,
        'commit_pool': str(pool_dir(rec['repository'])),
        'reason': dec['reason'],
        'worker_pass_is_proposal_only': True,
        'publication_status': 'HOLD',
        'causal_admission': False,
        'replay_commands': [
            'python3 -c "import json,pathlib; p=pathlib.Path(%r); print(p if p.exists() else 'missing')"' % (adv_path or ''),
            'GIT_NO_LAZY_FETCH=1 git --git-dir %s log -1 --format=%%s %s' % (pool_dir(rec['repository']), rec['ai_ancestor']),
        ],
        'counterevidence': [
            'Slice overlap is file-level only; blobless deepen did not always yield parent blobs.',
            'Direct-root does not count AI-authored closers.',
        ],
        'baseline_overlap_disposition': 'NO_IDENTITY_IN_CANONICAL84_CHECKED_HERE',
    }
    cases.append(case)
    result_rows.append({
        'case_id': cid,
        'repository': rec['repository'],
        'fix_ref': rec['fix_ref'],
        'ai_ancestor': rec['ai_ancestor'],
        'final_verdict': verdict,
        'fp_class': dec.get('fp_class'),
        'contribution_class': contrib,
        'countable_proposal': False,
        'terminal': True,
        'gates': g,
        'overlap_n': rec.get('overlap_n'),
        'exact_ai_marker': marker,
        'advisory_path': adv_path,
        'withdrawn': adv.get('withdrawn'),
    })

vc = Counter(r['final_verdict'] for r in result_rows)
gate_counts = {}
for name in ['identity_gate','ai_hunk_gate','topology_gate','but_for_gate','fix_reversal_gate','release_gate','uniqueness_gate']:
    gate_counts[name] = dict(Counter(r['gates'][name] for r in result_rows))

result = {
    'schema_version': 1,
    'lane': 'direct-root-slice-1',
    'owned_directory': 'autoresearch/herdr-260814-dr1-grok46-high',
    'terminal': True,
    'status': 'TERMINAL',
    'language': 'en',
    'english_only': True,
    'worker_pass_is_proposal_only': True,
    'canonical_layer': 'canonical84',
    'publication_status': 'HOLD',
    'causal_admission': False,
    'more_than_200_claim': False,
    'did_not_commit_or_push': True,
    'did_not_edit_tracked_or_canonical': True,
    'github_api_used': False,
    'input': {
        'spec': 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md',
        'spec_sha256': sha256(SPEC),
        'slice': 'autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-1.jsonl',
        'slice_sha256': sha256(SLICE),
        'contract': 'autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md',
        'contract_sha256': sha256(CONTRACT),
        'truth_layers': 'docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md',
        'truth_layers_sha256': sha256(TRUTH),
    },
    'counts': {
        'input_rows': len(rows_in),
        'adjudicated_rows': len(result_rows),
        'terminal_rows': len(result_rows),
        'countable_proposals': 0,
        'AI_DIRECT_ROOT': 0,
        'AI_NEW_SURFACE_CONTRIBUTOR': 0,
        'FALSE_POSITIVE': vc.get('FALSE_POSITIVE', 0),
        'UNKNOWN': vc.get('UNKNOWN', 0),
        'wrong_edge': sum(1 for r in result_rows if r.get('fp_class') == 'wrong_edge'),
    },
    'gate_counts': gate_counts,
    'rows': result_rows,
    'blockers': [
        'Blobless pool often failed to fetch parent blobs under GIT_NO_LAZY_FETCH=1; unclosed hunk comparisons remain UNKNOWN rather than FAIL.',
    ],
    'claim_boundary': 'Zero countable direct-root proposals. Twelve rows are wrong_edge false positives. Thirteen rows keep UNKNOWN on ai_hunk/but_for/release because the ancestor overlap is on plausible mechanism files and the introducing hunk was not replayable. Greater-than-200 remains unsupported. Worker PASS is proposal-only and this packet emits none.',
}

(OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
with (OUT / 'cases.jsonl').open('w', encoding='utf-8') as f:
    for c in cases:
        f.write(json.dumps(c, ensure_ascii=True) + '\n')

L = []
A = L.append
A('# Direct-root slice 1 adjudication')
A('')
A('## Verdict first')
A('')
A('All 25 assigned rows are terminal and non-countable. Zero rows are proposed as AI_DIRECT_ROOT or AI_NEW_SURFACE_CONTRIBUTOR. Twelve rows are FALSE_POSITIVE with class wrong_edge. Thirteen rows are UNKNOWN because the AI ancestor overlaps plausible mechanism files and the blobless pool did not yield a closed hunk comparison; missing evidence is not converted into FAIL.')
A('')
A('Handlebars contributes seven identical test-fixture edges off 80c4516 (CLI unit tests / spec/expected). OpenTelemetry release prep, http4k (ancestor equals closer), CoreShop workflow-only security closer, and two OpenClaw Slack-media security-fix ancestors are also wrong_edge. Remaining rows keep UNKNOWN.')
A('')
A('## Counts')
A('')
A('- input/adjudicated/terminal: 25 / 25 / 25')
A('- countable proposals: 0')
A('- FALSE_POSITIVE wrong_edge: %d' % vc.get('FALSE_POSITIVE', 0))
A('- UNKNOWN unclosed hunk: %d' % vc.get('UNKNOWN', 0))
A('- AI_DIRECT_ROOT / AI_NEW_SURFACE_CONTRIBUTOR: 0 / 0')
A('')
A('## Gate policy')
A('')
A('FALSE_POSITIVE rows fail ai_hunk_gate and but_for_gate on positive evidence that the ancestor is tests, docs/release metadata, CI-only, or the closer itself. identity_gate is PASS when a first-party GHSA JSON was found and not withdrawn, else UNKNOWN. release_gate stays UNKNOWN because released-artifact replay was not required to reject a wrong edge. UNKNOWN rows leave ai_hunk, but_for, fix_reversal, and release UNKNOWN.')
A('')
A('## Per-row')
A('')
A('| case_id | verdict | class | I/A/T/B/F/R/U | overlap_n | note |')
A('| --- | --- | --- | --- | --- | --- |')
for c in cases:
    g = c['gates']
    seq = '/'.join(g[k][0] for k in ['identity_gate','ai_hunk_gate','topology_gate','but_for_gate','fix_reversal_gate','release_gate','uniqueness_gate'])
    A('| %s | %s | %s | %s | %s | %s |' % (c['case_id'], c['final_verdict'], c['fp_class'] or c['contribution_class'], seq, c['overlap_n'], c['reason'][:140]))
A('')
A('## Per-row reasoning')
A('')
for c in cases:
    A('### %s (%s)' % (c['case_id'], c['repository']))
    A('')
    A('- fix_ref: %s' % c['fix_ref'])
    A('- ai_ancestor: %s' % c['ai_ancestor'])
    A('- subject: %s' % c['subject'])
    A('- overlap_n / head: %s / %s' % (c['overlap_n'], ', '.join((c['overlap_files'] or [])[:6])))
    A('- advisory: %s' % ((c['advisory'] or {}).get('path') or 'not found in freshness-qa clone'))
    if (c['advisory'] or {}).get('summary'):
        A('- advisory summary: %s' % c['advisory']['summary'])
    A('- marker: %s' % (c['exact_ai_marker'] or 'none extracted from commit message'))
    A('- verdict: %s (%s)' % (c['final_verdict'], c['fp_class'] or 'unclosed'))
    A('- gates: %s' % json.dumps(c['gates']))
    A('- reason: %s' % c['reason'])
    A('- pool: %s' % c['commit_pool'])
    if c.get('git_error_head'):
        A('- git: %s' % c['git_error_head'].replace('\n', ' '))
    A('')
A('## Evidence paths')
A('')
A('- Spec: autoresearch/orchestrator-260814-ghsa200-canvas/sweep/DR-SPEC.md')
A('- Slice: autoresearch/orchestrator-260814-ghsa200-canvas/sweep/dr-slice-1.jsonl')
A('- Contract: autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md')
A('- Truth layers: docs/RESEARCH-TRUTH-LAYERS-2026-08-14.md')
A('- Advisory clone: /home/hanqing/.cache/ghsa200-worker-clones/freshness-qa/advisory-database')
A('- Commit pool: /home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>')
A('')
A('## Constraints kept')
A('')
A('Owned directory only. No GitHub API, no commits, no ledger/web/scripts edits. English only. Unclosed gates remain UNKNOWN. Worker PASS is a proposal; this packet emits none.')
A('')
(OUT / 'report.md').write_text('\n'.join(L) + '\n', encoding='utf-8')
print('wrote', len(cases), 'verdicts', dict(vc))
print('result', (OUT/'result.json').stat().st_size)
print('cases', (OUT/'cases.jsonl').stat().st_size)
print('report', (OUT/'report.md').stat().st_size)
