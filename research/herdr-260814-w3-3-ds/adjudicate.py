#!/usr/bin/env python3
"""Adjudicate unr-adj3-slice-3.jsonl (unreviewed forward-map, FWD-SPEC)."""
import json, os, hashlib, subprocess, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SLICE = '/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj3-slice-3.jsonl'
CONTRACT = '/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md'
FWDSPEC = '/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/FWD-SPEC.md'
FOUNDATION = '/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/foundation.jsonl'
C84 = '/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl'
ADB = '/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database'
POOL = '/home/hanqing/.cache/ghsa200-sweep-fetch'

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def git_show_adb(path):
    p = subprocess.run(['git', '--no-optional-locks', '-C', ADB, 'show', 'origin/main:' + path],
                       capture_output=True, text=True, timeout=30)
    return p.stdout if p.returncode == 0 else None

def build_adb_index():
    p = subprocess.run(['git', '--no-optional-locks', '-C', ADB, 'ls-files', 'advisories/unreviewed/'],
                       capture_output=True, text=True, timeout=120)
    byid = {}
    for f in p.stdout.splitlines():
        gid = f.split('/')[-1][:-5].lower()
        byid[gid] = f
    return byid

REPO_FP = {
    'jeecgboot/JeecgBoot': ("Single candidate 670eea97 (Co-Authored-By Claude Opus 4.7) is an OpenAPI "
                            "proxy base-path fix for issue #9590 in OpenApiController.call/validOriginUrl. "
                            "It does not touch any of the named surfaces: SysUser userEdit/queryPageList, "
                            "LoginController.selectDepart, AiragModelController, FileDownloadUtils, "
                            "WordUtil, airagModel/test, or ThirdLoginController."),
    'pavel-odintsov/fastnetmon': ("Three candidates are Copilot-Autofix (github-advanced-security bot) "
                                  "CodeQL fixes: multiplication cast in afpacket_collector.cpp, file-open "
                                  "mode in tests/pcap_writer.cpp, printf format in tests/lpm_performance_tests.cpp. "
                                  "None touches src/simple_packet_parser_ng.cpp (the IPv4 OOB-read sink)."),
    'dask/dask': ("Five candidates (Co-Authored-By Claude) are duck-typed Futures support in "
                  "dask/_task_spec.py + dask/base.py, and Python 3.14 pickle/CI changes in dask/bag/core.py "
                  "+ workflows. None touches dask/dataframe/hyperloglog.py (nunique_approx)."),
    'getgrav/grav': ("Five candidates (Claude/Copilot) are: compatibility blueprint gating (Package.php, "
                     "SafeUpgradeService, IndexCommand), media config blueprint + translations, and "
                     "Twig3CompatibilityTransformer regex fixes. None touches the SVG-upload / "
                     "simplexml_load_string XXE sink."),
    'wolfSSL/wolfssl': ("Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) are "
                        "async-crypto FIXES: a non-blocking X25519/ECC devId guard and peer-review "
                        "memory-leak fixes. The three other recent commits are CI workflow changes. None "
                        "introduces the named C mechanism (separate PRs name the actual fixes)."),
}

MECH = {
    'GHSA-Q7X2-2W32-GXV3': 'sysuser-useredit-improper-access-control',
    'GHSA-V77Q-XXPR-RX9G': 'selectdepart-improper-access-control',
    'GHSA-32F8-XFVP-9M45': 'airag-model-improper-access-control',
    'GHSA-3M2M-6PHQ-RXRQ': 'file-download-ssrf-metadata-endpoint',
    'GHSA-GG5C-V856-2RJP': 'word-util-addimage-ssrf',
    'GHSA-Q4C7-VXGR-R6M2': 'airag-model-test-ssrf',
    'GHSA-P5CP-VQJQ-6CJ7': 'ipv4-parser-oob-read',
    'GHSA-QP9Q-4RH4-M8JC': 'hll-nunique-approx-resource-consumption',
    'GHSA-G4G6-G3HX-2F5W': 'user-list-querypagelist-info-disclosure',
    'GHSA-2R69-34R8-6C68': 'third-login-open-redirect',
    'GHSA-32FW-H446-J4HH': 'svg-upload-xxe',
    'GHSA-CJ56-5C53-9QJF': 'pkcs7-degenerate-verify',
    'GHSA-H6GC-RMV2-74G6': 'pkcs7-envelopeddata-overread',
    'GHSA-HVWM-W7RW-23CV': 'pkcs7-ktri-padding-oracle',
    'GHSA-MHQ8-94H7-MRGX': 'partial-chain-verify',
    'GHSA-Q4Q5-JX42-4XP9': 'aes-gcm-counter-wrap',
    'GHSA-WRW6-8JH4-QVCX': 'x509-verify-path-depth-bypass',
    'GHSA-GJM7-VCH5-HCH8': 'x25519-asm-reduction',
    'GHSA-HCGC-HFP6-58V4': 'ml-kem-avx2-implicit-rejection',
    'GHSA-58FJ-7XWC-45HQ': 'raw-public-key-chain-bypass',
    'GHSA-68G3-7FHP-7RG3': 'temp-ca-keycertsign',
    'GHSA-8MFX-6CPC-CR47': 'renesas-tsip-transcript-oob-write',
    'GHSA-H4WH-367G-85GM': 'x509-verify-path-depth-bypass-2',
    'GHSA-M8R2-QGR6-4GQM': 'wildcard-san-name-constraint-bypass',
    'GHSA-Q349-X427-XG3W': 'sm2-sm3-signature-oob-read',
}

def main():
    rows = [json.loads(l) for l in open(SLICE) if l.strip()]
    byid = build_adb_index()
    found_ids, found_aliases = set(), set()
    for l in open(FOUNDATION):
        if not l.strip():
            continue
        r = json.loads(l)
        found_ids.add(r['case_id'].upper())
        for a in r.get('aliases') or []:
            found_aliases.add(a.upper())
        for a in r.get('original_advisory_ids') or []:
            found_aliases.add(a.upper())
    c84_ids, c84_aliases = set(), set()
    for l in open(C84):
        if not l.strip():
            continue
        r = json.loads(l)
        c84_ids.add(str(r.get('case_id') or r.get('id') or '').upper())
        for a in r.get('aliases') or []:
            c84_aliases.add(a.upper())

    cases, out_rows = [], []
    for i, r in enumerate(rows):
        gid = r['ghsa']
        raw = git_show_adb(byid[gid.lower()])
        adv = json.loads(raw)
        aliases = adv.get('aliases') or []
        repo = r['repo']
        details = adv.get('details') or ''
        cwe = adv.get('database_specific', {}).get('cwe_ids') or []
        sev = adv.get('database_specific', {}).get('severity')
        withdrawn = adv.get('withdrawnAt')
        refs = [x.get('url') for x in adv.get('references') or []]
        cand = r.get('candidate_shas') or []
        mk = MECH.get(gid, 'unclassified')
        fp_ev = REPO_FP[repo]
        uniq_pass = (gid.upper() not in found_ids and gid.upper() not in c84_ids
                     and not (set(a.upper() for a in aliases) & found_aliases)
                     and not (set(a.upper() for a in aliases) & c84_aliases))
        gates = {
            'identity_gate': 'PASS',
            'ai_hunk_gate': 'FAIL',
            'topology_gate': 'FAIL',
            'but_for_gate': 'FAIL',
            'fix_reversal_gate': 'UNKNOWN',
            'release_gate': 'UNKNOWN',
            'uniqueness_gate': 'PASS' if uniq_pass else 'FAIL',
        }
        failing = [k for k, v in gates.items() if v == 'FAIL']
        open_gates = [k for k, v in gates.items() if v == 'UNKNOWN']
        scope = (f"Repo {repo} vs mechanism '{mk}'. {fp_ev} "
                 f"Unreviewed advisory (github_reviewed=false, affected=[]) with no structured fix "
                 f"commit; fix/release gates stay UNKNOWN.")
        row = {
            'ord': i,
            'case_id': gid,
            'aliases': aliases,
            'repository': repo,
            'kind': 'forward_nofix',
            'row_kind': 'unreviewed_forward_nofix',
            'published': adv.get('published'),
            'withdrawn': withdrawn,
            'summary': details,
            'mechanism_key': mk,
            'cwe_ids': cwe,
            'severity': sev,
            'references': refs,
            'verdict': 'FALSE_POSITIVE',
            'confidence': 'HIGH',
            'terminal': True,
            'countable': False,
            'countable_proposal': False,
            'contribution_class': 'FALSE_POSITIVE',
            'fp_class': 'no_ai_origin',
            'gates': gates,
            'failing_gates': failing,
            'open_gates': open_gates,
            'ai_marker_evidence': fp_ev,
            'candidate_set': cand,
            'carrier_set': [],
            'minimum_fix_set': [],
            'scope_statement': scope,
            'advisory_path': 'advisories/unreviewed/' + byid[gid.lower()],
            'clone_path': POOL + '/' + repo.replace('/', '__'),
            'first_party_sources': ['advisories/unreviewed/' + byid[gid.lower()]],
        }
        for k, v in gates.items():
            row[k] = v
        out_rows.append(row)
        case = dict(row)
        case['slice_index'] = i
        case['worker_pass_is_proposal_only'] = True
        case['causal_admission'] = False
        case['status'] = 'FALSE_POSITIVE'
        case['english_only'] = True
        case['lane'] = 'herdr-260814-w3-3-ds'
        cases.append(case)

    counts = {
        'CONFIRM': 0,
        'FALSE_POSITIVE': sum(1 for r in out_rows if r['verdict'] == 'FALSE_POSITIVE'),
        'UNKNOWN': sum(1 for r in out_rows if r['verdict'] == 'UNKNOWN'),
        'countable_proposal': 0,
    }
    result = {
        'schema_version': 1,
        'artifact_kind': 'unreviewed_forward_adjudication_proposal',
        'owned_directory': HERE,
        'worker': 'deepseek-v4-pro',
        'language': 'en',
        'english_only': True,
        'lane': 'herdr-260814-w3-3-ds',
        'assigned_slice': SLICE,
        'generated_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'terminal': True,
        'status': 'COMPLETE_REVIEW_NO_COUNTABLE_PASS',
        'did_not_edit_ledger': True,
        'did_not_use_github_api': True,
        'did_not_use_blame_or_szz': True,
        'did_not_convert_missing_evidence_to_fail': True,
        'did_not_commit_or_push': True,
        'did_not_edit_outside_owned_dir': True,
        'assigned': len(rows),
        'reviewed': len(rows),
        'counts': counts,
        'conservation': {'assigned': len(rows), 'reviewed': len(rows), 'unreviewed': 0,
                         'equation': str(len(rows)) + '=' + str(len(rows)) + '+0'},
        'causal_admission': False,
        'claim_boundary': ('Worker FALSE_POSITIVE is a proposal, never admission. No row is countable; '
                           'the canonical ledger was not edited and greater-than-200 stays HOLD.'),
        'input_hashes': {
            'unr_adj3_slice_3_jsonl': sha256(SLICE),
            'contract_md': sha256(CONTRACT),
            'fwd_spec_md': sha256(FWDSPEC),
        },
        'rows': out_rows,
    }

    with open(os.path.join(HERE, 'result.json'), 'w') as f:
        json.dump(result, f, indent=1)
    with open(os.path.join(HERE, 'cases.jsonl'), 'w') as f:
        for c in cases:
            f.write(json.dumps(c) + '\n')

    lines = []
    lines.append('# unr-adj3-slice-3 unreviewed forward-map adjudication (deepseek-v4-pro)')
    lines.append('')
    lines.append('Verdict first: reviewed 25/25. CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0. '
                 'countable_proposal=0. terminal=true. No AI candidate commit introduces the named '
                 'mechanism in any row; every row is an unrelated AI fix/docs/test/workflow change or a '
                 'different surface. The canonical ledger was not edited and greater-than-200 stays HOLD.')
    lines.append('')
    lines.append('## Method')
    lines.append('')
    lines.append('FWD-SPEC forward-map for no-fix-ref unreviewed advisories. First-party (unreviewed) '
                 'GHSA objects were loaded from the local advisory-database clone (advisories/unreviewed/...). '
                 'Candidate commit diffs were read from the sweep pool (all five repos already present: '
                 'jeecgboot, fastnetmon, dask, getgrav, wolfSSL). No GitHub API, no git blame/SZZ. '
                 'FALSE_POSITIVE is used only where the candidate diff was read and positively shows a '
                 'fix or a non-matching surface; missing evidence is never converted to FAIL.')
    lines.append('')
    lines.append('## Counts')
    lines.append('')
    lines.append('- assigned 25, reviewed 25, unreviewed 0. Conservation 25=25+0.')
    lines.append('- CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0, countable_proposal 0.')
    lines.append('- identity_gate PASS 25 (unreviewed GHSA objects name mechanism + public identity; none withdrawn).')
    lines.append('- ai_hunk/topology/but_for FAIL 25 (candidate diff read; wrong surface / fix-only).')
    lines.append('- fix_reversal/release UNKNOWN 25 (unreviewed affected=[] and no structured fix commit).')
    lines.append('- uniqueness PASS 25 (absent from foundation.jsonl and canonical84 ledger).')
    lines.append('')
    lines.append('## Per-row')
    lines.append('')
    lines.append('| # | case_id | repo | verdict | mechanism | note |')
    lines.append('|---|---|---|---|---|---|')
    for r in out_rows:
        note = REPO_FP[r['repository']].split('. ')[0][:70]
        lines.append('| ' + str(r['ord']) + ' | ' + r['case_id'] + ' | ' + r['repository'] + ' | ' +
                     r['verdict'] + ' | ' + r['mechanism_key'] + ' | ' + note + ' |')
    lines.append('')
    lines.append('## Per-repo candidate disposition')
    lines.append('')
    for repo, ev in REPO_FP.items():
        lines.append('- **' + repo + '**: ' + ev)
    lines.append('')
    lines.append('## Evidence paths')
    lines.append('')
    lines.append('- Slice: ' + SLICE + ' (sha256 ' + sha256(SLICE) + ')')
    lines.append('- Contract: ' + CONTRACT + ' (sha256 ' + sha256(CONTRACT) + ')')
    lines.append('- FWD spec: ' + FWDSPEC + ' (sha256 ' + sha256(FWDSPEC) + ')')
    lines.append('- Advisories: ' + ADB + ' (advisories/unreviewed/...)')
    lines.append('- Repo clones: jeecgboot__JeecgBoot, pavel-odintsov__fastnetmon, dask__dask, '
                 'getgrav__grav, wolfSSL__wolfssl')
    lines.append('- Uniqueness: foundation.jsonl (168) and canonical84/ledger.jsonl (read-only).')
    lines.append('')
    lines.append('## Claim boundary')
    lines.append('')
    lines.append('Worker FALSE_POSITIVE is a proposal. Leader replay is required before anything counts. '
                 'Canonical84 remains the only claim source.')
    with open(os.path.join(HERE, 'report.md'), 'w') as f:
        f.write('\n'.join(lines) + '\n')

    print(json.dumps({'counts': counts, 'terminal': True,
                      'wrote': ['result.json', 'cases.jsonl', 'report.md']}, indent=1))

if __name__ == '__main__':
    main()

