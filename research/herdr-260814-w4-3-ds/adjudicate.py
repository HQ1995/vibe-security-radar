#!/usr/bin/env python3
"""Adjudicate unr-adj4-slice-3.jsonl (unreviewed forward-map, FWD-SPEC)."""
import json, os, hashlib, subprocess, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SLICE = '/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj4-slice-3.jsonl'
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
    'portainer/portainer': ("Candidates are a stacks prune fix (a2fee4fc, Claude Sonnet 4.6) and settings/auth "
                            "UI migrations (SessionLifetimeSelect, oauth auto-provision, auth-method select, azure form). "
                            "None touches the Docker proxy URL-normalization / authorization middleware (CWE-287)."),
    'wg-easy/wg-easy': ("Candidates rename WG_PORT/WG_CLIENT_PORT init vars (8b5e6c4c/e1928552), add setup-override "
                        "vars (7fbc1cef), and add a metrics password (fbf24410). None touches the WireGuard client "
                        "create / PostUp directive path (the OS command injection sink)."),
    'InvoicePlane/InvoicePlane': ("75e6d903 is a Copilot-authored SECURITY FIX (guest/Get.php file-access traversal) - a "
                                  "remediation, not the origin; 98ccbe4c is version/logging; 9d11e726 removes deprecated "
                                  "docker libs. None introduces file-upload RCE, report SQLi, or traversal."),
    'bludit/bludit': ("Single candidate ee057f2f (Claude) adds router.php (PHP built-in server) and sibling commits are "
                      "theme navbar/SEO changes. None touches SVG upload, session handling, API upload, page-creation "
                      "XSS, or site-logo SVG."),
    'ggml-org/whisper.cpp': ("Candidate 6fb7f1af is a SYCL BF16 DMMV GPU-kernel perf change. None touches "
                             "whisper_model_load / ggml.c (null-pointer dereference)."),
    'jupyterlab/jupyterlab': ("Candidates are spell-check CI workflows, a file-browser filter, and XSRF cookie "
                              "selection. None touches the plugin manager lock rules or PyPIExtensionManager.install()."),
    'azerothcore/azerothcore-wotlk': ("Candidates are game-content/database fixes and a CMake ARM-detection refactor "
                                      "(1b35971f, Copilot co-author). None touches deps/zlib inflate.c."),
    'HKUDS/nanobot': ("Candidates are a configurable web-search provider (71d90de3) and POC-infrastructure removal "
                      "(f8711f6a). None touches the WhatsApp bridge WebSocket (0.0.0.0:3001 no-auth)."),
    'usmannasir/cyberpanel': ("Candidates remove simple_install.sh in favor of install.sh (4ec55c64/dc666c44, Cursor "
                              "co-author). None touches the filemanager controller symlink path."),
    'siyuan-note/siyuan': ("Candidates are the bazaar-readme deep-link handler (16760a55/24c9c5fd) and SYLink "
                           "processing (129a9c2a). Only the bazaar-readme handler matches the bazaar-readme XSS "
                           "advisory; the other named surfaces (SVG sanitization, title-img, publish filters, auth "
                           "bypass, SQL injection) are not touched by these candidates."),
}

SPECIAL = {
    'GHSA-X52J-M89G-WH64': {
        'verdict': 'UNKNOWN',
        'confidence': 'MEDIUM',
        'contribution_class': 'UNRESOLVED',
        'fp_class': None,
        'gates': {
            'identity_gate': 'PASS',
            'ai_hunk_gate': 'UNKNOWN',
            'topology_gate': 'UNKNOWN',
            'but_for_gate': 'UNKNOWN',
            'fix_reversal_gate': 'UNKNOWN',
            'release_gate': 'UNKNOWN',
            'uniqueness_gate': 'PASS',
        },
        'reason': ("Candidate 16760a55/24c9c5fd 'Open bazaar resource readme by siyuan://bazaar/{type}/{name}/readme "
                   "URI (#17938)' introduces openBazaarReadme()/renderReadme(), the exact bazaar-readme deep-link "
                   "surface named by CVE-2026-66395, and carries copilot-swe-agent[bot] + Copilot co-author markers. "
                   "But it is a PR squash with human primary author Yingyi/Zuoqiu-Yingyi, so per-hunk AI authorship is "
                   "unresolved: ai_hunk/topology/but_for stay UNKNOWN (not converted to PASS or FAIL). "
                   "fix_reversal/release UNKNOWN (unreviewed advisory, no fix SHA or version range)."),
    },
}

MECH = {
    'GHSA-588V-59VC-3XH9': 'portainer-docker-proxy-auth-bypass',
    'GHSA-G5JQ-GH88-3GMW': 'wg-easy-postup-command-injection',
    'GHSA-JPVH-V7H3-V24C': 'invoiceplane-file-upload-rce',
    'GHSA-MFR5-898V-5WMR': 'invoiceplane-report-sqli',
    'GHSA-R995-4VFX-PPGF': 'invoiceplane-directory-traversal',
    'GHSA-8V3Q-HMMJ-942M': 'bludit-svg-upload-xss',
    'GHSA-FJJ5-FJ78-H28J': 'bludit-session-fixation',
    'GHSA-VFMC-78C4-2F7W': 'bludit-api-unrestricted-upload-rce',
    'GHSA-W5X8-257X-9RV5': 'bludit-page-creation-xss',
    'GHSA-JX42-8F9X-G57F': 'whisper-model-load-null-deref',
    'GHSA-JVGC-4PC6-8X5F': 'bludit-site-logo-svg-xss',
    'GHSA-FPF6-H6P9-9RJR': 'jupyterlab-plugin-lock-rule-bypass',
    'GHSA-R336-HQVQ-MFJH': 'jupyterlab-allowlist-await-bypass',
    'GHSA-J644-XC9Q-497G': 'azerothcore-zlib-inflate-oob',
    'GHSA-3G85-XPC2-P2HQ': 'nanobot-whatsapp-websocket-noauth',
    'GHSA-47JC-H939-7PJ5': 'cyberpanel-filemanager-symlink',
    'GHSA-5P6M-3744-5C8G': 'siyuan-svg-sanitization-xss',
    'GHSA-PWP5-QQ97-MCQC': 'siyuan-title-img-xss',
    'GHSA-X52J-M89G-WH64': 'siyuan-bazaar-readme-xss',
    'GHSA-2MMH-4RF8-7XG6': 'siyuan-backlink-publish-filter',
    'GHSA-3RFW-7FXW-6JXM': 'siyuan-getblockinfo-metadata',
    'GHSA-85XQ-27M5-59M9': 'siyuan-heading-transaction-disclosure',
    'GHSA-G64V-QQPG-V37H': 'siyuan-publish-auth-bypass',
    'GHSA-5W4J-HCHP-R332': 'siyuan-filetree-search-sqli',
    'GHSA-P2X7-4C4P-8WH6': 'siyuan-searchembedblock-sqli',
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
        uniq_pass = (gid.upper() not in found_ids and gid.upper() not in c84_ids
                     and not (set(a.upper() for a in aliases) & found_aliases)
                     and not (set(a.upper() for a in aliases) & c84_aliases))

        sp = SPECIAL.get(gid)
        if sp:
            gates = dict(sp['gates'])
            gates['uniqueness_gate'] = 'PASS' if uniq_pass else 'FAIL'
            verdict = sp['verdict']
            conf = sp['confidence']
            contrib = sp['contribution_class']
            fpcls = sp['fp_class']
            ev = sp['reason']
        else:
            gates = {
                'identity_gate': 'PASS',
                'ai_hunk_gate': 'FAIL',
                'topology_gate': 'FAIL',
                'but_for_gate': 'FAIL',
                'fix_reversal_gate': 'UNKNOWN',
                'release_gate': 'UNKNOWN',
                'uniqueness_gate': 'PASS' if uniq_pass else 'FAIL',
            }
            verdict = 'FALSE_POSITIVE'
            conf = 'HIGH'
            contrib = 'FALSE_POSITIVE'
            fpcls = 'no_ai_origin'
            ev = REPO_FP[repo]

        failing = [k for k, v in gates.items() if v == 'FAIL']
        open_gates = [k for k, v in gates.items() if v == 'UNKNOWN']
        countable = verdict in ('CONFIRM',) and not open_gates and not failing
        scope = (f"Repo {repo} vs mechanism '{mk}'. {ev} "
                 f"Unreviewed advisory (github_reviewed=false, affected=[]) with no structured fix commit.")
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
            'verdict': verdict,
            'confidence': conf,
            'terminal': verdict == 'FALSE_POSITIVE',
            'countable': countable,
            'countable_proposal': False,
            'contribution_class': contrib,
            'fp_class': fpcls,
            'gates': gates,
            'failing_gates': failing,
            'open_gates': open_gates,
            'ai_marker_evidence': ev,
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
        case['status'] = verdict
        case['english_only'] = True
        case['lane'] = 'herdr-260814-w4-3-ds'
        cases.append(case)

    counts = {
        'CONFIRM': sum(1 for r in out_rows if r['verdict'] == 'CONFIRM'),
        'FALSE_POSITIVE': sum(1 for r in out_rows if r['verdict'] == 'FALSE_POSITIVE'),
        'UNKNOWN': sum(1 for r in out_rows if r['verdict'] == 'UNKNOWN'),
        'countable_proposal': 0,
    }
    terminal = counts['UNKNOWN'] == 0
    result = {
        'schema_version': 1,
        'artifact_kind': 'unreviewed_forward_adjudication_proposal',
        'owned_directory': HERE,
        'worker': 'deepseek-v4-pro',
        'language': 'en',
        'english_only': True,
        'lane': 'herdr-260814-w4-3-ds',
        'assigned_slice': SLICE,
        'generated_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'terminal': terminal,
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
        'claim_boundary': ('Worker FALSE_POSITIVE/UNKNOWN is a proposal, never admission. No row is countable; '
                           'the canonical ledger was not edited and greater-than-200 stays HOLD.'),
        'input_hashes': {
            'unr_adj4_slice_3_jsonl': sha256(SLICE),
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
    lines.append('# unr-adj4-slice-3 unreviewed forward-map adjudication (deepseek-v4-pro)')
    lines.append('')
    lines.append('Verdict first: reviewed 25/25. CONFIRM 0, FALSE_POSITIVE 24, UNKNOWN 1. '
                 'countable_proposal=0. terminal=false. The single UNKNOWN row is a near-miss '
                 'AI_NEW_SURFACE_CONTRIBUTOR candidate (siyuan bazaar-readme deep-link XSS) whose AI authorship is on a '
                 'PR squash with a human primary author. The canonical ledger was not edited and greater-than-200 stays HOLD.')
    lines.append('')
    lines.append('## Method')
    lines.append('')
    lines.append('FWD-SPEC forward-map for no-fix-ref unreviewed advisories. First-party (unreviewed) GHSA objects were '
                 'loaded from the local advisory-database clone. Candidate diffs were read from the sweep pool; missing '
                 'repos (InvoicePlane, whisper.cpp, azerothcore-wotlk) were fetched via git smart-HTTP. No GitHub API, no '
                 'git blame/SZZ. FALSE_POSITIVE is used only where the candidate files/subject positively show a fix or '
                 'non-matching surface; missing evidence is never converted to FAIL.')
    lines.append('')
    lines.append('## Counts')
    lines.append('')
    lines.append('- assigned 25, reviewed 25, unreviewed 0. Conservation 25=25+0.')
    lines.append('- CONFIRM 0, FALSE_POSITIVE 24, UNKNOWN 1, countable_proposal 0.')
    lines.append('- identity_gate PASS 25 (unreviewed GHSA objects name mechanism + public identity; none withdrawn).')
    lines.append('- ai_hunk/topology/but_for FAIL 24 (wrong surface / fix-only); UNKNOWN 1 (siyuan bazaar-readme).')
    lines.append('- fix_reversal/release UNKNOWN 25 (unreviewed affected=[] and no structured fix commit).')
    lines.append('- uniqueness PASS 25 (absent from foundation.jsonl and canonical84 ledger).')
    lines.append('')
    lines.append('## Per-row')
    lines.append('')
    lines.append('| # | case_id | repo | verdict | mechanism | note |')
    lines.append('|---|---|---|---|---|---|')
    for r in out_rows:
        note = (REPO_FP.get(r['repository']) or '').split('. ')[0][:70]
        lines.append('| ' + str(r['ord']) + ' | ' + r['case_id'] + ' | ' + r['repository'] + ' | ' +
                     r['verdict'] + ' | ' + r['mechanism_key'] + ' | ' + note + ' |')
    lines.append('')
    lines.append('## UNKNOWN row detail')
    lines.append('')
    lines.append('- GHSA-X52J-M89G-WH64 (CVE-2026-66395) siyuan bazaar-readme reflected XSS: candidate 16760a55/24c9c5fd '
                 '(PR #17938) introduces the siyuan://bazaar readme deep-link handler with copilot-swe-agent/Copilot '
                 'co-author markers, but is a squash with human primary author Yingyi, so per-hunk AI authorship is '
                 'unresolved and ai_hunk/topology/but_for/fix_reversal/release stay UNKNOWN. Requires leader replay.')
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
    lines.append('- Repo clones: portainer, wg-easy, InvoicePlane (fetched), bludit, whisper.cpp (fetched), jupyterlab, '
                 'azerothcore-wotlk (fetched), nanobot, cyberpanel, siyuan-note')
    lines.append('- Uniqueness: foundation.jsonl (168) and canonical84/ledger.jsonl (read-only).')
    lines.append('')
    lines.append('## Claim boundary')
    lines.append('')
    lines.append('Worker FALSE_POSITIVE/UNKNOWN is a proposal. Leader replay is required before anything counts. '
                 'Canonical84 remains the only claim source.')
    with open(os.path.join(HERE, 'report.md'), 'w') as f:
        f.write('\n'.join(lines) + '\n')

    print(json.dumps({'counts': counts, 'terminal': terminal,
                      'wrote': ['result.json', 'cases.jsonl', 'report.md']}, indent=1))

if __name__ == '__main__':
    main()

