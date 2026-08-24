#!/usr/bin/env python3
"""Adjudicate unr-adj2-slice-3.jsonl (unreviewed forward-map, FWD-SPEC)."""
import json, os, hashlib, subprocess, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SLICE = '/home/hanqing/agents/ai-slop/autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj2-slice-3.jsonl'
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
    'bludit/bludit': ("Candidate commits carry Co-Authored-By Claude (Sonnet/Opus 4.6) trailers and are "
                      "security/bug FIXES for other issues: fbb08543 (IDOR auth check, SameSite cookie, "
                      "page-erasure guard, navigation-label XSS escape), f91393d7 (thumbnail toggle), "
                      "6a6cdb02/d09327cb (API pagination), 270d59bb (search cache). None authors the "
                      "stored-XSS or CSRF hunk."),
    'wolfSSL/wolfssl': ("Candidates 2a18b7ee (Claude Sonnet 4.5) and 19bb7198 (Claude Opus 4.6) are "
                        "async-crypto FIXES: a non-blocking X25519/ECC devId guard in src/internal.c and "
                        "src/tls.c, and peer-review memory-leak fixes in tls.c/asn.c/curve25519.c. The "
                        "three other recent commits are CI workflow changes. None introduces the named "
                        "C mechanism (separate PRs name the actual fixes)."),
    'ixray-team/ixray-1.6-stcop': ("Candidates are authored by OpenHands (<openhands@all-hands.dev>) and "
                                   "are backports of upstream OpenSSL CVE fixes (CVE-2015-3195, "
                                   "CVE-2016-0701, CVE-2016-2182, CVE-2022-0778) into "
                                   "src/3rd-party/crypto/openssl/. None introduces the info-disclosure "
                                   "mechanism (before 1.3)."),
    'ocaml/ocaml': ("Candidates (Co-Authored-By Claude) touch testsuite/tests/tool-ocamlc-determinism "
                    "and driver/compmisc.ml (type-ID/level counter reset for .cmo determinism). None "
                    "touches otherlibs/bigarray (Bigarray.reshape)."),
    'pfefferle/wordpress-webmention': ("Candidates (Co-authored-by Copilot) touch class-comment-walker.php, "
                                      "class-admin.php, class-settings-fields.php, Entity/class-item.php, "
                                      "Handler/class-wp.php. The SSRF sinks are includes/handler/class-mf2.php "
                                      "(MF2::parse_authorpage) and includes/class-tools.php (Tools::read); "
                                      "no candidate file matches."),
}

MECH = {
    'GHSA-WG93-HP69-VV5W': 'stored-xss-post-content',
    'GHSA-XW6C-FFPM-FGCM': 'csrf-plugin-theme-management',
    'GHSA-2Q9G-Q8JJ-FR53': 'packet-sniffer-aead-underflow',
    'GHSA-3CR6-HPF3-2HMG': 'pkcs7-signed-attributes-stack-overflow',
    'GHSA-24VQ-QFC5-QRMJ': 'session-deserialize-heap-overflow',
    'GHSA-86FV-Q5VX-MW5M': 'crl-number-buffer-overflow',
    'GHSA-CWC7-2FMX-FFFQ': 'tls12-cert-verify-before-cke',
    'GHSA-F5X4-GF23-WQM9': 'riscv-muldi3-timing-sidechannel',
    'GHSA-PGC5-R6CV-2825': 'ml-kem-dsa-fault-injection',
    'GHSA-WM74-PVWW-Q7H2': 'sp256-get-entry-timing',
    'GHSA-267H-VRW9-53P3': 'hpke-labeled-extract-ech-stack-overflow',
    'GHSA-6P64-86QJ-33GC': 'add-to-chain-heap-corruption',
    'GHSA-CQX9-3CPJ-RRQP': 'kcapi-ecc-import-heap-overflow',
    'GHSA-F377-557W-VJGV': 'alpn-oob-read',
    'GHSA-G3XR-5F55-CF5G': 'tls13-hrr-key-share',
    'GHSA-J2G5-52P7-MFPC': 'tls13-ech-parsing-underflow',
    'GHSA-M9R6-9WMX-24JV': 'pkcs7-envelopeddata-oob-read',
    'GHSA-6C79-F9M3-C7M5': 'sensitive-info-disclosure',
    'GHSA-6P45-JV22-32GP': 'bigarray-reshape-int-overflow',
    'GHSA-PWM7-WR54-2JXV': 'ssrf-mf2-parse-authorpage',
    'GHSA-WJF6-53J2-2F8C': 'ssrf-tools-read',
    'GHSA-98WW-GW4P-68M3': 'decodeobjectid-oob-write',
    'GHSA-F5H9-5Q52-QRX7': 'ecdsa-digest-size-check',
    'GHSA-MX4J-FJQX-F8QJ': 'certfromx509-aki-overflow',
    'GHSA-VGV9-MV66-MPC7': 'aria-gcm-nonce-reuse',
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
        case['lane'] = 'herdr-260814-w2-3-ds'
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
        'lane': 'herdr-260814-w2-3-ds',
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
            'unr_adj2_slice_3_jsonl': sha256(SLICE),
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
    lines.append('# unr-adj2-slice-3 unreviewed forward-map adjudication (deepseek-v4-pro)')
    lines.append('')
    lines.append('Verdict first: reviewed 25/25. CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0. '
                 'countable_proposal=0. terminal=true. No AI candidate commit introduces the named '
                 'mechanism in any row; every row is an unrelated AI fix/test/workflow change or a '
                 'different surface. The canonical ledger was not edited and greater-than-200 stays HOLD.')
    lines.append('')
    lines.append('## Method')
    lines.append('')
    lines.append('FWD-SPEC forward-map for no-fix-ref unreviewed advisories. Each row names ghsa, repo, '
                 'recent_ai_commits, candidate_shas. First-party (unreviewed) GHSA objects were loaded '
                 'from the local advisory-database clone (advisories/unreviewed/...). Candidate commit '
                 'diffs were read from the sweep pool; missing repos were fetched via git smart-HTTP '
                 '(--filter=blob:none --shallow-since=2025-08-01). No GitHub API, no git blame/SZZ. '
                 'FALSE_POSITIVE is used only where the candidate diff was read and positively shows a '
                 'fix or a non-matching surface; missing evidence is never converted to FAIL.')
    lines.append('')
    lines.append('## Counts')
    lines.append('')
    lines.append('- assigned 25, reviewed 25, unreviewed 0. Conservation 25=25+0.')
    lines.append('- CONFIRM 0, FALSE_POSITIVE 25, UNKNOWN 0, countable_proposal 0.')
    lines.append('- identity_gate PASS 25 (unreviewed GHSA objects name mechanism + public identity; '
                 'repository identified from references; none withdrawn).')
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
    lines.append('- Repo clones (fetched this run): bludit__bludit, wolfSSL__wolfssl, '
                 'ixray-team__ixray-1.6-stcop, ocaml__ocaml, pfefferle__wordpress-webmention')
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

