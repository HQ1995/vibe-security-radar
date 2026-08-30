#!/usr/bin/env python3
"""Round7 correction (2026-08-26): re-attribute pydantic-ai + coder to NOT_AI.

External cross-check (Grok) found that both AI attributions pointed at non-BIC
commits. Local clone verification established the true minimal atomic first-writers.
Rewrites the 2 lane lines in full (18-key contract) and patches the 3 affected
keys in each ledger row; all other bytes of both files are untouched.
"""
import json

LANE_DIR = '.ai-slop/state/research-queue/round7'
LEDGER = 'artifacts/funnel-account-20260817.jsonl'

PYD = 'alias-a16652492e42b6eefef74358'
CODER = 'alias-ed3fab545510d72c9e9ecc14'

pyd_row = {
    'class_id': PYD,
    'case_id': 'CVE-2026-65975',
    'repo': 'pydantic/pydantic-ai',
    'advisory_ids': ['CVE-2026-65975', 'GHSA-jpr8-2v3g-wgf9'],
    'verdict': 'NOT_AI',
    'bug_semantics': ('UI adapters (AG-UI, Vercel AI): a dangling client-submitted tool call can execute '
                      'when a trailing message is dropped during sanitize_messages. sanitize_messages '
                      '(introduced in pydantic_ai_slim/pydantic_ai/ui/_adapter.py by #5228, later moved to '
                      'messages.py by the #6169 refactor) drops a request/response whose parts sanitize to '
                      'empty (e.g. a client-supplied system prompt) to avoid leaving an empty '
                      'ModelRequest/ModelResponse; dropping a trailing message can re-expose an earlier '
                      'ModelResponse whose unresolved (dangling) tool calls a promptless run then dispatches '
                      'directly, executing a client-injected tool call. The in-BIC mitigation was incomplete, '
                      'leaving the execution path. Affects pydantic-ai >=1.88.0,<1.107.1 and >=2.0.0b1,<2.5.0.'),
    'flaw_origin': ("53964f0ea79fdcb178fef705c6b5c64198c0ee36 "
                    "'feat(ui): add `UIAdapter.sanitize_messages` and `allowed_file_url_schemes` (#5228)' "
                    '(Douwe Maan, 2026-04-28, no AI markers) is the minimal atomic first-writer: it created '
                    'UIAdapter.sanitize_messages in pydantic_ai_slim/pydantic_ai/ui/_adapter.py including the '
                    "trailing-message drop logic (`last_index = len(messages) - 1`, 'drop the request/response "
                    "entirely') and the incomplete dangling-tail mitigation; shipped in v1.88.0 (advisory: "
                    '>=1.88.0, <1.107.1). The later #6169 refactor that moved the function to messages.py is '
                    'not the BIC: it is not an ancestor of the fixed version v1.107.1 and its parent already '
                    'contained the drop logic.'),
    'introducer_sha': '53964f0ea79fdcb178fef705c6b5c64198c0ee36',
    'introducer_parent': '1b4f90624d084fcbb0654ee67dc959a79c35d3e9',
    'introducer_parent_absent': True,
    'squash_decomposed': False,
    'decomposed_shas': [],
    'ai_marker': ("absent on BIC 53964f0e (Douwe Maan, no AI trailers); the 'Co-authored-by: Claude Opus 4.8 "
                  "(1M context)' trailer is on later refactor b31d6072b7967e35f1f47d82bcaf102686972e07 (#6169, "
                  '2026-07-03), which moved the function from ui/_adapter.py to messages.py and is NOT an '
                  'ancestor of v1.107.1, so it did not write the vulnerable lines -> marker demoted per '
                  'protocol'),
    'fix_sha': '54d51dbf3189cb7639949253951eda52d0e19054',
    'direct_fix_sha': '54d51dbf3189cb7639949253951eda52d0e19054',
    'evidence': ("Identity pinned: repo=pydantic/pydantic-ai (class-repo-precise); advisories_count=2; the "
                 "vulnerable function the advisory names is sanitize_messages, whose sole 2-ID pydantic-ai "
                 "advisory is GHSA-jpr8-2v3g-wgf9 / CVE-2026-65975 ('UI adapters (AG-UI, Vercel AI): a dangling "
                 "client-submitted tool call can execute when a trailing message is dropped during "
                 "sanitize_messages'); the other 4 pydantic-ai GHSAs (2jrp/cg7w/cqp8/wjp5) each map to "
                 "4-member classes and are the SSRF/XSS bugs. Correction (external cross-check 2026-08-26, "
                 'locally re-verified): the true BIC is 53964f0e (#5228, Douwe Maan, 2026-04-28, no AI '
                 "trailers) - it first wrote UIAdapter.sanitize_messages with the drop logic into "
                 "pydantic_ai_slim/pydantic_ai/ui/_adapter.py; parent 1b4f9062 contains no 'last_index' in "
                 'pydantic_ai_slim/pydantic_ai/ (verified by git grep); 53964f0e is absent from v1.87.0 and '
                 'present in v1.88.0 (tag membership checked both ways). The previously recorded BIC b31d6072 '
                 "(#6169, David SF + 'Co-authored-by: Claude Opus 4.8 (1M context)', 2026-07-03) is a move "
                 'refactor (ui/_adapter.py -383 lines, messages.py +428) that is NOT an ancestor of v1.107.1 '
                 '(git merge-base --is-ancestor = NO), first ships in v2.5.0, and its parent 0e7401af already '
                 "contains 'def sanitize_messages' at ui/_adapter.py:347 - so it could not be the first "
                 'writer. Fix correction: 54d51dbf (#6407, David SF, 2026-07-10, no markers) strips dangling '
                 'tool calls from the surviving tail AFTER empty-message drops; it is present in v1.107.1 and '
                 'absent from v1.107.0 (the advisory-fixed version), and 54d51dbf^ == v1.107.0. The previously '
                 "recorded fix 86029861bb86b210c29b3d3f3d5660fefd8c57 (#6319) resolves a different "
                 "sanitize_messages issue, not this CVE's drop->re-expose->dispatch flaw."),
    'reasoning': ('Minimal BIC is 53964f0e (#5228, human, no AI markers): it first wrote the '
                  'sanitize_messages drop logic and shipped it in v1.88.0, the advisory lower bound; its '
                  'parent demonstrably lacks the logic. The earlier AI_ROOT_CAUSE attribution was wrong on '
                  'two counts: (1) it treated the #6169 move refactor as the first writer, although that commit '
                  'postdates the fixed version and is not an ancestor of v1.107.1; (2) it cited the wrong fix '
                  '(#6319 instead of #6407). AI marker on a non-BIC commit -> demoted. Verdict NOT_AI.'),
    'remaining_gap': None,
}

coder_row = {
    'class_id': CODER,
    'case_id': 'GHSA-686C-7VGV-V3FX',
    'repo': 'coder/coder',
    'advisory_ids': ['GHSA-686C-7VGV-V3FX', 'CVE-2026-45796'],
    'verdict': 'NOT_AI',
    'bug_semantics': ('Unauthenticated semi-blind SSRF via POST /api/v2/workspaceagents/azure-instance-identity: '
                      'during PKCS#7 certificate-chain verification, Validate() fetched OCSP/CRL/certificate '
                      'URLs from the crafted signature over the network with no host allowlist, no private-IP '
                      'rejection, no response-size cap and DNS-rebinding-prone dialing, letting an '
                      'unauthenticated attacker force the Coder server to issue HTTP GET requests to arbitrary '
                      'internal or external hosts (reachability oracle via error messages).'),
    "flaw_origin": ("c8246e3e8ade9c447aca6f93a6ec58dda0a715ea 'feat: Add Azure instance identitity "
                    "authentication (#1064)' (Kyle Carberry, 2022-04-19, no AI markers, pre-AI era) first "
                    "wrote the cert-fetch path `res, err := http.DefaultClient.Do(req)` in "
                    "coderd/azureidentity/azureidentity.go (line 102) with no host allowlist, no private-IP "
                    "rejection and no response-size cap; the line was unchanged until the 2026 hardening "
                    "(file later touched by 8d1220e0c8/d67552f852/9ea21bf8ee/871ed128aa/e3db203011 without "
                    "altering the call)"),
    'introducer_sha': 'c8246e3e8ade9c447aca6f93a6ec58dda0a715ea',
    'introducer_parent': '118a47e4e159c15230cca39befdb04971c67434f',
    'introducer_parent_absent': True,
    'squash_decomposed': False,
    'decomposed_shas': [],
    'ai_marker': ("absent on BIC (2022-04-19, Kyle Carberry, pre-AI); the 'Co-Authored-By: Claude Opus 4.7 "
                  "(1M context)' trailer is on revert f2b9ec2b4ba798a4a28b7b2ffb17dfff2c488c2b (Jakub "
                  'Domeracki, 2026-05-13 12:04 +0200), which is NOT the BIC: it reverted same-day hardening '
                  'fb3aef1883 and was superseded within 47 minutes by fix 57b11d40 on the parallel squash '
                  'revert 9400eaa9 (#25273); f2b9ec2b appears in no tag and every tag containing 9400eaa9 '
                  '(earliest v2.34.0) also contains the fix, so no release ever shipped the vulnerable state'),
    'fix_sha': '57b11d405f17492aa789d4b9ff33366f961a37f8',
    'direct_fix_sha': '57b11d405f17492aa789d4b9ff33366f961a37f8',
    'evidence': ("OSV GHSA-686c-7vgv-v3fx / CVE-2026-45796 'Coder: Unauthenticated SSRF via Azure Instance "
                 "Identity Endpoint' (points at coderd/azureidentity/azureidentity.go Validate()). Correction "
                 '(external cross-check 2026-08-26, locally re-verified): the minimal BIC of the vulnerable '
                 'line is c8246e3e (#1064, Kyle Carberry, 2022-04-19, no AI markers) - git log -L anchored at '
                 "the pre-hardening state shows the line history c8246e3e -> 9ea21bf8ee -> d67552f852 -> "
                 "8d1220e0c8 -> 871ed128aa -> e3db203011, with e3db203011's diff touching no DefaultClient "
                 'line; parent 118a47e4 contains no http.DefaultClient in coderd/azureidentity/ (verified by '
                 'git grep). The 2026 incident: fb3aef1883 (11:55) hardened the cert fetch (host allowlist, '
                 'private-IP rejection, size cap); AI revert f2b9ec2b (12:04 +0200, author Jakub Domeracki, '
                 'Co-Authored-By: Claude Opus 4.7) and its squash carrier 9400eaa9 (12:10, #25273, human, no '
                 "marker) both deleted it; fix 57b11d40 (12:51, #25274, human, no marker) restored it on top "
                 'of 9400eaa9 (57b11d40^ == 9400eaa9). f2b9ec2b is not an ancestor of 9400eaa9 or 57b11d40; '
                 'git tag --contains f2b9ec2b is empty; every tag containing 9400eaa9 (v2.34.0 through '
                 'v2.36.3, 20 tags) contains 57b11d40 (checked individually). Hence the vulnerable window '
                 'was never released, and the AI marker sits on a non-BIC commit that shipped in no release '
                 '-> demoted per protocol.'),
    'reasoning': ('Per AUDIT-PROTOCOL the minimal atomic first-writer of the vulnerable lines decides '
                  'attribution. The vulnerable fetch (http.DefaultClient.Do(req) on an attacker-controlled '
                  'cert URL, no allowlist) was written in 2022 by c8246e3e (#1064, human, pre-AI era); its '
                  'parent lacks the call. The 2026 AI-co-authored revert f2b9ec2b (Opus 4.7 trailer) is real '
                  'but (1) is not the BIC and (2) was never released: the squash carrier 9400eaa9 and the fix '
                  '57b11d40 landed within 47 minutes and no tag contains the carrier without the fix. AI '
                  'marker on a non-BIC, unreleased commit -> demoted. Verdict NOT_AI.'),
    'remaining_gap': None,
}


def dump(r):
    return json.dumps(r, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def patch_lane(fname, new_row):
    rows = [json.loads(l) for l in open(f'{LANE_DIR}/{fname}') if l.strip()]
    out = []
    replaced = 0
    for r in rows:
        if not isinstance(r, dict) or r.get('class_id') != new_row['class_id']:
            out.append(r)
            continue
        replaced += 1
        out.append(new_row)
    assert replaced == 1, f'{fname}: replaced {replaced}'
    with open(f'{LANE_DIR}/{fname}', 'w') as f:
        for r in out:
            f.write(dump(r) + '\n')
    return len(out)


def patch_ledger(new_rows):
    out = []
    replaced = {}
    for l in open(LEDGER):
        if not l.strip():
            continue
        r = json.loads(l)
        if r.get('class_id') in new_rows:
            nr = new_rows[r['class_id']]
            r['status'] = nr['verdict']
            r['round7_verdict'] = nr['verdict']
            r['round7_research'] = nr
            replaced[r['class_id']] = True
        out.append(r)
    assert len(replaced) == 2 and all(replaced.values()), f'ledger replaced: {replaced}'
    with open(LEDGER, 'w') as f:
        for r in out:
            f.write(dump(r) + '\n')
    return len(out)


n1 = patch_lane('qL.jsonl', pyd_row)
n2 = patch_lane('qM.jsonl', coder_row)
n3 = patch_ledger({PYD: pyd_row, CODER: coder_row})
print(f'lane qL lines={n1}, qM lines={n2}, ledger lines={n3}')
print('OK')
