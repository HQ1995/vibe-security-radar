#!/usr/bin/env python3
"""Round7 correction round 2 (2026-08-26): Grok's second audit of the 200 records.

Every claim below was re-verified against the local clones (numactl node 1)
before any byte changed:

1. relyra alias-57104d605e4cddde423d1ce4 — stays NOT_AI. The BIC 2aeba972
   (human szTheory) carries only 'Made-with: Cursor', which is NOT a
   canonical attribution under the production source policy (verb not in
   EXPLICIT_ATTRIBUTION_VERBS; not Co-Authored-By/Generated-with/Assisted-by;
   unknown_tool_attribution_is_production_evidence=false). Independent fix
   fact recorded: 2e456897 (Co-Authored-By: Claude Opus 4.7) wires real
   XMLDSig crypto into the exact [candidate] arm the BIC wrote. An
   AI-written fix does not flip the root-cause verdict.

2. openclaw alias-6fa8cee871e7f5f2b5a07c0b — NOT_AI -> AI_ROOT_CAUSE. BIC
   20523b918ad (2026-02-24, SidQin-cyber) carries the canonical
   'Co-authored-by: Cursor <cursoragent@cursor.com>' trailer and first-wrote
   trustedProxyAuthOk (git log -S; parent d84659f22 absent). The advisory
   fix is ec45c317 (2026-02-26, Peter Steinberger, human, no AI trailer,
   'block trusted-proxy control-ui node bypass'): adds role === "operator"
   to the trustedProxyAuthOk predicates in message-handler.ts at both sites,
   exactly restoring the omitted role gate, with node-role rejection tests.
   96fba91b3a (2026-05-13, [AI]) is a later, broader hardening that removed
   the bypass entirely; it is recorded in evidence, not used as the fix.
   This row duplicates the pre-round7 primary TP alias-3f35b69df081559ab1fad010
   (GHSA-VVGP-4C28-M3JM) and is folded at ledger level
   (site_publication.publish=false). advisory_ids = GHSA only: the primary
   has no advisory_identity/member_ids to mirror and no local evidence maps
   this advisory to a CVE. squash_decomposed true->false and
   decomposed_shas 7->[]: the 7 PR-member SHAs are all unresolvable locally
   (one is a bad object); 20523b918ad is the locally verifiable atomic
   first-writer, not a squash member we can enumerate.

3. better-auth alias-f0b371318e30448b9a250d8a — NOT_AI -> AI_ROOT_CAUSE.
   True BIC b5f3bad63 (2025-10-21, Alex Yang, canonical 'Co-authored-by:
   Copilot <175728472+Copilot@users.noreply.github.com>', 'feat: add
   storeStateStrategy (#5470)') first-wrote the unverified cookie branch in
   oauth2/state.ts (symmetricDecrypt + stateDataSchema.parse(JSON.parse(...))
   with NO comparison of decrypted state to the callback state param).
   Parent 3a3434b40 has no storeStateStrategy. 34c8a4bd2 (2026-01-14, Paola
   Estefanía de Campos, human) is a MOVE commit (oauth2/state.ts -> state.ts,
   +221/-192), not the introducer; the unverified branch rides along
   (present unverified in 9deb7936^:state.ts). The 3d3435b32ded (Cursor)
   cited by the earlier row is a phantom SHA, unresolvable from any ref.
   Fix 9deb7936 (2026-04-09, Maxwell + human co-authors, #8949) adds the
   oauthState nonce to the schema/payload and the state_security_mismatch
   check in parseGenericState; HEAD is post-fix.

Rewrites the 3 lane lines in full (18-key contract) and patches each ledger
row's status / round7_verdict / round7_research; the openclaw row also gains
the site_publication fold. All other bytes of both files are untouched.
"""
import json
import re

LANE_DIR = '.ai-slop/state/research-queue/round7'
LEDGER = 'artifacts/funnel-account-20260817.jsonl'
LANE_FILE = 'qZ.jsonl'

RELYRA = 'alias-57104d605e4cddde423d1ce4'
OPENCLAW = 'alias-6fa8cee871e7f5f2b5a07c0b'
BETTERAUTH = 'alias-f0b371318e30448b9a250d8a'
OPENCLAW_PRIMARY = 'alias-3f35b69df081559ab1fad010'
SHA40 = re.compile(r'^[0-9a-f]{40}$')
KEYS = {
    'class_id', 'case_id', 'repo', 'advisory_ids', 'bug_semantics', 'flaw_origin',
    'introducer_sha', 'introducer_parent', 'introducer_parent_absent',
    'squash_decomposed', 'decomposed_shas', 'ai_marker', 'verdict', 'fix_sha',
    'direct_fix_sha', 'evidence', 'reasoning', 'remaining_gap',
}


def dump(r):
    return json.dumps(r, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def load_lane():
    return [json.loads(l) for l in open(f'{LANE_DIR}/{LANE_FILE}') if l.strip()]


def build_relyra(existing):
    """Keep BIC identity + bug text; record the verified fix; clarify marker."""
    row = {k: existing[k] for k in (
        'class_id', 'case_id', 'repo', 'advisory_ids', 'bug_semantics',
        'flaw_origin', 'introducer_sha', 'introducer_parent',
        'introducer_parent_absent', 'squash_decomposed', 'decomposed_shas',
    )}
    row['verdict'] = 'NOT_AI'
    row['fix_sha'] = '2e456897af3158c175bb490ce7fc51d6241c8922'
    row['direct_fix_sha'] = '2e456897af3158c175bb490ce7fc51d6241c8922'
    row['ai_marker'] = (
        "BIC 2aeba972 author szTheory (human). Sole AI signal is 'Made-with: Cursor', which is "
        "NOT a canonical attribution: 'Made' is not in EXPLICIT_ATTRIBUTION_VERBS "
        "(cve-analyzer source_policy), it is not a Co-Authored-By / Generated-with / "
        "Assisted-by trailer, and unknown_tool_attribution_is_production_evidence=false. "
        "Independent fact: fix 2e456897 is Co-Authored-By: Claude Opus 4.7 (1M context) "
        "(AI-written fix; does not change the BIC root-cause verdict)."
    )
    row['evidence'] = (
        existing['evidence']
        + " Fix 2e456897 (2026-05-24, szTheory, subject 'feat(29-03): wire real XMLDSig crypto "
        "into the [candidate] arm (D-01)', body 'Closes the published-hex SAML auth-bypass: the "
        "[candidate] arm of verified_signed_node now performs genuine cryptographic verification "
        "between selecting the single candidate and building %SignedNode{}', trailer "
        "Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>) threads "
        "cert_chain/public_key_from_cert_chain/safe_verify into the arm and calls "
        "cryptographically_verify/4 before building %SignedNode{} (signature.ex L169-178); "
        "2e456897^:signature.ex still contains the unverified arm. The AI co-author is on the "
        "FIX commit, not the BIC; 'Made-with: Cursor' on the BIC is a non-canonical tool "
        "attribution (see ai_marker) and is not production AI evidence, so flaw_origin's "
        "'marker AI' phrasing is superseded."
    )
    row['reasoning'] = (
        "BIC 2aeba972 (human author szTheory) first wrote the unverified [candidate] arm; the "
        "only AI signal on it is 'Made-with: Cursor', which fails the production source policy "
        "(verb not in EXPLICIT_ATTRIBUTION_VERBS; unknown-tool attribution is not production "
        "evidence). The fix 2e456897 is AI-written (Claude Opus 4.7 co-author) and targets "
        "exactly this arm, but an AI-written fix does not make the root cause AI-authored. "
        "Same standard as the round-1 demotions of pydantic-ai/coder. Verdict NOT_AI stands; "
        "fix_sha/direct_fix_sha now recorded."
    )
    row['remaining_gap'] = None
    return row


def build_openclaw():
    return {
        'class_id': OPENCLAW,
        'case_id': 'GHSA-VVGP-4C28-M3JM',
        'repo': 'openclaw/openclaw',
        'advisory_ids': ['GHSA-VVGP-4C28-M3JM'],
        'verdict': 'AI_ROOT_CAUSE',
        'bug_semantics': (
            "Gateway trusted-proxy Control UI auth bypassed device pairing and device identity "
            "for node-role sessions. BIC 20523b918ad computes trustedProxyAuthOk without any role "
            "gate; connect-policy.shouldSkipControlUiPairing 'if (trustedProxyAuthOk) return true' "
            "and evaluateMissingDeviceIdentity 'allow' let a trusted-proxy Control UI connection "
            "of ANY role skip pairing and proceed without device identity. Fix ec45c317 adds "
            "role === 'operator' to the trustedProxyAuthOk predicates, restoring the operator-only "
            "boundary."
        ),
        'flaw_origin': (
            "connect-policy.ts shouldSkipControlUiPairing 'if (trustedProxyAuthOk) return true' + "
            "evaluateMissingDeviceIdentity trusted-proxy allow; message-handler.ts "
            "trustedProxyAuthOk predicate (isControlUi && mode==='trusted-proxy' && authOk && "
            "authMethod==='trusted-proxy', no role term). BIC 20523b918ad (2026-02-24, "
            "SidQin-cyber, 'fix(gateway): allow trusted-proxy control-ui auth to skip device "
            "pairing', Fixes #25293, Co-authored-by: Cursor <cursoragent@cursor.com>) first wrote "
            "trustedProxyAuthOk (git log -S across connect-policy.ts and message-handler.ts); "
            "parent d84659f22 contains no trustedProxyAuthOk."
        ),
        'introducer_sha': '20523b918adff4feae378ac9965e204c56b6e3d8',
        'introducer_parent': 'd84659f22fc59d9eecfa6f1cebe24b79674bed5a',
        'introducer_parent_absent': True,
        'squash_decomposed': False,
        'decomposed_shas': [],
        'ai_marker': (
            "BIC 20523b918ad carries 'Co-authored-by: Cursor <cursoragent@cursor.com>' (canonical "
            "trailer, 2026-02-24). Notes: the earlier dossier's atomic origin "
            "4a7b813a4f70946aa2b9401a3fd6865f32c5f9b9 is unresolvable locally (bad object); the "
            "7 PR-squash member SHAs recorded earlier are all unresolvable locally. 20523b918ad "
            "is the locally verifiable atomic first-writer and itself carries the canonical "
            "Cursor trailer."
        ),
        'fix_sha': 'ec45c317f5d0631a3d333b236da58c4749ede2a3',
        'direct_fix_sha': 'ec45c317f5d0631a3d333b236da58c4749ede2a3',
        'evidence': (
            "Local openclaw clone: git log -S 'trustedProxyAuthOk' -> 20523b918ad (2026-02-24, "
            "SidQin-cyber, Co-authored-by: Cursor) first writes it: connect-policy.ts "
            "shouldSkipControlUiPairing gains 'if (trustedProxyAuthOk) { return true; }' and "
            "evaluateMissingDeviceIdentity gains an isControlUi && trustedProxyAuthOk allow; "
            "message-handler.ts computes the predicate with no role term at two sites. Parent "
            "d84659f22: 0 occurrences (absence verified). Advisory fix ec45c317 (2026-02-26, "
            "Peter Steinberger, human, no AI trailer, 'fix(gateway): block trusted-proxy "
            "control-ui node bypass') adds role === 'operator' to the trustedProxyAuthOk "
            "predicate at both message-handler.ts sites (L491-494, L629-632) and adds "
            "node-role rejection tests in server.auth.test.ts; it is an ancestor of the later "
            "AI hardening 96fba91b3a51d6e536f03a4077ef8a11a132578d (2026-05-13, [AI], Pavan Kumar "
            "Gondhi, 'Require Control UI pairing before proxy-scoped access (#81288)'), which "
            "renamed the parameter _trustedProxyAuthOk, deleted the shouldSkipControlUiPairing "
            "bypass, and removed the trustedProxyAuthOk scope-clearing clause. The dossier "
            "(scripts/audit_results/GHSA-vvgp-4c28-m3jm.json) names ec45c317 as fix_commit and "
            "describes exactly this role-gate restoration."
        ),
        'reasoning': (
            "Chain closes with AI at the BIC: Cursor-coauthored 20523b918ad introduced the "
            "role-less trustedProxyAuthOk allow path (pairing skip + missing-device-identity "
            "allow for any Control UI role); the human fix ec45c317 (2 days later) restored the "
            "operator-only gate that the BIC's predicate omitted. AI wrote the root cause -> "
            "AI_ROOT_CAUSE. This row duplicates the pre-round7 primary TP "
            f'{OPENCLAW_PRIMARY} (same advisory GHSA-VVGP-4C28-M3JM, same Cursor BIC lineage) '
            "and is folded at ledger level via site_publication.publish=false, so it does not "
            "add a net published TP and is skipped by detect_duplicate_tps."
        ),
        'remaining_gap': None,
    }


def build_betterauth():
    return {
        'class_id': BETTERAUTH,
        'case_id': 'GHSA-wxw3-q3m9-c3jr',
        'repo': 'better-auth/better-auth',
        'advisory_ids': ['GHSA-wxw3-q3m9-c3jr'],
        'verdict': 'AI_ROOT_CAUSE',
        'bug_semantics': (
            "OAuth state with storeStateStrategy=cookie is stored in an encrypted cookie and "
            "parsed back (symmetricDecrypt + stateDataSchema.parse(JSON.parse(decryptedData))) "
            "without comparing the decrypted state to the callback state query parameter, "
            "allowing OAuth CSRF / state mismatch. Fix 9deb7936 adds the oauthState nonce to "
            "the stored payload and a state_security_mismatch check in parseGenericState."
        ),
        'flaw_origin': (
            "packages/better-auth/src/oauth2/state.ts cookie branch (storeStateStrategy === "
            "'cookie'): BIC b5f3bad633d8ae79fd5ffbb35ec2a39afdfc2f5e (2025-10-21, Alex Yang, "
            "'feat: add `storeStateStrategy` (#5470)', Co-authored-by: Copilot "
            "<175728472+Copilot@users.noreply.github.com>) first wrote the unverified cookie "
            "parse; parent 3a3434b403187ddace8cf35a1ee6ae88aeb11377 has no storeStateStrategy. "
            "34c8a4bd2 (2026-01-14, Paola Estefanía de Campos, human, 'fix(saml): IdP-Initiated "
            "Callback Routing (#6675)') moved the generic state logic to new src/state.ts "
            "(+221) and shrank oauth2/state.ts (-192) without adding verification; the earlier "
            "row's 3d3435b32ded (Cursor) is a phantom SHA, unresolvable from any ref."
        ),
        'introducer_sha': 'b5f3bad633d8ae79fd5ffbb35ec2a39afdfc2f5e',
        'introducer_parent': '3a3434b403187ddace8cf35a1ee6ae88aeb11377',
        'introducer_parent_absent': True,
        'squash_decomposed': False,
        'decomposed_shas': [],
        'ai_marker': (
            "BIC b5f3bad63 carries 'Co-authored-by: Copilot "
            "<175728472+Copilot@users.noreply.github.com>' (canonical trailer, 2025-10-21). "
            "The 34c8a4bd2 previously cited as the BIC is a human move commit (IdP-Initiated "
            "Callback Routing), not the introducer; 3d3435b32ded (Cursor) is a phantom SHA "
            "that no local ref resolves."
        ),
        'fix_sha': '9deb7936aba7931f2db4b460141f476508f11bfd',
        'direct_fix_sha': '9deb7936aba7931f2db4b460141f476508f11bfd',
        'evidence': (
            "Local better-auth clone: git log -S 'storeStateStrategy' -- "
            "packages/better-auth/src/oauth2/state.ts -> b5f3bad63 (2025-10-21, Copilot "
            "co-author) creates the cookie branch: store writes "
            "symmetricEncrypt(JSON.stringify(stateData)) to the oauth_state cookie; the "
            "retrieve branch does symmetricDecrypt + stateDataSchema.parse(JSON.parse("
            "decryptedData)) with NO comparison of the parsed state to the callback state "
            "parameter (the verification-branch stateCookieValue !== state check applies only "
            "to the non-cookie path). Parent 3a3434b40: 0 occurrences of "
            "storeStateStrategy/symmetricDecrypt (absence verified). 34c8a4bd2 (human) moves "
            "the logic: 34c8a4bd2^:state.ts does not exist; after the move, "
            "9deb7936^:state.ts still carries the unverified cookie branch (L63-66 store, "
            "L137 retrieve, no nonce). Fix 9deb7936 (2026-04-09, Maxwell, co-authors Bereket "
            "Engida + Gustavo Valverde, all human, 'fix: cookie store strategy should verify "
            "oauth state (#8949)') adds oauthState to the StateData schema, stores "
            "oauthState: state in the cookie payload, and makes parseGenericState throw "
            "StateError('state_security_mismatch') when parsedData.oauthState !== state; "
            "post-fix state.ts has 6 oauthState references (pre-fix 0); 9deb7936 is an "
            "ancestor of HEAD."
        ),
        'reasoning': (
            "Chain closes with AI at the BIC: Copilot-coauthored b5f3bad63 first wrote the "
            "cookie-state parse that never compares the decrypted state to the callback "
            "state parameter; the flaw survives the human 34c8a4bd2 file move and is fixed "
            "by human 9deb7936, which adds the oauthState nonce + state_security_mismatch "
            "check. AI wrote the root cause -> AI_ROOT_CAUSE. The earlier NOT_AI row rested "
            "on a phantom SHA (3d3435b32ded) and mislabeled the move commit as the BIC; "
            "both are corrected here."
        ),
        'remaining_gap': None,
    }


def patch_lane(new_rows):
    rows = load_lane()
    new_by_id = {nr['class_id']: nr for nr in new_rows}
    for cid in new_by_id:
        assert cid in {r.get('class_id') for r in rows}, f'lane missing {cid}'
    out = []
    replaced = 0
    for r in rows:
        cid = r.get('class_id')
        if cid in new_by_id:
            replaced += 1
            out.append(new_by_id[cid])
        else:
            out.append(r)
    assert replaced == len(new_rows), f'lane replaced {replaced} != {len(new_rows)}'
    with open(f'{LANE_DIR}/{LANE_FILE}', 'w') as f:
        for r in out:
            f.write(dump(r) + '\n')
    return len(out)


def openclaw_fold():
    return {
        'date': '2026-08-26',
        'folded_into': 'GHSA-VVGP-4C28-M3JM',
        'kept_class_id': OPENCLAW_PRIMARY,
        'note': (
            'Duplicate row of GHSA-vvgp-4c28-m3jm; primary row is '
            f'{OPENCLAW_PRIMARY}. Marked at ledger level so publication does not need '
            'drop lists.'
        ),
        'publish': False,
    }


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
            if nr['class_id'] == OPENCLAW:
                r['site_publication'] = openclaw_fold()
            replaced[r['class_id']] = True
        out.append(r)
    assert len(replaced) == len(new_rows) and all(replaced.values()), f'ledger replaced: {replaced}'
    with open(LEDGER, 'w') as f:
        for r in out:
            f.write(dump(r) + '\n')
    return len(out)


def main():
    lane = load_lane()
    existing = {r.get('class_id'): r for r in lane}
    rows = [
        build_relyra(existing[RELYRA]),
        build_openclaw(),
        build_betterauth(),
    ]
    for row in rows:
        assert set(row) == KEYS, f'{row["class_id"]}: key diff {set(row) ^ KEYS}'
        for k in ('introducer_sha', 'fix_sha', 'direct_fix_sha'):
            assert row[k] is None or SHA40.match(row[k]), f'{row["class_id"]}: {k}'
        assert row['fix_sha'] == row['direct_fix_sha'], row['class_id']
        assert all(SHA40.match(s) for s in row['decomposed_shas']), row['class_id']
        assert row['verdict'] in {'NOT_AI', 'AI_ROOT_CAUSE', 'AI_CODE_FLAWED', 'BLOCKED', 'EVIDENCE_GAP'}
    n_lane = patch_lane(rows)
    n_ledger = patch_ledger({r['class_id']: r for r in rows})
    print(f'lane qZ lines={n_lane}, ledger lines={n_ledger}')
    print('OK')


if __name__ == '__main__':
    main()
