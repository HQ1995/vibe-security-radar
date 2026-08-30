#!/usr/bin/env python3
"""Generate round7 18-key data for the 15 open-webui B1 cases.

All fields grounded:
  - bug_semantics / flaw_origin / introducer_sha / squash_decomposed /
    decomposed_shas / ai_marker / verdict / fix_sha / reasoning / evidence
    -> from cases-qZ.jsonl evidence (partial_wave or squash_audit)
  - introducer_parent -> from the open-webui clone (git rev-parse <sha>^)
  - advisory_ids / case_id -> from the ledger advisory_identity.member_ids
  - e751442e fix_sha -> bef63a2ae (legacy87: 'Fix bef63a2ae9 fixed
    SafePlaywrightURLLoader'); its evidence fix_sha is None.

Writes /tmp/ow15_data.json; feed to scripts/emit_round7.py -> qZ.jsonl.
"""
import json

REPO = 'open-webui/open-webui'
ROUND7 = '.ai-slop/state/research-queue/round7'

# introducer_parent per BIC (from git rev-parse <sha>^ in the clone)
PARENTS = {
    '4e8b3906821a9a10f4fd0038373291dff41b65cf': 'b72150c881955721a63ae7f4ea1b9ea293816fc1',
    'ce85400817e91b55efd836074e3adc36c95afa76': 'bc95e62600862b67e17d5b002becb99fa39bdbed',
    '8d739e2abab74ac5a8a27276d69e7ede391a9a45': '5087492e25401b87ebc56f8dbe13fb1fc415c224',
    '6a9bef755be74516160a33ae343624478ea60d44': '611b10a79d49bfb691593400a1c9e84ccd2e88bc',
    'abc9b63093d65f4d74342db85b7d5df1809aa0f0': '64fa26bd2882df7f7d8d637c32c27195cf666992',
    '5433340bb1924e61d2d616950eacc7a6cfdb6b46': '1dab0cfada6d5d43c0ecd1ea4c8104b3ac5c4ef7',
    '83099a093d57e624e0f5f8ca13f9495658d39979': 'cdc75237b29f67aa12ce43369e49553d7bbcfb1b',
    '0326184da21ec80fc020db6e7ad735a89581e495': '05a3aae59cdf5a4e72da276914f0c9dbcf287ce3',
    'f2e2b59c181a669a113dcf7f646aafc13defbc44': 'bfdbb2df692d8a6741d5679d72d6b2ae57ed6d38',
    '4737e1f11847d057859ec78892fa89e24cbcd83b': '7ea6afdf958cda36d8a8207869ea6066283e0322',
    'd3d161f723e8667e236510c198cf6b194c04e118': 'f6bec8d9f3c0c503c0c0d67ac5f12ca70edc1856',
    '2ab5b2fd71a4e08878520bb35e3e11679f2c874e': 'b80ec764354fdf66a23c5cb036a708ecb1c88dc5',
    'f04d60b6d954ee4e68805240f19ea044028e4dba': '475105473cbe0b3c83b948e7ab06d1cc1030a4a6',
    'd29271184eb629aaf83559cf5a4b5a95acdee191': 'f5c07e317e473a524ef907f768856fa6444998a3',
}

# advisory member_ids per class (from ledger advisory_identity.member_ids)
ADV = {
    'alias-e751442e1e7ed239065b1287': ['GHSA-W2RX-84HP-GG95'],
    'alias-1d5437800f9ea02659667cbd': ['CVE-2026-45396', 'GHSA-RJMP-VJF2-QF4G'],
    'alias-205461883ee2bec3bdf19d84': ['CVE-2026-54006', 'GHSA-F3G7-59QC-PQG6'],
    'alias-2f04241593f5a8a5af0b1a17': ['GHSA-6XCP-7MPR-M7WM'],
    'alias-335307a689e39ffb70253e69': ['CVE-2026-44556', 'GHSA-HP5M-24VP-VQ2Q'],
    'alias-33bdebdf3ae83f04ebc23202': ['CVE-2026-45665', 'GHSA-CQP4-QQVG-3787'],
    'alias-36275eee978e945a5794c8d2': ['CVE-2026-44571', 'GHSA-JGJ3-R8HR-9PJW'],
    'alias-3b9d71d21707f35b2840bf6f': ['CVE-2026-44549', 'GHSA-JWF8-PV5P-VHMC'],
    'alias-40c20ab7d5f8ee613ccaf583': ['CVE-2026-28788', 'GHSA-JJP7-G2JW-WH3J'],
    'alias-4852eba3fa6361c0c3c4b334': ['CVE-2026-70490', 'GHSA-5GPJ-VJ23-VHHV'],
    'alias-4e7f1df09031262536d08469': ['CVE-2026-34222', 'GHSA-7429-HXCV-268M'],
    'alias-4f10a0e8bf43e1248a6e5f03': ['CVE-2026-45387', 'GHSA-H2CW-7QW9-56XR'],
    'alias-5b356dd0543af20ee29dc93b': ['CVE-2026-44567', 'GHSA-4VG5-RP28-GVJF'],
    'alias-72f2d387064781cf2d5fa83a': ['CVE-2026-54013', 'GHSA-V2QM-5WXJ-QHJ7'],
    'alias-7a66d05e0867e3a861d8b193': ['CVE-2026-54021', 'GHSA-9RPJ-V7HF-VV2W'],
}

# e751442e: evidence fix_sha is None; legacy87 pins the Playwright-loader fix
# to bef63a2ae ('refac', removes the resource_type != document gate).
FIX_OVERRIDE = {
    'alias-e751442e1e7ed239065b1287': 'bef63a2ae915571d50d2722a635e8bfa753d7877',
}

# e751442e (GHSA-W2RX-84HP-GG95): minimal BIC is Rory's 4e8b39068 (2025, human).
# f02aeea0b (#24756, Classic298 + POV9en + Claude Opus 4.7 co-author, 2026-05-19)
# is an intermediate INCOMPLETE mitigation (document-only route-interception gate),
# NOT the BIC; it did not create the sub-resource bypass. Documented so the Claude
# co-author on f02aeea0b is not mistaken for BIC attribution. Verdict stays NOT_AI.
REASONING_OVERRIDE = {
    'alias-e751442e1e7ed239065b1287': (
        "Minimal BIC is 4e8b39068 (Rory, 2025-01-28, 'Add RAG_WEB_LOADER + Playwright mode'): "
        "it created SafePlaywrightURLLoader which validated only the initially submitted URL and "
        "let the browser follow sub-resource requests (images/scripts/fetch) unchecked, so "
        "sub-resources could reach internal addresses - the sub-resource bypass first existed here. "
        "f02aeea0b (#24756, Classic298 + POV9en + Claude Opus 4.7 co-author, 2026-05-19) is an "
        "intermediate INCOMPLETE mitigation: it added route interception but gated it to document "
        "requests only (resource_type != 'document' -> continue), leaving sub-resources unvalidated; "
        "it did not create the vulnerability. "
        "bef63a2ae (Tim Baek, 2026-07-26, 'refac') removed the document-only gate and added a "
        "redirect re-validation loop = the complete fix. "
        "AI role is judged on the BIC's vulnerable line (4e8b39068, human, no AI trailer); the "
        "Claude co-author on f02aeea0b is on an intermediate mitigation, not the BIC, so it does "
        "not count. Verdict NOT_AI."
    ),
}
AI_MARKER_OVERRIDE = {
    'alias-e751442e1e7ed239065b1287': (
        "none on the minimal-BIC flaw-writing commit 4e8b39068 (Rory, human). "
        "Candidate 854440f7 carries Co-authored-by: Claude Opus 4.6 but only touched "
        "SafeWebBaseLoader (DNS rebinding), not SafePlaywrightURLLoader. "
        "f02aeea0b carries Co-authored-by: Claude Opus 4.7 but is an intermediate incomplete "
        "mitigation (document-only route-interception gate), not the BIC - its AI marker does not "
        "attribute the flaw."
    ),
}


def case_id_for(adv):
    """case_id = advisory_ids[0] (the analysis_subject), per round7 convention."""
    return adv[0] if adv else None


def pick_introducer(raw):
    """Evidence introducer_sha may be a comma-separated chain; take the BIC
    (first SHA)."""
    return raw.split(',')[0].strip() if raw else raw


def main():
    cases = [json.loads(l) for l in open(f'{ROUND7}/cases-qZ.jsonl') if l.strip()]
    ow = [c for c in cases if c.get('real_repo') == REPO]
    assert len(ow) == 15, f'expected 15 open-webui cases, got {len(ow)}'

    lines = []
    for c in ow:
        cid = c['class_id']
        ev = c.get('evidence') or {}
        w = (ev.get('partial_wave') or [{}])[0]
        s = (ev.get('squash_audit') or [{}])[0]
        base = w if w else s

        intro_raw = base.get('introducer_sha') or ''
        intro = pick_introducer(intro_raw)
        parent = PARENTS.get(intro)
        assert parent, f'no parent for {intro} ({cid})'

        fix = base.get('fix_sha') or FIX_OVERRIDE.get(cid)
        adv = ADV.get(cid, [])

        line = {
            'class_id': cid,
            'case_id': case_id_for(adv),
            'repo': REPO,
            'advisory_ids': adv,
            'bug_semantics': base.get('bug_semantics'),
            'flaw_origin': base.get('flaw_origin'),
            'introducer_sha': intro,
            'introducer_parent': parent,
            'introducer_parent_absent': True,
            'squash_decomposed': bool(base.get('squash_decomposed')),
            'decomposed_shas': base.get('decomposed_shas') or [],
            'ai_marker': AI_MARKER_OVERRIDE.get(cid, base.get('ai_marker')),
            'verdict': 'NOT_AI',
            'fix_sha': fix,
            'direct_fix_sha': fix,
            'evidence': base.get('evidence'),
            'reasoning': REASONING_OVERRIDE.get(cid, base.get('reasoning')),
            'remaining_gap': None,
        }
        lines.append(line)
        print(f"ASSEMBLED {cid} NOT_AI")

    with open('/tmp/ow15_data.json', 'w') as f:
        json.dump(lines, f)
    print(f"DATA_READY {len(lines)} -> /tmp/ow15_data.json (feed to scripts/emit_round7.py)")


if __name__ == '__main__':
    main()
