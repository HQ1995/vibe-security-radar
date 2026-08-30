# Round 10 protocol re-check — points of disagreement

Re-review of `research/round10-top200-20260828/` against `docs/AUDIT-PROTOCOL.md`
(2026-08-29). Every git claim below was re-verified in the assigned clones with
`numactl`-prefixed git commands. Verdict shorthand: P = `primary/wNNN.json`
(glm-5.3-flash), R = `review/wNNN.json` (independent re-review).

**For the round-10 lane owner (glm primary), the round-11 fix list in priority
order:**
1. Add FALSE_POSITIVE + withdrawn/rejected (CVE.org) rule to the primary
   prompt; re-run w121, w194, and re-adjudicate all 174 NOT_AI against CVE.org
   disposition (mechanical, no re-research needed).
2. Re-run the 18 review records that fail `audit_record_gates`, and pin
   `introducer_parent_absent` semantics to line-level in both prompts +
   comparator (58 same-BIC contradictions are mostly this ambiguity).
3. Regenerate comparisons from all 193 reviews (56 never compared; 19 true
   flips); replace the ivg 0/137 headline (marker-text artifact; real
   substantive disagreements: 55/137).
4. Case re-adjudication lists: §2 (accept R), §3 (keep P), Bottom line
   verification-basis note. P/w196's record is provenance-tainted (cites
   `w195`/CVE-2026-73326, absent from its bundle) — re-run in clean context.

## 1. Process-level disagreements

1. **The primary prompt omits the withdrawn/rejected → FALSE_POSITIVE rule.**
   `prompt-primary.txt` does not offer FALSE_POSITIVE as a verdict and does not
   mention the CVE.org check, although the primary prompt's first line instructs
   reading `docs/AUDIT-PROTOCOL.md`, which states the rule. Result: P produced
   **zero** FALSE_POSITIVE verdicts in 200 cases, while the review pass (whose
   prompt includes the rule) produced 7. Direct casualties: w121
   (CVE-2025-34351 is REJECTED at CVE.org; P said NOT_AI), w194 (CVE-2026-8449
   REJECTED; P said NOT_AI). I disagree with the campaign setup: the primary
   prompt must carry the same verdict set and the CVE.org disposition check.

2. **Both disagreement reports are stale and cover disjoint subsets.**
   `disagreement-report.md` compares 44 cases; `independent-vs-glm/` compares
   137. The review directory now holds 193 files; **56 reviews were never
   compared at all**, and 2 further verdict flips (w082 NOT_AI→FP,
   w087 BLOCKED→NOT_AI) exist in raw files but in no comparison report. The
   true flip count is 19, not 17. I disagree with treating either report as the
   adjudication input; regenerate from the raw 193 before adjudicating.

3. **"Full core agreement: 0/137" is a comparator artifact, not a finding.**
   The ivg comparator diffs the free-text `ai_marker` string verbatim; 42 of
   137 rows differ ONLY in that phrasing ("absent: author X…" vs "absent — …").
   Real substantive disagreements (verdict/BIC/parent/parent-absence/fix/repo):
   55 of 137. The headline number overstates conflict ~2.5×. Compare
   `marker_state`, not marker prose (the top-level `compare_results.py` already
   does; the ivg pass did not).

4. **The review pass was never gate-checked.** `verify_campaign.py` runs
   `audit_record_gates.check_record` over primary records only. Running the
   same gates over `review/` yields **18 failures** (17 closed NOT_AI without
   `fix_sha` and without a structured `unpatched` record — 17 of 20 mention
   "unpatched" only informally; w082 FALSE_POSITIVE without withdrawn/rejected
   evidence wording). I disagree with landing any R verdicts without the same
   gate discipline P was held to.

5. **58 same-BIC `introducer_parent_absent` contradictions.** For 58 cases the
   two passes claim the SAME introducer sha but disagree on the binary
   parent-absence fact (50× P=true/R=false, 8× P=false/R=true). This is a
   checkable fact, not a judgment call; at least one side did not really check.
   Root cause is an unscoped field: P checked line-level absence, R frequently
   checked file-level existence (e.g. w036: parent has `account.py` with 2
   GET-routes, BIC adds the 14 named ones — "absent" is true only for the named
   lines). I disagree with the field semantics as used; `AUDIT-PROTOCOL.md`
   should pin parent-absence to "the specific vulnerable lines", and the
   comparator should flag same-sha ppa flips as factual errors, not topics.

## 2. Case-level disagreements — primary wrong (accept R)

6. **w007 (GHSA-qg6r-j76g-wv2q, jahlives/openssl_encrypt): P AI_ROOT_CAUSE is
   marker-driven; the sink does not exist.** At P's BIC 4c7ae852,
   `settings.secret_key` has **zero consumers** in `server/telemetry-server/app`
   (`git grep secret_key <bic> -- server/telemetry-server/app` → only the
   config default); `hash_api_key` is plain `sha256(api_key)`. The advisory's
   claimed sink (default key feeding hash forgery) is absent, and the resolution
   commit does not wire it in either. R's FALSE_POSITIVE is correct. This is
   the worst primary failure mode in the round: "AI second" was honored, but
   "vulnerability first" was not — the mechanism was never verified before
   attributing AI.

7. **w113 (GHSA-hwgh-c22g-48rj, iatsiuk/pptr-mcp): P AI_ROOT_CAUSE describes
   the product's documented contract, not a flaw.** README's Key
   Difference/Security sections document non-sandboxed script execution for
   trusted local use; the reporter's own issue #1 calls it architectural.
   R's FALSE_POSITIVE (advisory misclassifies intended behavior) is the better
   protocol reading, though the CVE remains PUBLISHED at CVE.org — flag as
   contested FP, not clean FP.

8. **11 of 12 primary BLOCKED verdicts contradict the protocol's own clause.**
   The protocol explicitly allows "a first-write that is the smallest surviving
   object in public history IS a valid BIC when its immediate parent is
   verifiable". Verified examples where the object was reachable and P's BLOCKED
   was wrong: w023 (squash member e0f646d899e6 is a normal 2017 commit, ancestor
   of the 2026 fork merge; parent 5f039d2d lacks `_isExpressionDepthLimitReached`
   — human, NOT_AI), w068 (first write of `value="<?=$c_id?>"` is 1a609785 2013,
   parent blob has `value=''`; P's "pre-2013 unreachable" was false), w122
   (41d21074b is the first public commit of gnuboard5, parent verified, adds the
   exact scheme/host-only check). w116's BLOCKED survives scrutiny (both passes independently hit the same wall: the 1.17.3 npm tarball is unpublished, no git object carries the payload, so no BIC exists — P did not over-block here).

9. **w008/w026: primary EVIDENCE_GAP demanded inaccessible finer members that
   the protocol does not require.** w026: 12b2c215's `Former-commit-id` objects
   are absent from the clone (`cat-file -e` fails) — "no finer public member can
   be reconstructed" is satisfied; R's closed NOT_AI is correct. w008: same
   pattern with the private n8n-private member; R's NOT_AI on the public squash
   with human author + GraphQL-trailer evidence is protocol-conformant.

## 3. Case-level disagreements — review wrong (keep P)

10. **w004 (GHSA-62jr-cqgr-xmh7, n8n-io/n8n): R's AI_ROOT_CAUSE attributes the
    wrong commit.** R's BIC bd3aafce (2026-05-21, `Co-authored-by: Cursor`) is
    ~6 months **later** than P's BIC 8a83f6a9c5dd (2025-11-24, squash-landed as
    a49b179e 2025-11-26) and bd3aafce does not first-write the mechanism: at its
    parent 374e7ed the `isFilePathBlocked(resolvedRepositoryPath)` check already
    exists, and `git.clone(source, '.')` with `baseDir: resolvedRepositoryPath`
    already clones into the checked path. 8a83f6a first added the (async)
    blocked-path check while baseDir/clone still used the raw unresolved path —
    that is the first write of the check-then-unbound-use TOCTOU. P's NOT_AI
    (human author, no marker on 8a83f6a) stands. The Cursor trailer on a later
    refactor must not attribute the BIC — exactly the protocol's
    "later AI refactors do not attribute" clause, violated by R.

11. **R's blanket parent-absence errors.** Beyond w004, spot-verified R
    factual errors on same-sha records: w000/w001 (P's ppa=true is trivially or
    grep-verified correct — w001's parent lacks `xor_accumulator`;
    R said false). In the 8 reverse cases (P=false/R=true, e.g. w193, w185) the
    disagreement is line-scoped and unresolved; those need re-checking, not
    auto-adoption of either side.

## 4. Verdict-mix observations I disagree with framing as-is

12. **`audit-summary.json`'s "NOT_AI 174" is not a human-authorship census.**
    It includes withdrawn/rejected advisories that should be FALSE_POSITIVE
    (protocol line 18-20: NOT_AI means a real vulnerability with human
    authorship). Per current evidence the corrected mix is roughly:
    AI_ROOT_CAUSE 9–10, NOT_AI ~165, FALSE_POSITIVE ~7–9, BLOCKED 1, EVIDENCE_GAP 0–2
    — pending re-adjudication of the 56 uncompared reviews and the 58 ppa
    contradictions.

13. **"Ledger provenance" handling is right; its framing is not.** I agree the
    campaign did not write the ledger and the external-mutation proof trail is
    adequate. But `verify_campaign.py` silently downgrades a hard gate to a
    provenance note via an `else` branch — the exit code and `"record_gates":
    "PASS"` line can mask a failed hash gate in future rounds. Make the
    downgrade explicit in the printed JSON (e.g. `"ledger_gate": "DOWNGRADED"`),
    or exit nonzero.

## Bottom line

- Adopt R on: w007, w113 (contested), w008, w026, w023, w048, w049, w066, w067,
  w068, w078, w087, w119, w121, w122, w129, w194, w082.
- Keep P on: w004, w116, and the 10 AI_ROOT_CAUSE cases R corroborates
  (w000, w006, w012, w013, w035, w036, w037, w040, w041, w141).
- Re-check before landing: the 8 reverse-direction ppa conflicts, all 56
  uncompared reviews, and the 7 cases with no review at all
  (w088, w157, w165, w187, w195, w198, w199).
- Fix the tooling: primary prompt verdict set, gate coverage for review files,
  marker_state comparison in every comparator, and line-scoped ppa semantics.

Verification basis of the adopt list (full disclosure): git-verified by this
recheck — w007, w008, w023, w026, w068, w122, plus w004 (kept-P) and w116
(kept-P). Evidence-read but NOT git-verified here — w048, w049, w066, w067,
w078, w087, w119, w129 (R's evidence was coherent; treat as provisional until
each BIC is re-run against the clone), and w121/w194/w082 (verdict follows from
CVE.org/GitHub disposition facts, no git needed). w113 stays contested.
