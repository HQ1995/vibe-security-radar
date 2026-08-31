# Independent rereview of four authoritative gate failures

Date: 2026-08-31  
Scope: GHSA-P7MM-R948-4Q3Q, GHSA-VFGX-5Q85-58Q3,
GHSA-8X4M-QW58-3PCX, and GHSA-8G98-M4J9-QWW5.

## Method and decision boundary

This rereview applies `docs/AUDIT-PROTOCOL.md` from the vulnerability outward:
identify the advisory mechanism first, then find the smallest surviving object
that first wrote it, verify the immediate parent, judge AI only on that object,
verify a direct reversal, and finally verify release containment. A nearby
AI-marked commit, a refactor, a release-note commit, or a version string is not
a substitute for any of those edges.

Evidence was limited to first-party GitHub advisories and immutable objects in
the local upstream clones. Existing shard reports were used only as leads; the
commits, parents, diffs, ancestry, and tags described below were replayed from
Git. No ledger, database, publisher, generated data, or test files were
modified.

Gate order in this report is: `identity`, `ai_hunk`, `topology`, `but_for`,
`fix_reversal`, `release`, `uniqueness`.

## Result

| Advisory | Authoritative old result | Independent result | Does new evidence supersede the old FAIL? | Disposition |
|---|---|---|---|---|
| GHSA-P7MM-R948-4Q3Q | `PASS, PASS, PASS, PASS, FAIL, PASS, PASS` | `PASS` on all seven gates, using the real code fix rather than a release-note commit | **Yes** | `READY_TO_BACKFILL` |
| GHSA-VFGX-5Q85-58Q3 | `PASS, PASS, PASS, FAIL, PASS, PASS, FAIL` | `PASS` on all seven gates, after replacing the refactor with the true first writer | **Yes** | `READY_TO_BACKFILL` |
| GHSA-8X4M-QW58-3PCX | `PASS, PASS, PASS, PASS, PASS, FAIL, PASS` on an unrelated header chain | The asserted chain fails advisory identity, but-for, reversal, and release; the real ten-branch payment case is not decomposed | **No**; the new aggregate-fix lead does not rehabilitate the asserted chain | `EVIDENCE_GAP / HOLD` |
| GHSA-8G98-M4J9-QWW5 | `PASS, FAIL, PASS, PASS, NARROW, NARROW, PASS` | Jules-bot authorship makes `ai_hunk=PASS`; PayPal-only reversal is `PASS`, but aggregate reversal is `NARROW` and release is `UNKNOWN` | **Only the old AI-marker FAIL is superseded** | `EVIDENCE_GAP / HOLD` |

## GHSA-P7MM-R948-4Q3Q

First-party source:
[paperclip advisory](https://github.com/paperclipai/paperclip/security/advisories/GHSA-p7mm-r948-4q3q).

### Candidate, parent, fix, and release

- Candidate/BIC:
  [`abadd469bc85e9fa5137ff5ffce433f1c2db2c0b`](https://github.com/paperclipai/paperclip/commit/abadd469bc85e9fa5137ff5ffce433f1c2db2c0b).
- Immediate parent: `8c830eae70a14723749828f0ce5d9ae435270e9c`.
- Direct fix:
  [`32a9165ddf6308f3b46eae0653b6f583e502e538`](https://github.com/paperclipai/paperclip/commit/32a9165ddf6308f3b46eae0653b6f583e502e538).
- The candidate is single-parent and carries a `Co-Authored-By: Claude Opus
  4.6` trailer. Its parent has the shared `decidedByUserId` validator but no
  reachable approval route/service that writes the supplied identity.
- The candidate adds approve/reject/request-revision paths that pass the
  request body's `decidedByUserId` into the authoritative approval and budget
  attribution records. The fix removes that client field and instead derives
  the identity from `req.actor.userId`.
- The previously recorded `b8725c52...` is release-note/version material, not
  the code reversal. It therefore cannot support `fix_reversal`.
- `canary/v2026.415.0-canary.0`, `.1`, and `.2` contain the BIC but not the
  fix. `canary/v2026.415.0-canary.3` contains the fix, and stable
  `v2026.416.0` contains both.

### Seven gates

| Gate | Verdict | Direct basis |
|---|---|---|
| identity | PASS | The advisory's client-controlled decision-attribution flow is the flow added by `abadd469...`. |
| ai_hunk | PASS | The BIC itself has the Claude Opus 4.6 co-author trailer; the judgment does not rely on a later carrier. |
| topology | PASS | `abadd469...` is a verifiable single-parent commit; parent `8c830eae...` lacks the reachable route/service sink. |
| but_for | PASS | Removing the BIC removes the first reachable body-to-authoritative-attribution path. |
| fix_reversal | PASS | `32a9165...` removes the body-controlled identity and derives it from the authenticated actor on all three decision actions. |
| release | PASS | Canary `.0`-`.2` witness candidate-without-fix; `.3` witnesses candidate-plus-fix. |
| uniqueness | PASS | Other advisories sharing the large origin/fix commits have different entry points, sinks, and mechanisms; this scope is only approval decision attribution. |

### Conclusion

The direct fix evidence **supersedes** the old `fix_reversal=FAIL`.
This case is `READY_TO_BACKFILL` with candidate `abadd469...`, parent
`8c830eae...`, minimum fix `32a9165...`, and seven `PASS` gates.

The protocol classification is direct AI root cause (`AI_ROOT_CAUSE` /
`AI_DIRECT_ROOT`): the AI-marked candidate first writes the reachable
vulnerable flow. The current 26-row draft still retains `status=AI_CODE_FLAWED`
for this row, which conflicts with the shard's own field correction and should
be corrected before that draft is applied.

Primary local replay: `.ai-slop/state/repos/paperclipai_paperclip` and
`/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/04/GHSA-p7mm-r948-4q3q/GHSA-p7mm-r948-4q3q.json`.

## GHSA-VFGX-5Q85-58Q3

First-party source:
[openssl_encrypt advisory](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-vfgx-5q85-58q3).

### Candidate, parent, carrier, fix, and release

- True candidate/BIC:
  [`5f60678d7da2eef6404355ecdad28148cb1a37f7`](https://github.com/jahlives/openssl_encrypt/commit/5f60678d7da2eef6404355ecdad28148cb1a37f7).
- Immediate parent: `f2e251b13b9b23c0509762e2c99c1735fa9b7544`.
- Later carrier/refactor: `990c09c4f33649b9120d4995c385151652bc5cd9`.
- Direct fix:
  [`09e96e090417d34d2f533f6810d3cd4f77810101`](https://github.com/jahlives/openssl_encrypt/commit/09e96e090417d34d2f533f6810d3cd4f77810101).
- The BIC creates the steganography implementation, including the
  password-derived seed and `random.seed`/`random.sample`/`random.shuffle`
  selection paths. Its parent has no steganography implementation. The BIC
  itself says it was generated with Claude Code and has a Claude co-author
  marker.
- The old candidate `990c09c4...` is not an origin: its parent already has the
  weak PRNG paths, and rename-aware diff/history shows that commit moving them
  into the plugin layout.
- The fix replaces the weak password-seeded Mersenne-Twister selection paths
  with deterministic HMAC-SHA256-derived shuffles.
- Tags `v1.3.0` and `v1.3.6` contain the true BIC but not the fix. `v1.4.0`
  contains both.

### Seven gates

| Gate | Verdict | Direct basis |
|---|---|---|
| identity | PASS | The first-party advisory names the same password-seeded non-cryptographic steganography selection implemented by the BIC. |
| ai_hunk | PASS | The true first writer—not merely the refactor—contains direct Claude Code generation/co-author evidence. |
| topology | PASS | `5f60678...` is single-parent; `f2e251b...` has no steganography code. |
| but_for | PASS | The weak PRNG mechanism first appears in `5f60678...`; `990c09c4...` only carries it. |
| fix_reversal | PASS | `09e96e09...` replaces each relevant weak shuffle with the cryptographic deterministic construction. |
| release | PASS | `v1.3.0`/`v1.3.6` are vulnerable witnesses; `v1.4.0` is the fixed witness. |
| uniqueness | PASS | No competing published class uses this true BIC for the same mechanism; treating the later carrier as an origin was the source of the old duplication concern. |

### Conclusion

The corrected origin **supersedes** both the old `but_for=FAIL` and
`uniqueness=FAIL`. This case is `READY_TO_BACKFILL` with candidate
`5f60678...`, parent `f2e251b...`, carrier `990c09c4...`, minimum fix
`09e96e09...`, and seven `PASS` gates.

Primary local replay: `.ai-slop/state/repos/jahlives_openssl_encrypt` and
`/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-vfgx-5q85-58q3/GHSA-vfgx-5q85-58q3.json`.

## GHSA-8X4M-QW58-3PCX

First-party source:
[mppx advisory](https://github.com/wevm/mppx/security/advisories/GHSA-8x4m-qw58-3pcx).

The advisory is an aggregate of ten `tempo/charge` and `tempo/session`
payment-bypass, replay, and griefing branches, reported fixed in `0.4.8`.

### The asserted chain is unrelated

- Asserted candidate:
  [`2566a1a0c2d9b8b2a80a4afbc1a95c9f6b7e56ba`](https://github.com/wevm/mppx/commit/2566a1a0c2d9b8b2a80a4afbc1a95c9f6b7e56ba),
  parent `3ddb115483d537574652faae60a0ca94591bc69b`.
- Asserted fix:
  [`81ba76322f7d77af9e9466fcf6788a296d6fc543`](https://github.com/wevm/mppx/commit/81ba76322f7d77af9e9466fcf6788a296d6fc543).
- The candidate adds an optional challenge description and raw header
  serialization. The alleged fix escapes non-Latin-1 header content. Neither
  commit reaches a `tempo/charge` or `tempo/session` payment invariant.
- `mppx@0.4.7`, `mppx@0.4.8`, and `mppx@0.8.17` contain the asserted candidate
  but not `81ba763...`; the alleged fix first appears on the later `0.8.18`
  line. This is release evidence for a different vulnerability, not the
  advisory's fixed-0.4.8 claim.

For the currently asserted pair, the defensible gate vector is:

| Gate | Verdict | Direct basis |
|---|---|---|
| identity | FAIL | The code path is header-description serialization, not charge/session payment validation. |
| ai_hunk | UNKNOWN | Any AI signal on this unrelated commit is non-probative for the advisory mechanism. |
| topology | UNKNOWN | The commit parent is known, but no advisory-relevant BIC/parent boundary has been established. |
| but_for | FAIL | Removing the description/header commit does not remove any of the advisory's payment branches. |
| fix_reversal | FAIL | Escaping header content does not reverse a charge/session invariant. |
| release | FAIL | The alleged fix is absent from the advisory's fixed `0.4.8` line and belongs to a later release line. |
| uniqueness | UNKNOWN | Uniqueness cannot be tested until the ten real branches have origins. |

### Correct aggregate-fix lead, but no closed causal chain

- `mppx@0.4.7` resolves to `0742b760...` and lacks
  [`1092d43eeecefd4a8e675d4b753103e3eca105a8`](https://github.com/wevm/mppx/commit/1092d43eeecefd4a8e675d4b753103e3eca105a8).
- `mppx@0.4.8` resolves exactly to `1092d43...`; its immediate parent is
  `539c5607a2b0abedf1125bc9f1604d4b16d85ef7`.
- That aggregate commit changes 32 files and directly repairs advisory-named
  areas, including charge-hash replay state, transfer-log verification,
  sender-signature checks, route and channel binding, settled/finalized state,
  method fallback, and force-close persistence. It is therefore a strong
  aggregate fix lead and a valid fixed-release identity witness.
- It is not proof of a single atomic origin or minimum fix edge. For example,
  human commit `d9fc55b5f90946fc41d14bc0e8ab8c084dde8532` (parent
  `f39d1337...`) first creates the charge implementation containing unguarded
  hash/transaction flows and has no AI marker. Other relevant historical
  boundaries are mixed: `c28944e6...`, `22895da7...`, and `881bd18c...` have
  Amp markers, while `39264982...`, `11c0422c...`, and `b6057dc...` are human
  commits. The advisory cannot truthfully be assigned one AI root without
  branch decomposition.

The corrected advisory shell can retain `identity=PASS` for the
advisory/repository and can record that `0.4.8` contains the aggregate fix.
It cannot promote the causal gates: `ai_hunk`, `topology`, `but_for`, and
`uniqueness` remain `UNKNOWN`; `fix_reversal` is at most `NARROW` until the
aggregate is mapped to atomic branches. The tag comparison alone is not a
complete release-containment gate because the corresponding branch BICs are
not yet assigned.

### Conclusion

The new `1092d43...` evidence does **not** supersede the old failure in a way
that permits publication. It proves that the existing chain is misbound and
identifies the real aggregate fix, but not the ten BIC/parent/AI/fix chains.
Disposition: `EVIDENCE_GAP / HOLD`.

Required correction is to clear `2566a1a...`, `81ba763...`, their hunks,
mechanism, and AI attribution from this advisory record. Required research is
a ten-branch decomposition with, for each branch, its smallest BIC, immediate
parent absence, BIC-local AI marker or human authorship, direct reversal, and
vulnerable/fixed artifact containment. Until then, no asserted unknown may be
promoted to `PASS`.

Primary local replay: `.ai-slop/state/repos/wevm_mppx` and
`/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-8x4m-qw58-3pcx/GHSA-8x4m-qw58-3pcx.json`.

## GHSA-8G98-M4J9-QWW5

First-party source:
[Taylored advisory](https://github.com/tailot/taylored/security/advisories/GHSA-8g98-m4j9-qww5).

The advisory bundles four flaws: path traversal through `patchId`, missing
PayPal webhook validation, purchase-token replay, and insufficient PBKDF2
iterations. It names 7.0.5 through 7.0.7 as affected and 7.0.8 as fixed.

### Candidate, parent, fixes, and scope

- Candidate/BIC:
  [`c139c021f68a09d22c2af88641b61c00f67f2af4`](https://github.com/tailot/taylored/commit/c139c021f68a09d22c2af88641b61c00f67f2af4).
- Immediate parent: `610281a664bd4e8c8d0c7052116bedaea5c8a4c6`.
- First partial/PayPal fix:
  [`57b7634391959dbbdb39b387ac4dc68157cd58a1`](https://github.com/tailot/taylored/commit/57b7634391959dbbdb39b387ac4dc68157cd58a1).
- Later path-containment fix: `5e5a80b5ffd0b6fccf7bdc2d8793e8b01cb83844`.
- The parent has no backend template. The candidate creates it with raw
  `req.body` trust at `/paypal/webhook`, unsanitized `patchId` filesystem
  joins, a reusable purchase token, and a 100,000-iteration PBKDF2 setting.
- The candidate is directly authored by `google-labs-jules[bot]`. That is
  BIC-local AI evidence and conclusively replaces the old assertion that no
  AI marker exists.
- Jules-bot commit `57b763...`, whose parent is the candidate, adds PayPal
  signature verification, a serial token-replay guard, and 310,000 PBKDF2
  iterations. It does not add path containment. Human commit `5e5a80b...`
  subsequently adds `path.basename` containment. Separately, the serial
  SELECT-then-UPDATE replay guard is the subject of later incomplete-
  remediation advisory GHSA-VH5J-5FHQ-9XWG, so `57b763...` must not be
  described as a complete reversal of every bundled branch.

### Seven gates by permissible scope

| Gate | PayPal-webhook-only scope | Full four-flaw aggregate | Direct basis |
|---|---|---|---|
| identity | PASS | PASS | The BIC creates the advisory-named backend mechanisms; the PayPal endpoint is exact. |
| ai_hunk | PASS | PASS | The BIC itself is authored by the Jules bot. |
| topology | PASS | PASS | `c139c021...` is single-parent and `610281a...` lacks the backend template. |
| but_for | PASS | PASS | Removing the BIC removes the newly created vulnerable backend mechanisms. |
| fix_reversal | PASS | NARROW | `57b763...` directly adds PayPal verification; aggregate closure also needs `5e5a80b...` and cannot overstate the replay guard. |
| release | UNKNOWN | UNKNOWN | The named vulnerable/fixed artifacts are unavailable and no matching Git tags survive. |
| uniqueness | PASS | PASS | PayPal validation is distinct from the later replay-race advisory; the shared fix-to-candidate relationship is recorded rather than treated as a duplicate origin. |

### Release evidence gap

- The clone has no 7.0.5, 7.0.7, or 7.0.8 tags; its sole surviving release
  tag is 8.2.4 and already contains all of the commits above.
- The named npm 7.0.5-7.0.8 artifacts were not recoverable locally or from the
  recorded registry evidence. Packument timestamps are not artifacts.
- Repository `package.json` versions are not a substitute and conflict with
  the advisory boundary: the candidate and `57b763...` show 7.0.6, while
  `5e5a80b...` shows 7.0.9.

### Conclusion

The direct Jules authorship **supersedes** the old `ai_hunk=FAIL`. It does not
close the case. A PayPal-only record has six `PASS` gates and
`release=UNKNOWN`; the full advisory has `fix_reversal=NARROW` and
`release=UNKNOWN`. Disposition remains `EVIDENCE_GAP / HOLD` until vulnerable
and fixed published artifacts are recovered. If the case remains aggregate,
its minimum fix set must include at least `57b763...` and `5e5a80b...`, with
the replay limitation stated explicitly.

Primary local replay used immutable objects in
`.ai-slop/state/repos/tailot_taylored` and
`/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2025/06/GHSA-8g98-m4j9-qww5/GHSA-8g98-m4j9-qww5.json`.
The clone's worktree had pre-existing deletions and was not restored or
modified.

## Integration boundary

No new patch draft is attached:

- P7MM and VFGX already appear in the existing 26-row
  `ready-ledger-patches.jsonl`; duplicating them would create competing patch
  rows. P7MM's retained status/classification mismatch must be fixed before
  application.
- 8X4M and 8G98 do not have seven closed gates, so a publication patch would
  overstate the evidence. Their required actions are respectively
  wrong-chain removal plus branch research, and continued release-artifact
  recovery with an explicit PayPal-only or aggregate scope.

This report is an evidence verdict only; it does not apply any ledger or site
change.
