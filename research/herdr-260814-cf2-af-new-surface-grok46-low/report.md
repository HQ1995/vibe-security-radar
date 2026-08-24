# CF2 A-F new-surface: 0 PASS_PROPOSAL

Verdict first: **0 PASS_PROPOSAL**. Assigned and reviewed **6** hard added-file matches. Cap 40 was not filled because the hard-match pool exhausted at 6. Worker PASS is proposal only. Canonical strict count 85 is untouched. Greater-than-200 remains unsupported.

## Method

Universe: unreviewed A-F dispositions `REVIEW_QUEUE_FILE_OVERLAP` and `UNKNOWN_AI_PRESENT_NO_EXACT_MECHANISM_LINK` from `herdr-260813-ghsa200-commitfirst-af`, excluding terminal REJECT/BLOCKED/exact-SHA closer reviews, canonical85 IDs, foundation IDs, and CVE aliases as counting units.

Hard rank: atomic (single parent, no `(#N)` squash subject) AI-marked commits that are ancestors of a first-party advisory fix SHA, are not themselves advisory-listed closers, and added (`git diff-tree --diff-filter=A`) a path overlapping the fix file set. Filename overlap without an added path is routing only.

Probed 196 file-overlap rows that already had commit_refs. Status split 196=6 HIT + 190 NO_ADDED_OVERLAP.

## Cases

### GHSA-HR7P-WG7R-HG9M REJECT (release_gate)

Identity PASS. AI hunk PASS: `68af171d` atomic Co-Authored-By Claude Opus 4.8 added `src/core/module_policy.py` with default denylist `env.get`. Topology PASS: 1 parent, not a squash carrier, ancestor of closer `d5f89d71`. Patch-delta but_for PASS and fix_reversal PASS: closer adds `is_env_var_allowed()` to that same AI-added file and gates `${env.VAR}` in `variable_resolver.py`. Advisory names the residual interpolation bypass of the `env.get` denylist.

**release_gate FAIL**: `v2.26.4` peeled `50d0d327` does not contain `68af171d`. First later tags `v2.26.6` peeled `2471c6e7` and `v2.26.7` peeled `9449def3` already contain both `68af171d` and `d5f89d71`. No git tag is a vulnerable artifact with the attempted rem and without the closure. Missing separable release is not PASS.

### GHSA-2956-977X-2W3R REJECT

Same candidate `68af171d`. Arbitrary file write via `image.download` is a sibling hole: `download.py` was added by unmarked `02a060f9`. Closer confines writes in download.py and does not amend the AI denylist for `image.*`. Not incomplete-remediation of the env/capability gate. Same release failure.

### GHSA-7R9J-R86Q-7G45 REJECT

Added overlap is `oauth2.spec.ts`. Closer `5b0fe83d` is merge PR 18236 (not origin). `34e8b665` hit on query.ts is upgrade-test log formatting.

### GHSA-65W6-PF7X-5G85 REJECT

Basename `index.ts` routing: AI `f9536974` added `src/email/index.ts`. `src/endpoints/index.ts` added by unmarked `0ab2990b`.

### GHSA-QGC4-8P88-4W7M REJECT

Copilot commit added `node_modules`. Closer is merge PR 4 rate limiter.

### GHSA-FCRW-F7GG-6G9F REJECT

Added overlap is `utils.spec.ts`. Squash `(#16681)` cannot transfer authorship.

## Conservation

3167 source dispositions = 769 terminal excluded + 2398 unreviewed. Hard probe 196 = 6 + 190. Reviewed 6 = 6 REJECT. PASS_PROPOSAL=0. Did not pad.

## Claim boundary

This packet does not change L0/canonical85. Worker PASS is proposal only and none are emitted.
