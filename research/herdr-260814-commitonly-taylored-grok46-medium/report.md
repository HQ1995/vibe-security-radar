# Hostile commit-only review: taylored GHSA-8G98 and GHSA-VH5J

Verdict first: two causal-only PASS proposals, zero countable admissions. Assigned 2, reviewed 2, unreviewed 0. Equation 2=2+0. Canonical88 stays 88. Publication stays HOLD. Shared SHA 57b76343 is inspected in opposite roles and is not a dedupe. Prior packet gates were routing only.

Identity sources are the github-reviewed OSV objects (sha256 f9f1f975... and 7b4729eb...) plus published repo advisories. Local clone `/home/hanqing/.cache/cve-analyzer/repos/tailot_taylored` HEAD `05da9137527cb7be236bb8e63f1c3b0dffcc6b2a`, sole tag `8.2.4`.

## GHSA-8G98-M4J9-QWW5 PASS_PROPOSAL (release UNKNOWN)

Identity PASS. GitHub-reviewed `GHSA-8g98-m4j9-qww5`, no CVE, not withdrawn. Repo `tailot/taylored`. npm `taylored` introduced `7.0.5` fixed `7.0.8`. Official commit reference is `57b76343`. The advisory text bundles four issues. This row scopes only Missing PayPal Webhook Validation.

AI hunk PASS. Jules `c139c021` is single-parent from `610281a6`. Author `google-labs-jules[bot]`. Parent has no `templates/backend-in-a-box/index.js`. Candidate blob `0dd0853c` adds `app.post('/paypal/webhook')` with `const webhookEvent = req.body`.

Topology PASS. Origin is a first-parent ancestor of closer `57b76343` and of tag `8.2.4`. n_parents=1. No squash transfer.

But-for PASS. Removing `c139c021` removes the unverified webhook. Path traversal, PBKDF2, and token replay are out of scope.

Fix reversal PASS. Jules `57b76343` (parent `c139c021`, n_parents=1, blob `8a5317f9`) adds `verifyAndGetWebhookEvent`. Human `5e5a80b5` later rewrites verify to axios `verify-webhook-signature` and adds `path.basename` sanitization. That human commit is not the paypal minimum fix.

Uniqueness PASS versus canonical88 and versus GHSA-VH5J. Fingerprints differ. Shared SHA `57b76343` is the closer here.

Release UNKNOWN. `tag --contains c139c021 --no-contains 57b76343` is empty. Only tag `8.2.4` contains both. npm `versions` currently has only `8.2.4`. Time keys including `7.0.5` and `7.0.8` are not recovered tarballs.

## GHSA-VH5J-5FHQ-9XWG PASS_PROPOSAL (release UNKNOWN)

Identity PASS independently. GitHub-reviewed `GHSA-vh5j-5fhq-9xwg`, no CVE, not withdrawn. Repo advisory names `/get-patch` purchase-token replay race. Official closer `fdf67a6f`. OSV `introduced: 0` is not causal proof.

AI hunk PASS as incomplete remediation. Jules `57b76343` is an explicit security attempt: adds `token_used_at` and SELECT-then-UPDATE. Parent `c139c021` `/get-patch` has no such column.

Topology PASS. Candidate is a first-parent ancestor of human closer `fdf67a6f`. n_parents=1. Human `5e5a80b5` is a rewrite carrier of the same residual, not an authorship transfer.

But-for PASS under the patch-delta rule. The named residual is concurrent SELECT-then-UPDATE on the AI-added `token_used_at` guard. Rollback would reopen unlimited reuse; that broader hole is not this GHSA. Human `5e5a80b5` blob `472511e7` matches the advisory `SELECT id, token_used_at` quote more closely than Jules blob `8a5317f9`, but it preserves Jules's incomplete consume.

Fix reversal PASS. Human `fdf67a6f` (parent `f4d21045`, n_parents=1, blob `4cc255d7`) replaces the two-statement sequence with `UPDATE ... AND token_used_at IS NULL`. Advisory `RETURNING` text is not required; `this.changes` is the same consume.

Uniqueness PASS. Distinct from the paypal-body row. Same SHA inspected, not merged.

Release UNKNOWN. `tag --contains 57b76343 --no-contains fdf67a6f` is empty. Commit `d6f5477` has package.json `8.1.2` and contains the candidate without the closer, but it is not a tag. Incomplete-remediation countability also needs a recovered released artifact with the attempted guard and without the closer. That artifact was not recovered. Do not infer PASS from `8.2.4`.

## Conservation and claim boundary

Assigned 2 = reviewed 2 + unreviewed 0. PASS 0. PASS_PROPOSAL 2. Countable 0. Canonical ledger not edited. No commit or push. No padding. Worker PASS is proposal only.
