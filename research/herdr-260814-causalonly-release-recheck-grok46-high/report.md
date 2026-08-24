# Causal-only release recheck as of 2026-08-14

TERMINAL. Assigned 4, reviewed 4, unreviewed 0. Equation 4=4+0.
NARROW 4. PASS 0. PASS_PROPOSAL 0. REJECT 0. UNKNOWN 0. Countable 0.
Canonical91 stays 91 HOLD. Packet delta 0. Worker PASS is proposal only and this packet emits none.

This packet independently rebuilt the seven gates for GHSA-8G98-M4J9-QWW5, GHSA-VH5J-5FHQ-9XWG, GHSA-H2V8-4C3F-VQGV, and GHSA-G8MR-85JM-7XHM from first-party advisory objects, local git, current Git tags, frozen GitHub release projections, and live npm/crates/PyPI checksums. Prior causal packets were routing only. The exact candidate/fix hypothesis did not change on any row. Same-first-tag, commit-only, or missing exact vulnerable/fixed containment stays NARROW. Advisory publication is not a release.

## GHSA-8G98-M4J9-QWW5 NARROW

Repository tailot/taylored. Class AI_DIRECT_ROOT. Causal six PASS. release_gate NARROW. Candidate/fix unchanged: c139c021 / 57b76343.

1. identity_gate PASS. github-reviewed GHSA-8g98-m4j9-qww5 is unwithdrawn, has no CVE, names npm taylored introduced 7.0.5 fixed 7.0.8, and references 57b76343. This row scopes Missing PayPal Webhook Validation only.

2. ai_hunk_gate PASS. Jules atomic c139c021, parent 610281a6, n_parents=1. Parent lacks templates/backend-in-a-box/index.js. Candidate blob 0dd0853c adds app.post('/paypal/webhook') with const webhookEvent = req.body.

3. topology_gate PASS. First-parent ancestor of closer 57b76343 and of tag 8.2.4. No squash transfer.

4. but_for_gate PASS. Removing c139c021 removes the unverified webhook. Path traversal, PBKDF2, and token replay are out of scope.

5. fix_reversal_gate PASS. Jules 57b76343 (parent c139c021, blob 8a5317f9) adds verifyAndGetWebhookEvent. Human 5e5a80b5 later swaps SDK verify for axios verify-webhook-signature. That human commit is not the paypal minimum fix.

6. uniqueness_gate PASS versus canonical91 strict 91 and versus GHSA-VH5J. Shared SHA 57b76343 is the closer here.

7. release_gate NARROW. tag --contains c139c021 --no-contains 57b76343 is empty. Sole local tag 8.2.4 peel 05da9137 already contains both. Live npm versions dict is only 8.2.4 (metadata sha256 2084ea76..., tarball sha256 932bd516..., gitHead 9b3bb75b). Time keys 7.0.5/7.0.8 are not recovered tarballs. The 8.2.4 tarball already uses verify-webhook-signature, not req.body trust. Frozen GitHub releases projection is []. PyPI and crates.io 404. Missing exact vulnerable artifact.

## GHSA-VH5J-5FHQ-9XWG NARROW

Repository tailot/taylored. Class AI_INCOMPLETE_REMEDIATION. Causal six PASS. release_gate NARROW. Candidate/fix unchanged: 57b76343 / fdf67a6f.

1. identity_gate PASS independently. github-reviewed GHSA-vh5j-5fhq-9xwg names /get-patch purchase-token replay, last known affected <=8.1.2 patched 8.1.3, closer fdf67a6f. OSV introduced 0 is routing, not origin.

2. ai_hunk_gate PASS as incomplete remediation. Jules 57b76343 adds token_used_at and SELECT-then-UPDATE. Parent c139c021 /get-patch has no such column.

3. topology_gate PASS. Candidate is a first-parent ancestor of human closer fdf67a6f. Human 5e5a80b5 is a rewrite carrier, not authorship transfer.

4. but_for_gate PASS under the patch-delta rule. The named residual is concurrent SELECT-then-UPDATE on the AI-added token_used_at guard. Rollback would reopen unlimited reuse; that broader hole is not this GHSA.

5. fix_reversal_gate PASS. Human fdf67a6f (parent f4d21045, blob 4cc255d7) replaces the two-statement sequence with UPDATE ... AND token_used_at IS NULL.

6. uniqueness_gate PASS. Distinct from the paypal-body row. Same SHA inspected, not merged.

7. release_gate NARROW. tag --contains 57b76343 --no-contains fdf67a6f is empty. Commit d6f5477 package.json 8.1.2 contains the candidate without the closer, but it is not a tag. npm taylored@8.2.4 already contains token_used_at IS NULL. Incomplete-remediation countability needs a recovered released artifact with the attempted guard and without the closer. That artifact was not recovered.

## GHSA-H2V8-4C3F-VQGV NARROW

Repository brentmid/evernote-mcp-server. Class AI_DIRECT_ROOT. Causal six PASS. release_gate NARROW. Candidate/fix unchanged: e08547bc / 1e66c78c. Commit-only.

1. identity_gate PASS. Unreviewed GHSA-h2v8-4c3f-vqgv aliases CVE-2025-12489, names openBrowser command injection, and references 1e66c78c. No github-reviewed collision at advisory-database HEAD 39d888.

2. ai_hunk_gate PASS. Atomic e08547bc, parent 9f7c1b36. Parent has no auth.js. Candidate adds exec(`${command} "${url}"`). Marker: Generated with Claude Code and Co-Authored-By: Claude <noreply@anthropic.com>.

3. topology_gate PASS. n_parents=1. No carrier. Closer 1e66c78c is Claude-marked and is the reversal.

4. but_for_gate PASS. Removing the candidate removes auth.js. Reachable OAuth URL interpolation into exec.

5. fix_reversal_gate PASS. 1e66c78c switches exec interpolation to spawn(command, args).

6. uniqueness_gate PASS. Absent from canonical91 strict 91 and from the 212 source layer. Distinct from G8MR.

7. release_gate NARROW. Local tags=0. Live npm evernote-mcp-server is yasuhiroki 0.0.2/0.0.3 (tarball sha256 f3caba45... / 098f5a1d...; gitHead 406e50aa / 78ebf186; src/*.mjs; no auth.js). Scoped npm 404. PyPI 404. crates.io 404. Docker Hub 404 (sha256 80019e0e...). GitHub HTML/REST timed out; no new first-party artifact. package.json versions are not registry artifacts. Commit-only remains NARROW.

## GHSA-G8MR-85JM-7XHM NARROW

Repository vitest-dev/vitest. Class AI_INCOMPLETE_REMEDIATION. Causal six PASS. release_gate NARROW. Candidate/fix unchanged: af88b1f5 / 385a1aef. Same-first-tag.

Two mechanisms must not be mixed. The older ungated CDP hole is sendCdpEvent with no allowWrite flags (parent blob 7619c5f0, shipped as v3.2.4). The AI residual is Codex backport af88b1f5 adding allowWrite/allowExec/canWrite while leaving sendCdpEvent ungated, then closer 385a1aef adding isCdpAllowed/assertCdpAllowed.

1. identity_gate PASS. github-reviewed GHSA-g8mr-85jm-7xhm aliases CVE-2026-53633 and binds @vitest/browser 3.x last-known-affected <=3.2.4 patched 3.2.5. Advisory ranges are not containment.

2. ai_hunk_gate PASS. Atomic af88b1f5, parent 5a7d56e2, Co-authored-by: Codex <noreply@openai.com>. Parent has sendCdpEvent and zero allowWrite.

3. topology_gate PASS. n_parents=1. Fix parent is the candidate. Independent git log v3.2.4..v3.2.5 -- packages/browser/src/node/rpc.ts yields exactly those two commits. v4/v5 tags are not ancestors of this v3 candidate. Other-line closers stay out of this row.

4. but_for_gate PASS under incomplete-remediation patch-delta. The AI commit authors the allowWrite/allowExec boundary and omits CDP. v3.2.4 is not this residual.

5. fix_reversal_gate PASS. 385a1aef wraps sendCdpEvent and trackCdpEvent with assertCdpAllowed.

6. uniqueness_gate PASS. Absent from canonical91 strict 91. Ledger PRESERVE counted=false with release_gate NA. Distinct from the pre-AI CDP hole.

7. release_gate NARROW. First tag containing the candidate is v3.2.5, which already contains the closer. Tag v3.2.4 peel c666d149 rpc blob equals the parent (older ungated hole). Tag v3.2.5 peel 2cbad0a9 rpc blob equals the fix. Current tags v3.2.6/v3.2.7 remain gated (v3.2.7 rpc blob 86cc4e0b still has assertCdpAllowed). Frozen GitHub releases: v3.2.4 draft=false prerelease=false immutable=false target_commitish=main (moving branch is not containment); v3.2.5 draft=false prerelease=false immutable=true. Live npm @vitest/browser@3.2.4 sha256 a24c6ade... has sendCdpEvent and no allowWrite. @3.2.5 sha256 0f4e1678..., @3.2.6 sha256 c23deb91..., and @3.2.7 sha256 1ef783d2... already have allowWrite, canWrite, isCdpAllowed, and assertCdpAllowed. Same-first-tag.

## Uniqueness and claim boundary

None of the four IDs are in canonical91 strict_released_case_ids (91). 8G98, VH5J, and G8MR exist in the source layer as counted=false PRESERVE rows. H2V8 is absent from that source layer. Shared SHA 57b76343 is inspected in opposite roles and is not a duplicate. Prefer no seven-gate PASS over treating later 8.2.4, yasuhiroki npm, version strings, the older ungated CDP hole, or v3.2.5 (already the closer) as AI residual containment.

This packet did not edit canonical ledgers, did not commit or push, did not mutate shared caches, and did not store durable clones. Status TERMINAL.
