# Promisor recovery 54, shard A18

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **18**. Assigned 18. Hard hits 0. REJECT_CANDIDATE_EDGE 6. BLOCKED 9. NOT_SELECTED 3. UNKNOWN 0. NARROW 0. No padding. No backfill. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Frozen assignment is the exact first 18 IDs of the 54-row `no_resolvable_first_party_fix` set, in original-hits order. Source 54. This shard 18. Leftover 36. Reviewed 18. Unreviewed 0. Equation 18=9 BLOCKED + 6 REJECT_CANDIDATE_EDGE + 3 NOT_SELECTED. Overlap with canonical84 is 0. Overlap with prior selected.jsonl is 0. Did not pad. Did not backfill. Did not replace a failed row.

Old skip existed because partial/promisor clones lacked objects. Recovery used public git plus the same-GHSA repository security advisory HTML. The github/advisory-database object and OSV were routing only. GitHub API was not used. Parser expansion stopped. Zero PASS is the frozen outcome.

## Source tier

Claim-grade bind is the repository advisory HTML for the same GHSA, plus official git objects that page names. A global JSON commit ref is never claim-grade first-party causality. Missing fix, intro, or release evidence stays BLOCKED. A patched-version tag that does not overlap the advisory mechanism stays NOT_SELECTED with gates NOT_OPENED. A recovered fix-parent deleted hunk that blames to a human is REJECT_CANDIDATE_EDGE only. ghsa_wide_not_ai=false. whole_case_causal_reject=false. Residual recall remains open.

Temporary clones lived under `/home/hanqing/.cache/ai-slop-ghsa200/herdr-260814-ghsa200-promisor-recovery54-a18-grok46-xhigh` and are deleted before handoff. `/tmp` was not retained for clones. Replay does not clone.

## Outcomes

Six REJECT_CANDIDATE_EDGE rows, all edge-only. Named recovered facts: cloudreve oauth jwt `ed20843`; Grav admin security commit `99f65329` for the two XSS rows; nitro/ufo `5cd9e676`; shell-quote `4378a6e`; Linuxfabrik lib `6573ff9347e5`. Origins on those deleted hunks are human. No atomic AI hunk. Not GHSA-wide NOT-AI.

Nine BLOCKED rows. Apostrophe six plus Lemmy have repository HTML with no claim-grade fix SHA. mbhatt1/disclosures repository advisory is unavailable. Symfony HTML names `6b717aaac21b` which public git upload-pack rejects; the v6.4.40 tag is a Kernel.php version bump, not the OIDC handler.

Three NOT_SELECTED rows. Grav core `1.8.0-beta.27` is a release prepare commit. Steeltoe `4.2.0` is a Sonar workflow bump. Wings `v1.12.0` is websocket throttling, not activity-log SQLite batching. Those are mining misses, not causal negatives.

| n | ID | Repository | Verdict | Reason |
| --- | --- | --- | --- | --- |
| 1 | GHSA-97V6-998M-FP4G | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 2 | GHSA-9MRH-V2V3-XPFM | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 3 | GHSA-C276-FJ82-F2PQ | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 4 | GHSA-MJ7R-X3H3-7RMR | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 5 | GHSA-XHQ9-58FW-859P | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 6 | GHSA-RPR9-RXV7-X643 | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 7 | GHSA-VGJ4-345G-JCF8 | cloudreve/cloudreve | REJECT_CANDIDATE_EDGE | human_origin_on_fix_parent_deleted_hunk |
| 8 | GHSA-GQXX-248X-G29F | getgrav/grav | REJECT_CANDIDATE_EDGE | human_origin_on_fix_parent_deleted_hunk |
| 9 | GHSA-Q3QX-CP62-F6M7 | getgrav/grav | NOT_SELECTED | tag_commit_mechanism_mismatch |
| 10 | GHSA-RMW5-F87R-W988 | getgrav/grav | REJECT_CANDIDATE_EDGE | human_origin_on_fix_parent_deleted_hunk |
| 11 | GHSA-9PHM-9P8F-HW5M | nitrojs/nitro | REJECT_CANDIDATE_EDGE | human_origin_on_fix_parent_deleted_hunk |
| 12 | GHSA-W7JW-789Q-3M8P | ljharb/shell-quote | REJECT_CANDIDATE_EDGE | human_origin_on_fix_parent_deleted_hunk |
| 13 | GHSA-4JC5-G844-4X33 | Linuxfabrik/monitoring-plugins | REJECT_CANDIDATE_EDGE | human_origin_on_fix_parent_deleted_hunk |
| 14 | GHSA-G4PX-6QHM-HQJM | mbhatt1/disclosures | BLOCKED | repo_advisory_unavailable |
| 15 | GHSA-Q537-8FR5-CW35 | LemmyNet/lemmy | BLOCKED | missing_fix_or_ref |
| 16 | GHSA-227R-JM2G-7CP4 | SteeltoeOSS/security-advisories | NOT_SELECTED | tag_commit_mechanism_mismatch |
| 17 | GHSA-2497-GP99-2M74 | pterodactyl/wings | NOT_SELECTED | tag_commit_mechanism_mismatch |
| 18 | GHSA-29FC-P6C4-24CG | symfony/symfony | BLOCKED | fix_object_unresolved |

## Named recovered facts

GHSA-9PHM HTML names ufo `5cd9e676711af3f4e4b5398ddf6ca8d52c1c7e1f`. GHSA-4JC5 HTML names `6573ff9`, recovered as `6573ff9347e541200305d278d2663d2e54e052ff` on Linuxfabrik/lib. GHSA-W7JW patched tag parent is `4378a6e613db5948168684864e49b42b83134d2d`. GHSA-GQXX and GHSA-RMW5 share Grav admin `99f653296504f1d6408510dd2f6f20a45a26f9b0`. GHSA-VGJ4 recovered oauth jwt `ed20843dc3df20a25fcaf6b538647e11c4d68d87`. None of those origin hunks carry an AI trailer.

GHSA-9MRH HTML names introducing commit `49d0bb775161ce5ccf572752979ff727a31e51a5` (Robert Means, human). That is not a fix. Residual fix remains unresolved, so the row stays BLOCKED.

## Claim boundary

Worker PASS is a proposal only. This packet has zero PASS. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported. Seven gates were not all opened. An edge rejection is not GHSA-wide NOT-AI.
