# Advisory identity delta after f2c6ab3 (canonical94)

Verdict first: **0 ROUTE**. **0 PASS**. Inspected **1** novel identity (`GHSA-9Q54-F358-3FQF`). Bound not padded. Packet delta **0**. Canonical94 stays **94 HOLD**. Publication and greater-than-200 remain **HOLD**. A new advisory or routing match is never causality. Worker PASS is proposal only; this packet emits none.

## Freeze

Prior official github/advisory-database HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 github-reviewed tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` (34389 reviewed identities) unreviewed tree `8cdc0a0b741cc5df87e9f2b7fa582debca410fdb` (323477 unreviewed identities) at read-only `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. Shared caches were not mutated. HEAD after work remains `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`.

Current public origin/main was fetched blob:none into a throwaway bare clone with read-only object alternates: `fb4768f4075a98a9356f35655d29c7aeb76d83a9` committer 2026-08-15T05:08:08+00:00 subject Publish GHSA-6qwm-5fm9-cvjx. github-reviewed tree `f637e23cef5f0afbc36d8b6162b2b276d1c47bc2`. unreviewed tree `c651ac2a7e2c1a536d7c99ee2a203ee68ecc6876`. Range `f2c6ab3..fb4768f` is 27 commits. CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`, summary SHA256 `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b`, status HOLD, strict 94.

Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`. No credentials. No retained clone. No commit or push.

## Identity delta (trees, not prose)

Reviewed identities: 34389 frozen, 34406 current. Added **17**. Removed **0**. Modified **16**. Unchanged 34373. Conservation `34389 + 17 - 0 = 34406`. Exact sorted added-ID sha256 `e0a7bf058d950fa2ddf7aacddf9648600787d55319b6a304b5b178b01ff9a019`. Exact sorted modified-ID sha256 `543b9605ce53a2423468715ccfd19d4cfc4dfab8f647b823eb584cfdd54abff9`. Exact sorted added-or-modified sha256 `a2af3f349a5c05e8a0abb5b0a02e83b59ce9c5414b2a10db218b273ac0020406`. Removed sha256 is empty `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Unreviewed identities: 323477 frozen, 323651 current. Added 179. Removed 5. Modified 64. Conservation `323477 + 179 - 5 = 323651`. Unreviewed rows are outside admission (not github-reviewed first-party repository advisories).

Added reviewed IDs: GHSA-29RF-F4VV-PVQ6, GHSA-2FQW-7C6R-2CQ6, GHSA-2J9V-P4XJ-CJW2, GHSA-49MQ-FC6Q-3H46, GHSA-4X9G-VW65-VVF9, GHSA-5FPJ-28RV-84R7, GHSA-76PC-MQXP-3RQ5, GHSA-7J4W-X8X8-5MVG, GHSA-8G5P-JXP9-457C, GHSA-8RW6-P7M8-63JP, GHSA-9HGC-G3W5-67CM, GHSA-9Q54-F358-3FQF, GHSA-FPMH-VX4H-XC33, GHSA-H84G-69H7-MW6V, GHSA-V5M8-5455-QW2X, GHSA-VF2H-7X3W-97FR, GHSA-XGHW-P77P-3R7X.

Modified reviewed IDs: GHSA-355H-QMC2-WPWF, GHSA-36JR-MH4H-2G58, GHSA-4C8G-83QW-93J6, GHSA-63VM-454H-VHHQ, GHSA-6QWM-5FM9-CVJX, GHSA-934W-87QH-QR26, GHSA-9QRM-48QF-R2RW, GHSA-C9CV-MQ2M-PPP3, GHSA-CX4M-2P55-RW7J, GHSA-HHPQ-7WG4-36JM, GHSA-P6JF-79J3-33F3, GHSA-QCXQ-75WR-5CM8, GHSA-RMJ7-2VXQ-3G9F, GHSA-VGWF-H737-FF37, GHSA-W22P-4X9F-486V, GHSA-XVCM-6775-5M9R.

## Exclusion and admission

Inventory of 260813-260815 top-level cases/adjudication/result artifacts, skipping work/notes/pages/snapshot/clones/cache/tmp: files=722 cases.jsonl=335 adjudications=34 result.json=353 rows=17816. Distinct explicit terminal verdict identities=12468 sha256 `f9316dd85a737a88318bd864716d2caf3ee7f5fa3aa0308267eabc426679b383`. Canonical94 strict 94 is a subset of that union. Shared SHA is not identity dedupe. Files newer than the pinned inventory cutoff are ignored. Replay re-hashes the frozen snapshot and does not walk this owned directory.

Reviewed added-or-modified 33 = 32 explicit terminals + 1 remaining. Canonical94 overlap on the delta: GHSA-76PC-MQXP-3RQ5, GHSA-8RW6-P7M8-63JP. Those 32 terminals were not reopened.

Among the 33: withdrawn 0, no first-party repo-advisory URL 11, first-party with exact same-repo 40-hex 14, first-party without 40-hex 8. All 14 same-repo-40hex rows are already terminals or canonical94. Admission search for active first-party plus same-repository 40-hex therefore yields **0** net-new identities.

The one remaining identity after exclusion is GHSA-9Q54-F358-3FQF (first-party aws/s2n-quic, no advisory 40-hex). It was inspected because it is novel. It is not ROUTE.

## Novel identity: GHSA-9Q54-F358-3FQF REJECT_ROUTING

identity_gate PASS. github-reviewed GHSA-9q54-f358-3fqf aliases CVE-2026-10740, not withdrawn, blob `24b8d65f4317f6d6d7b24292cb193702c621b6fe` at `advisories/github-reviewed/2026/08/GHSA-9q54-f358-3fqf/GHSA-9q54-f358-3fqf.json`. Official GitHub object type=reviewed, repository_advisory_url on aws/s2n-quic, first-party URL `https://github.com/aws/s2n-quic/security/advisories/GHSA-9q54-f358-3fqf`. Affected crates.io s2n-quic introduced 0 fixed 1.82.0, last_known_affected <= 1.81.0. Zero 40-hex strings in the advisory JSON. References are the repo advisory, NVD, AWS bulletin 2026-042, package URL, and tag v1.82.0.

ai_hunk_gate FAIL. No advisory-listed closer. First-party tag compare v1.81.0 (`8986c9f5c785db101aa8a26ff403c8ed5d03cb42`) to v1.82.0 (`4438384b247e5cf8615892cfe1ac1c4dc75a2119`) has seven atomic commits. The CRYPTO-buffer reversal is reconstructed closer `6c90fa94bca4b65d1cfb41eb47fcdcd60ef61c5a` (subject Merge commit from fork, author Boquan Fang, n_parents=1, parent `9ea237a8b571a263bafc62e42902df186775496e`). source_matcher on that commit is empty. File history of `quic/s2n-quic-transport/src/space/crypto_stream.rs` before the closer is Cameron Bytheway / Wesley Rosenblum human commits; the unbounded buffer is marked by the 2020 citation commit `a92a3534401e1dc6ffec057dc220a0e0033d78ea` (`TODO we need to limit the buffer size here`), matcher empty. Canvas Claude trailer `4b5b4b2b2f803dfafda7b564577f20cf0ee9024b` matches coauthor_trailer-v4 but edits only dc/s2n-quic-dc handshake log paths, not crypto_stream.rs. That hit is routing, not origin.

topology_gate PASS on the reconstructed closer (n_parents=1). GitHub "Merge commit from fork" does not create a two-parent commit here. Authorship is not transferred from the unrelated Claude DC commit. Missing listed SHA still fails admission.

but_for_gate FAIL. Removing 6c90fa94 restores the 2020 human TODO hole. The advisory path is the missing RFC 9000 section 7.5 cap, not an AI-added endpoint.

fix_reversal_gate FAIL for counting: no advisory 40-hex. Reconstructing the tag-range closer does add `MAX_CRYPTO_BUFFER_SIZE` (128 KiB) and `CRYPTO_BUFFER_EXCEEDED` on `on_crypto_frame`. That reconstruction is not an admission SHA.

release_gate PASS on published transport crates that contain the hunk, FAIL as a seven-gate bundle because the named advisory package s2n-quic-1.81.0/1.82.0 tarballs do not contain crypto_stream.rs. crates.io s2n-quic-transport 0.81.0 sha256 `d1ddd739c1776770dd2ab0b33da1cf372a395500252ae5250c08e2d6bf51b38f` has the TODO and no MAX_CRYPTO_BUFFER_SIZE. 0.82.0 sha256 `3b82fca53ce1734cc1d1dca96cc9ceb65ed528f27cb43b7de865215b6cf17908` has MAX_CRYPTO_BUFFER_SIZE. Git tag v1.82.0 contains 6c90fa94. Git tag v1.81.0 does not. A fatal AI-hunk FAIL already blocks ROUTE.

uniqueness_gate PASS versus canonical94 strict 94. GHSA-9Q54 is absent from the 94.

ROUTE requires all seven gates plausible and no fatal FAIL. ai_hunk FAIL and but_for FAIL are fatal. Never PASS. Never ROUTE.

## Conservation

33 assigned-or-excluded reviewed AM = 32 terminals + 1 inspected. Equation `33=32+1`. Assigned 1 = 1 reviewed + 0 unreviewed. Equation `1=1+0`. Eligible after exclusion and same-repo-40hex admission: 0. Inspected the 1 novel remainder. Did not pad. cve_aliases_counted=false. packet_delta=0. ROUTE=0. PASS=0.

Unreviewed conservation holds by tree counts and is not an admission denominator.

## Claim boundary

This packet does not admit cases and does not KEEP any ROUTE. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported. Canonical94 remains 94 HOLD.

## Replay

`zsh autoresearch/herdr-260815-advisory-delta-0815-grok46-high/replay.zsh`

Two consecutive runs must be byte-identical with empty stderr.
