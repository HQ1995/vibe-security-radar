# No-pre-fix PR-member recall repair (canonical94)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Recall repair, not admission.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
Inventory result SHA256 `cecb1710279e2df3e7635d3ee91e0d85f25e453528ea18aa29299380ff6dbbd9` replay `87ddd177ec134e756666d5f0ff0bb662038a8f91a87a1482e5ce9ed35d5672c7`.
Completed slice result hashes pinned as they exist: ranks61-120 `81b693b0307fe800212cd7d1c00d0f1a06e59e1d86f6a576a214cf99789d5838`; 121-180 `9d8df176577c9d306cc30c26bc930d868d3c1a179b1657ecaf6591b8953d500b`; 181-240 `e067fffaf6399ee7785acb1d4fdfa0e0294de586e38df5e715a0d6ba7fb71963`; 241-300 `d4622d2dcd51dff5d0a117a2edb2ab20cb1c37e70e6dbd1a36604f2c4147f6b5`; 301-360 `66e3d203f3176b6ea2fedd5517848707a09a9e3c24689e0d69f9a0a60ab8123c`; 361-420 `d5dc14623c032dc3d93fc88e7ee7058923ba514e065f094d1fb1b368269f8216`; 601-660 `a8c7917affd92e1f17867dcb97f2cda8dbef330c332aac0f4204d42aee8bc61c`. Missing intermediate slices were not waited on.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only.

## Exclusive bucket reconstruction

Nextqueue-era inventory cutoff is source result.json mtime, skipping the nextqueue packet itself and skip-parts work/notes/pages/snapshot/clones/cache/tmp/node_modules.
Inventory: files=584 cases.jsonl=267 adjudications=34 result.json=283 rows=12504 distinct explicit terminal verdict identities=7932.
Exclusive walk on 34389 reviewed identities: withdrawn, no GitHub repository, no exact same-repo 40-hex commit, published before 2025-05-01, terminal verdict, no first-party repo-advisory URL, then local clone and fix object.
Structural remainder 803 = no_local_clone 5 + fix_object_missing 38 + object-present 760.
Object-present 760 minus nextqueue ai_hit 31 (queued 20 + leftover 11) = exclusive no_pre_fix_ai_marker 729.
no_pre_fix_ids sha256 `ffeceb62c6fa243e5865020390ba5de297d01ce3fc0ac1c9754f46d2739c63b1`.
Canonical94 overlap with the 729: 0. Later terminal identities after the nextqueue freeze overlapping the 729: 0. Remaining 729.

Selector: remaining 729 ranked by first-party repo-advisory, exact local fix object, fix-path overlap (code files in closer > 0 before non-code), low commit fanout (fewer closer paths), then uppercase GHSA ID. Inspect final ranks 721-729. Keyword-only rank was not used.
Selection identity: reconstructed ranks 1-720 (720 IDs) are disjoint from this 9-ID slice (overlap 0). Uniqueness of the 9 IDs holds.

## Inspected ranks 721-729 (9)

721. GHSA-V245-V573-V5VM repo=markdown-it/linkify-it fix=105e5d77f7d1 np=1 files=2 code=0 members=0 REJECT_ROUTING
722. GHSA-3MQ9-XHGQ-R7GJ repo=lf-edge/eve fix=5fef4d92e758 np=1 files=3 code=0 members=0 REJECT_ROUTING
723. GHSA-4C4V-42HC-72P6 repo=lf-edge/eve fix=5fef4d92e758 np=1 files=3 code=0 members=0 REJECT_ROUTING
724. GHSA-HX9W-F2W9-9G96 repo=hexpm/hex_core fix=cdf726095bca np=1 files=3 code=0 members=0 REJECT_ROUTING
725. GHSA-M2HG-WJQ3-28WQ repo=kaspernj/form-data-objectizer fix=7c54b99408e6 np=1 files=3 code=0 members=2 REJECT_ROUTING
726. GHSA-XWC6-V6G8-PW2H repo=ImageMagick/ImageMagick fix=8d4c67a90ae4 np=1 files=3 code=0 members=0 REJECT_ROUTING
727. GHSA-7PPR-R889-MCF2 repo=http4s/blaze fix=173e8ca820a0 np=1 files=4 code=0 members=0 REJECT_ROUTING
728. GHSA-M95P-425X-X889 repo=LFDT-Lockness/cggmp21 fix=60e0ada5291e np=1 files=4 code=0 members=2 REJECT_ROUTING
729. GHSA-QJ3P-XC97-XW74 repo=MetaMask/metamask-sdk fix=baa185c6cfa9 np=1 files=5 code=0 members=0 REJECT_ROUTING

ROUTE 0. REJECT_ROUTING 9. Did not pad. This tail is the non-code remainder of the rank key (n_code_files=0 for all nine). Tests, docs, and lockfiles are not mechanism-relevant. Shared SHA, AI-on-fix, carrier trailer transfer, filename overlap, and sibling path did not qualify.

## Conservation

bucket 729 = inspected through rank 729 plus unreviewed remainder 0. Equation 729=729+0. Holds.
assigned 9 = reviewed REJECT_ROUTING 9 + unreviewed 0. Equation 9=9+0. Holds.
excluded canonical94 from 729 = 0. later terminals from 729 = 0.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0. Did not pad.

Stop. No ledger, site, or other-directory edits. No commit or push. No PASS.
