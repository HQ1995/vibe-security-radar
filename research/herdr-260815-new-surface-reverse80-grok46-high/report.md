# Reverse new-surface and scoped-contributor census (canonical94)

**Status: TERMINAL.** Worker PASS is a proposal only. This packet emits none. Canonical strict count remains **94**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0. This packet does not call a PASS. ROUTE only.

## Why this census

Reverse mining starts from exact atomic AI-marked commits in repositories that already have a first-party GHSA, then asks whether that commit added a new endpoint, caller, plugin, transport, file format, or privileged path which invoked an older vulnerable primitive, and whether the later GHSA closer changes that new surface or its necessary shared helper. An old helper alone is allowed only if removing the AI-added surface removes the advisory path.

## Freeze

Frozen github/advisory-database HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 github-reviewed tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` (34389 reviewed identities) at read-only `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database`. CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`, summary SHA256 `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b`, status HOLD, strict 94.

Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only.

## Universe and exclusions

GitHub-reviewed identities: **34389**. Conservation:

34389 = 910 withdrawn + 18845 no first-party repository advisory + 5910 no same-repo 40-hex closer + 8724 eligible.

8724 = 62 canonical94 + 5992 later terminals + 0 extra named-surface freeze (all 86 named-surface identities were already inside the terminal union) + 2670 remaining.

Named surface packets frozen and excluded: ai-dependency-surface20 (0 remaining), ai-route-surface20 (GHSA-73HC-M4HX-79PJ), sharedhelper-newcaller20 (10), new-surface-unseen20 (5), cf2-af (6), cf2-gj (40), cf2-oz (12), cf4-b4-surface (12). Union 86, already covered by terminals.

Inventory of 260813-260815 top-level cases/adjudication/result artifacts, skipping work/pages/snapshot/clones/cache/tmp: files=708 cases.jsonl=329 adjudications=34 result.json=345 rows=16225. Distinct explicit terminal verdict identities=10889. Shared SHA is not identity dedupe. Files newer than the pinned inventory cutoff are ignored.

Eligible first-party remainder after canonical94, later terminals, and named surface freeze: **2670**. Overlap with canonical94: 0. Assigned from that remainder: 22 strongest AI-ancestry rows. Did not pad to 80.

## Identity and clones

Every assigned row has a public repository advisory at the exact owner/repo/security/advisories/GHSA URL and at least one same-repo 40-hex commit reference. Read-only local clone map size 6990. Remaining with clone: 1309. mega skip 397. no_local_clone 964. closer object missing 49. closer object present 1260. Full-ancestry AI-grep hits among those 1260: **22**. No AI-grep 1238.

Equation: 2670 = 397 mega + 964 no_clone + 49 closer_missing + 1238 no_AI_ancestry + 22 assigned.
Assigned equation: 22=22+0.

## Routing

ROUTE 22. Deep inspect 22 of a max 80. Exact reverse new-surface hits where the closer edits the AI-added surface or its necessary shared helper: **0**. Did not pad. AI-on-fix, filename overlap, shared SHA, PR branding, squash-carrier trailer, OSV introduced, and community prose were not used as causal evidence.

Reject-class split of the 22 ROUTE rows: MATCHER_FAIL 15, NO_CLOSER_SURFACE_OVERLAP 6, NO_NEW_SURFACE 1. source_matcher true 7. New surface kinds 0. Closer overlap on an added surface 0.

Shared candidate SHA 6f91e2c540d917867e9c139842a2c2a117a26c79 (keycloak i18n Update messages_pt_BR.properties) is reused across 10 Keycloak GHSAs. Shared SHA is routing only.

## Per identity (all ROUTE, never PASS)

1. GHSA-2CWW-FGMG-4JQC keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `d9f0c84b7975`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
2. GHSA-4VC8-PG5C-VG4X keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `f9708037383a`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.
3. GHSA-5PXH-89CX-4668 OpenMage/magento-lts. ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Atomic candidate `b1c2dca6328b` parent `7e5a1414b77f` closer `d307e5bf7572`. subject TinyMCE: potential fix for code scanning alert: Inefficient regular expression (#4491). added_surface none. gates identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.
4. GHSA-69FP-7C8P-CRJR keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `2191cc26ae6d`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
5. GHSA-7PQ6-V88G-WF3W getsentry/sentry. ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Atomic candidate `0458514d5584` parent `68b9c135a314` closer `6db508f7949d`. subject ref(releases): Create two new functions (#81423). added_surface none. gates identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
6. GHSA-8QW9-GF7W-42X5 streamlit/streamlit. ROUTE. class MATCHER_FAIL. Atomic candidate `2b2886eebc30` parent `675e5e6f1d6e` closer `bd0a8996c4c7`. subject Vendor `pympler.asizeof` (#7193). added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=UNKNOWN uniqueness=PASS.
7. GHSA-92CP-5422-2MW7 redis/go-redis. ROUTE. class NO_NEW_SURFACE. Atomic candidate `ebe11d06ca95` parent `5314a571322c` closer `d236865b0cfa`. subject feat: Enable CI for Redis CE 8.0 (#3274). added_surface none. gates identity=PASS ai_hunk=PASS topology=FAIL but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.
8. GHSA-C25H-C27Q-5QPV keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `0d0530046b9c`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
9. GHSA-CQ42-VHV7-XR7P keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `f9708037383a`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.
10. GHSA-F3GH-529W-V32X zitadel/zitadel. ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Atomic candidate `1ee7a1ab7ca3` parent `48ffc902cc90` closer `d9d8339813f1`. subject feat(eventstore): accept transaction in push (#8945). added_surface none. gates identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
11. GHSA-F4V7-3MWW-9GC2 keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `7a76858fe4aa`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
12. GHSA-FWHR-88QX-H9G7 rails/rails. ROUTE. class MATCHER_FAIL. Atomic candidate `74264f44675f` parent `02c1b7ac48eb` closer `35858f1d9d57`. subject Improve password length validation in ActiveModel::SecurePassword for BCrypt compatibility. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
13. GHSA-G6QQ-C9F9-2772 keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `071032a108bd`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
14. GHSA-HMG4-WWM5-P999 umbraco/Umbraco-CMS. ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Atomic candidate `669c585ac4c7` parent `16d8ad8115c3` closer `559c6c9f312d`. subject Validate client IDs before applying them (#17426). added_surface none. gates identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
15. GHSA-HW58-3793-42GG keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `99ca24c83272`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
16. GHSA-JJHX-JHVP-74WQ rails/rails. ROUTE. class MATCHER_FAIL. Atomic candidate `74264f44675f` parent `02c1b7ac48eb` closer `b4d3bfb5ed8a`. subject Improve password length validation in ActiveModel::SecurePassword for BCrypt compatibility. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
17. GHSA-M6Q9-P373-G5Q8 keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `9d9817e15a07`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
18. GHSA-PRJP-H48F-JGF6 rails/rails. ROUTE. class MATCHER_FAIL. Atomic candidate `74264f44675f` parent `02c1b7ac48eb` closer `e215bf3360e6`. subject Improve password length validation in ActiveModel::SecurePassword for BCrypt compatibility. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
19. GHSA-Q62R-8PPJ-XVF4 umbraco/Umbraco-CMS. ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Atomic candidate `26907f202fb1` parent `85176d1bf6bf` closer `06a2a500b358`. subject hotfix: context provider should not destroy instance (#18864). added_surface none. gates identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=FAIL uniqueness=PASS.
20. GHSA-RXFF-VR5R-8CJ5 streamlit/streamlit. ROUTE. class MATCHER_FAIL. Atomic candidate `2b2886eebc30` parent `675e5e6f1d6e` closer `3a639859cfdf`. subject Vendor `pympler.asizeof` (#7193). added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=UNKNOWN uniqueness=PASS.
21. GHSA-W3G8-R9GW-QRH8 keycloak/keycloak. ROUTE. class MATCHER_FAIL. Atomic candidate `6f91e2c540d9` parent `720c5c6576cc` closer `93b2a7327b25`. subject Update messages_pt_BR.properties. added_surface none. gates identity=PASS ai_hunk=FAIL topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.
22. GHSA-WV8V-RMW2-25WC umbraco/Umbraco-CMS. ROUTE. class NO_CLOSER_SURFACE_OVERLAP. Atomic candidate `669c585ac4c7` parent `16d8ad8115c3` closer `d4f8754f9338`. subject Validate client IDs before applying them (#17426). added_surface none. gates identity=PASS ai_hunk=PASS topology=PASS but_for=FAIL fix_reversal=FAIL release=PASS uniqueness=PASS.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported. Canonical94 remains 94 HOLD.

## Replay

`zsh autoresearch/herdr-260815-new-surface-reverse80-grok46-high/replay.zsh`

Two consecutive runs must be byte-identical with empty stderr.
