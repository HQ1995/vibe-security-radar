# Unreviewed tail route (canonical94)

**Status: TERMINAL.** Worker PASS is a proposal only. This packet emits none. Canonical strict count remains **94**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0. This packet does not call a PASS.

## Freeze

Pinned frozen tail `autoresearch/herdr-260814-ghsa200-unreviewed-commitref20-grok46-medium/work/remaining-hits.jsonl` SHA256 `15e41133a618dc3ad869486133c76a67f139395bd4389f981fad35302bfd32dd` (513 unique `unprobed_after_cap` github-unreviewed rows). Parent freeze stopped after cap-20; this tail was never probed. Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`, summary SHA256 `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b`, status HOLD, strict 94.

Frozen github/advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc`. Current local github-reviewed cache HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` (34389 reviewed identities).

## Exclusions

First subtract canonical94 identities (overlap 0) and every explicit terminal identity in herdr/orchestrator 260813-260815 artifacts, skipping work/notes/pages/snapshot/clones/cache/tmp. Inventory files=844 cases.jsonl=315 adjudications=34 result.json=331 selected.jsonl=56 assignment.jsonl=108 rows=15203. Distinct explicit terminal verdict identities=8841. Selected-or-inspected identities=1885. Union=8844.

Excluded from the 513: **27**. Screened: **486**. Unknown: **0**.

Conservation: 513=27+486+0. Assigned 486=486+0.

## Identity

For each remaining GHSA, first-party identity requires a public repository advisory at the exact `owner/repo/security/advisories/GHSA` URL. A community github-unreviewed record alone fails. Live `gh api repos/<owner>/<repo>/security-advisories/<id>` returned Not Found for all 486. Public HTML HEAD returned 404 for 482 and a repo-rename 301 then 404 for 4 (toddr/YAML-Syck -> cpan-authors/YAML-Syck; allegroai/clearml -> clearml/clearml). Successor URLs also 404. Local github-reviewed tree contains 0 of 486. Control: `https://github.com/nuxt/nuxt/security/advisories/GHSA-wm8w-6qjm-cv43` HTML 200.

## Routing

ROUTE 0. Deep inspect 0 of a max 20. No row opened same-repo closer history because identity did not close. AI-on-fix, shared SHA, filename overlap, PR branding, squash trailer transfer, OSV introduced, and community prose were not used as causal evidence. source_matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4` was not applied to a closer hunk because no first-party identity remained.

All 486 screened rows are REJECT_ROUTING, reject_reason `community_unreviewed_no_first_party_repo_advisory`. proposed_pass=false.

## Claim boundary

Worker PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported. Canonical94 remains 94 HOLD.

## Replay

`zsh autoresearch/herdr-260815-unreviewed-tail-route-grok46-high/replay.zsh`

Two consecutive runs must be byte-identical with empty stderr.
