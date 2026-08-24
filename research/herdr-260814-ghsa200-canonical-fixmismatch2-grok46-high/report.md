# Hostile fix-topology audit: Faraday and OpenClaw named-SHA mismatch

**KEEP_WITH_CORRECTION for both rows.** Packet delta 0. Canonical strict count remains 84 at commit `ca034f064fd696201c81baae7392c14f0d501d2b`.

This packet independently replays public git for two canonical84 rows that source-tier QA left UNKNOWN for `exact_fix_topology_unresolved`. Canonical84 ledger and accepted-packet evidence are routing only. First-party object pins are the already-hashed repository advisory facts from source-tier QA. Worker PASS is a proposal. This packet does not admit rows, does not mutate canonical84, and does not support a greater-than-200 claim.

Conservation: assigned=2, reviewed=2, unreviewed=0, KEEP=0, KEEP_WITH_CORRECTION=2, REJECT=0, UNKNOWN=0, BLOCKED=0.

Repo advisory named-SHA inequality alone is not failure. Both rows have a valid named or atomic fix closure inside the fixed release, and all seven gates close. Canonical `minimum_fix_set` is semantically the atomic closer on both rows. Canonical `fixed_release.sha` / `vulnerable_release.sha` copy that closer or candidate instead of the tag peel or npm `gitHead`. Proposed corrections are those release fields only. `carrier_set` stays empty.

## A) GHSA-5RV5-XJ5J-3484 lostisland/faraday

Class: `AI_INCOMPLETE_REMEDIATION`. Candidate `a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc`. Canonical closer / `minimum_fix_set` `3f1280c69e93297d574e85a2d462d05ebadf1d09`. Repo advisory SHA `a01039c948d3e9e41e03d152aed7244f0fb4d5ca`.

`a6d3a3a0` is a single-parent GitHub merge-from-fork. Associated pulls are empty. The commit extends `Faraday::Connection#build_exclusive_url` so strings starting with `//` are prefixed with `./`, names GHSA-33mh-2634-fwr2, and carries `Co-authored-by: Claude Opus 4.6`. Parent `b23f710d` has the older `start_with?` relative-URL guard without the `//` case. Candidate tests cover String `//evil.com` only.

`3f1280c6` is a later single-parent merge-from-fork by Tomoya Yamashita with no AI marker. It inserts `url = url.to_s if url.respond_to?(:host)` immediately before that same AI guard and adds a URI-object spec. Associated pulls are empty.

`a01039c` is PR #1667, a docs-only commit. It does not touch `lib/faraday/connection.rb`. That blob at `a01039c` equals the candidate blob `b58b6175...`, not the closer blob `23fcda3e...`. The first-party advisory quotes this SHA as the repository HEAD used to reproduce Faraday 2.14.1, not as a closer. It is an ancestor of `3f1280c6` and of tag `v2.14.2`, and it is not an ancestor of `v2.14.1`.

Tag peels: `v2.14.1` = `16cbd38ef252d25dedf416a4d2510a2f3db10c87` ("Version bump to 2.14.1"), first parent `a6d3a3a0`. `v2.14.2` = `2ecd5e05388303087c3f6872ef7f98f260e9560f` ("Update version.rb"), first parent `3f1280c6`. Mechanism blobs: `v2.14.1` equals candidate (incomplete `//` string guard, no `to_s`). `v2.14.2` equals closer (`to_s` plus `//` guard). RubyGems 2.14.1 / 2.14.2 are not yanked. Gem `connection.rb` sha256 values match those git blobs. GitHub releases are published, not draft, not prerelease.

Canonical `minimum_fix_set` `[3f1280c6]` is the atomic same-mechanism reversal. Canonical `fixed_release.sha` / `vulnerable_release.sha` are mislabeled as that closer and the candidate. Proposed release SHAs are the tag peels. Distinct from GHSA-33mh, which is absent from canonical84 strict 84.

## B) GHSA-68V4-HMWV-F43H openclaw/openclaw

Class: `AI_DIRECT_ROOT`. Candidate `06dd9b8ed864eb6668d42c497f0615e743da483a`. Canonical closer / `minimum_fix_set` `f865a5455ee03924a444e9ba0f1c4743d8fb6566`. Repo advisory SHA `e704323ff388ed21f6963f9b8e0b1b8dfaaabc5f`.

`06dd9b8e` is a single-parent commit. Associated pulls are empty. Parent `downloadToFile` has no redirect follow. The candidate adds `maxRedirects` and `resolve(downloadToFile(redirectUrl, dest, headers, maxRedirects - 1))`, forwarding the original headers, with `Generated with Claude Code` and `Co-Authored-By: Claude`.

`f865a545` is the GitHub squash of PR #58156. It is the first same-sink reversal: same-origin redirects keep headers; cross-origin redirects call `retainSafeHeadersForCrossOriginRedirectHeaders`. PR head `8ecd9650` is not an ancestor of the squash or of `v2026.3.31`. `fetch-guard.ts` blobs match; `store.ts` on the squash adds an unrelated `resolveMediaBufferPath` helper after the header-drop hunk. The landing closer on released history is the squash. Squash title `[AI]` is PR branding on the closer, not origin.

`e704323` is the GitHub squash of PR #58224. It is a descendant of `f865a545`. Parent `store.ts` blob equals the `f865a545` blob. The named commit extracts the same helper into `src/infra/net/redirect-headers.ts` and retargets the import. That is a same-mechanism descendant, not a missing closer.

npm `2026.3.28` `gitHead` `f9b1079283a8ee25a7cee77c8f8225d5c813bc30` equals lightweight-tag peel `v2026.3.28`. That tree still forwards original headers on media redirects and does not contain `f865a545`. npm `2026.3.31` `gitHead` `213a704b71f4996dc82a583288ee53785215f627` equals peel `v2026.3.31`, contains both `f865a545` and `e704323`, and `store.ts` blob equals `e704323`. Tarball sha256 `fd709a39...` / `638a14e0...`. Dist JS for 2026.3.28 still has `downloadToFile(redirectUrl, dest, headers, maxRedirects - 1)` without retain-safe. Dist JS for 2026.3.31 ships `redirect-headers` and retain-safe on the store path. GitHub releases are published. Repo advisory has no CVE alias; canonical alias CVE-2026-41345 is routing only and does not fail identity.

Canonical `minimum_fix_set` `[f865a545]` is the minimum atomic reversal. Canonical release SHAs copy closer/candidate instead of npm `gitHead`. Proposed release SHAs are `f9b10792` / `213a704b`. Distinct GHSA and mechanism from Faraday.

## Gates

### GHSA-5RV5-XJ5J-3484

1. `identity_gate`: PASS. First-party repo advisory HTTP 200, not withdrawn, alias CVE-2026-33637, rubygems faraday `<= 2.14.1` patched `2.14.2`.
2. `ai_hunk_gate`: PASS. Atomic `a6d3a3a0` authors the `//` string guard with an explicit Claude Opus 4.6 marker.
3. `topology_gate`: PASS. Single-parent fork-merge. No public PR members. No authorship transfer. Candidate is first parent of the `v2.14.1` bump. Closer is first parent of the `v2.14.2` bump.
4. `but_for_gate` / `remediation_patch_delta_gate`: PASS. The AI change is an explicit security attempt on the GHSA-33mh boundary. 2.14.1 ships that attempt without `to_s`. The GHSA names the URI-object residual. `3f1280c6` amends the same guard. Not an untouched sibling.
5. `fix_reversal_gate`: PASS. `3f1280c6` stringify-coerces URI objects before the AI `start_with?` guard.
6. `release_gate`: PASS. Tag and gem 2.14.1 contain the incomplete guard. Tag and gem 2.14.2 contain `to_s`.
7. `uniqueness_gate`: PASS. Already this GHSA in canonical84. Distinct from GHSA-33mh.

### GHSA-68V4-HMWV-F43H

1. `identity_gate`: PASS. First-party repo advisory HTTP 200, not withdrawn, npm openclaw `<=2026.3.28` patched `>= 2026.3.31`. Empty repo-advisory aliases do not fail identity.
2. `ai_hunk_gate`: PASS. Atomic `06dd9b8e` authors the exact redirect-follow-with-headers hunk.
3. `topology_gate`: PASS. Candidate is a direct commit. `f865a545` is the squash landing closer. `e704323` is a later descendant. PR member `8ecd9650` is not transferred onto origin and is not the counted closer.
4. `but_for_gate`: PASS. Parent has no redirect follow. Removing the AI hunk removes header forwarding on media redirects.
5. `fix_reversal_gate`: PASS. `f865a545` drops unsafe headers on cross-origin. `e704323` keeps that reversal after a helper extract. Both are in 2026.3.31.
6. `release_gate`: PASS. npm 2026.3.28 contains the candidate contribution without the drop. npm 2026.3.31 contains the drop. `gitHead` equals tag peels.
7. `uniqueness_gate`: PASS. Already this GHSA in canonical84. Distinct Faraday mechanism. Exact GHSA+mechanism is not duplicated in this packet.

`remediation_patch_delta_gate` is NOT_APPLICABLE on OpenClaw.

## Claim boundary

No worker proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound after a later rebuild. This packet does not rebuild canonical84. Publication and more-than-200 stay HOLD.
