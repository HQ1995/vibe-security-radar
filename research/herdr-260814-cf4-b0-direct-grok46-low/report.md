# CF4 B0 direct-origin discovery

Verdict first: **0 PASS_PROPOSAL**. Frozen **12**. Reviewed **12**. **10 NARROW**. **2 REJECT**. Canonical strict count stays **88 HOLD**. Publication and greater-than-200 remain unsupported. Worker PASS is proposal only; this packet emits none.

## Sources

- github-reviewed universe: `/home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database` HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`
- unreviewed subtree only: `/home/hanqing/.cache/cve-analyzer/advisory-database` HEAD `39d8887723797efc1804585dd06585c9fd751226`
- Union by uppercase GHSA ID; f2c6 reviewed wins on 17 collisions. f2c6 has github-reviewed only (unreviewed count 0 there). Unreviewed cases were not dropped: 317316 files scanned, 53022 bucket 0, 54 first-party-eligible after exclusion, 2 frozen.

Pinned hashes: CONTRACT `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`; canonical88 ledger `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`; summary `81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921`.

## Universe and conservation

Bucket is integer sha256 of uppercase GHSA ID modulo 6 equals 0.

- reviewed files 34389; active 33479; withdrawn 910; bucket0 5511
- unreviewed files 317316; active 317315; withdrawn 1; bucket0 53022
- union bucket0 58516 after 17 reviewed-wins collisions
- structured-field exclusions 8104 IDs from lane-root case_id/ghsa_id/reviewed_case_ids/assigned_ids/strict_released_case_ids
- excluded-in-union 1297 (1290 reviewed + 7 unreviewed)
- first-party eligible after exclude 2481 (2427 reviewed + 54 unreviewed)
- local official commit objects 1094 (1071 reviewed + 23 unreviewed)
- AI in last 250 ancestors of an official closer 59
- non-fix source-file overlap 8; blame-level extra 2; then 2 unreviewed object rows to complete 12 without padding i18n-only mattermost rows

Assigned 12 = reviewed 12 + unreviewed 0. Freeze disjoint from canonical88 88 and from structured exclusions. Official GIT introduced hashes in this union: 0, treated as routing-only absence, not padding.

## Frozen twelve

| ID | Kind | Verdict | Why not PASS |
| --- | --- | --- | --- |
| GHSA-MP6X-97XJ-9X62 | reviewed | NARROW | Claude rctx rename d78d59babe; token-exchange closer is independent |
| GHSA-XPG8-8XPV-948P | reviewed | NARROW | Same SHA rename on web_hub.go; MFA websocket closer is catalintomai |
| GHSA-HVRP-RF83-W775 | reviewed | NARROW | Claude adds TasksCallCapability only; session scope is later 62137874 |
| GHSA-7HP7-4P35-3CX2 | reviewed | NARROW | Claude debug-flag on routes.py; cookie-jar isolation is feb7237d |
| GHSA-G35P-PX32-WHV6 | reviewed | NARROW | AI-on-fix closer; ancestor is OTLP translator |
| GHSA-R6QJ-894F-5HR2 | reviewed | NARROW | Claude errcheck whitespace on saml.go, not invite relay |
| GHSA-P9F5-H3RX-J5QW | reviewed | NARROW | Claude util-to-x rename; gogs v0.14.3 is not an ancestor of d3ca23f9 |
| GHSA-42H5-H8QH-VV9V | reviewed | NARROW | Claude webhook commit preserves prompt skip; closer is AI-on-fix |
| GHSA-9P64-JPC7-M2RP | reviewed | NARROW | Claude removes unused audit settings; FakeSetting closer is separate |
| GHSA-4HWQ-4CPM-8VMX | reviewed | REJECT | No recognized AI hunk on extract32 closer |
| GHSA-6RFW-VRJC-WFF7 | unreviewed | REJECT | No first-party GHSA advisory; closer has no AI; AI ancestor is tests |
| GHSA-PCH7-6GR4-GW9W | unreviewed | NARROW | Unreviewed identity; Claude PFCP resets are not NRF NFProfile |

## Claim boundary

Proposal count **0**. Canonical 88 untouched. No commit, push, tracked edits, durable clones, pages, or helper scripts. Caches read-only. Prefer zero PASS over one false positive.
