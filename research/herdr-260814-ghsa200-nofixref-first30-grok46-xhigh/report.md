# No-fix-ref first30 recovery: 0 PASS proposals

Verdict first: **0 PASS**. Frozen selected count is **0**. Reviewed count is **0**. Assigned 30. Hard hits 0. BLOCKED 27. UNKNOWN 2. NOT_SELECTED 1. REJECT 0. NARROW 0. No padding. No backfill. Worker PASS is a proposal only and this packet emits none. packet_delta=0. Canonical strict count remains **84** at commit `ca034f064fd696201c81baae7392c14f0d501d2b`. Publication and more-than-200 remain **HOLD**. Causal admission is false.

## Conservation

Frozen pool: **5980**.
Source skip `no_first_party_fix_sha`: **2530**.
Cross-lane exclusion union: **230**.
Excluded inside this source population: **0**.
Eligible: **2530**.
Assigned: **30**.
Eligible leftover: **2500**.
Equations: 2530=0+2530; 2530=30+2500.
Did not pad. Did not backfill. Did not replace a failed row.

## Source tier

GitHub advisory-database global JSON is routing only. Negative control GHSA-47Q7-97XP-M272 shows that object can name a config-write summary while details and fix describe a hook-token bug. Every assigned row required the same-GHSA repository security advisory object or page, or an official same-repo artifact that advisory names. Title, details, range, and fix were checked for consistency. A global JSON commit ref is never a claim-grade first-party fix. Unavailable repo advisory is BLOCKED. Inconsistent title/details/range/fix is UNKNOWN. Missing claim-grade fix SHA or history is BLOCKED. Heuristic miss is NOT_SELECTED with gates NOT_OPENED, not causal REJECT.

## Outcomes

Repo advisory available and consistent, no claim-grade fix SHA: 21 BLOCKED (`missing_fix_or_ref`).
Repo advisory unavailable: 6 BLOCKED.
Title/details inconsistent: 1 UNKNOWN (GHSA-7R4P-VJF4-GXV4).
Range inconsistent: 1 UNKNOWN (GHSA-84XM-R438-86PX).
Claim-grade fix recovered then hard-prefilter miss: 1 NOT_SELECTED (GHSA-CR4V-6JM6-4963; repo advisory commit 83449669402080874b25ff1fa740649a9e6ea064; blamed squash carrier on `share/util/vendor_openjph.sh` did not map to an AI member hunk).

| n | ID | Repository | Verdict | Reason |
| --- | --- | --- | --- | --- |
| 1 | GHSA-HMGH-466J-FX4C | FlowiseAI/Flowise | BLOCKED | missing_fix_or_ref |
| 2 | GHSA-P3X5-MVMP-5F35 | canonical/lxd | BLOCKED | missing_fix_or_ref |
| 3 | GHSA-W2HG-2V4P-VMH6 | canonical/lxd | BLOCKED | missing_fix_or_ref |
| 4 | GHSA-XCH9-H8QW-85C7 | canonical/lxd | BLOCKED | missing_fix_or_ref |
| 5 | GHSA-VM2F-46XC-5JC3 | AstrBotDevs/AstrBot | BLOCKED | repo_advisory_unavailable |
| 6 | GHSA-54V4-4685-VWRJ | alextselegidis/easyappointments | BLOCKED | missing_fix_or_ref |
| 7 | GHSA-G4W6-C99W-4WH7 | browserstack/browserstack-local-nodejs | BLOCKED | repo_advisory_unavailable |
| 8 | GHSA-RVXJ-7F72-MHRX | EGroupware/egroupware | BLOCKED | missing_fix_or_ref |
| 9 | GHSA-5R63-Q8HG-P8QX | frangoteam/FUXA | BLOCKED | repo_advisory_unavailable |
| 10 | GHSA-6JR7-99PF-8VGF | backstage/backstage | BLOCKED | missing_fix_or_ref |
| 11 | GHSA-6QR9-G2XW-CW92 | dagu-org/dagu | BLOCKED | repo_advisory_unavailable |
| 12 | GHSA-7G56-FWXJ-CM23 | frangoteam/FUXA | BLOCKED | repo_advisory_unavailable |
| 13 | GHSA-4647-WPJQ-HH7F | Budibase/budibase | BLOCKED | missing_fix_or_ref |
| 14 | GHSA-4C96-W8V2-P28J | denoland/deno | BLOCKED | missing_fix_or_ref |
| 15 | GHSA-5F53-522J-J454 | FlowiseAI/Flowise | BLOCKED | missing_fix_or_ref |
| 16 | GHSA-5MG7-485Q-XM76 | BerriAI/litellm | BLOCKED | repo_advisory_unavailable |
| 17 | GHSA-7R4P-VJF4-GXV4 | caddyserver/caddy | UNKNOWN | title_details_inconsistent |
| 18 | GHSA-84XM-R438-86PX | envoyproxy/envoy | UNKNOWN | range_inconsistent |
| 19 | GHSA-928R-FM4V-MVRW | backstage/backstage | BLOCKED | missing_fix_or_ref |
| 20 | GHSA-97VP-PWQJ-46QC | BishopFox/sliver | BLOCKED | missing_fix_or_ref |
| 21 | GHSA-CR4V-6JM6-4963 | AcademySoftwareFoundation/openexr | NOT_SELECTED | no_hard_prefilter_hit |
| 22 | GHSA-HX52-CV84-JR5V | BishopFox/sliver | BLOCKED | missing_fix_or_ref |
| 23 | GHSA-J8G8-J7FC-43V6 | FlowiseAI/Flowise | BLOCKED | missing_fix_or_ref |
| 24 | GHSA-JC5M-WRP2-QQ38 | FlowiseAI/Flowise | BLOCKED | missing_fix_or_ref |
| 25 | GHSA-JFJG-VC52-WQVF | bentoml/BentoML | BLOCKED | missing_fix_or_ref |
| 26 | GHSA-MQ4R-H2GH-QV7X | FlowiseAI/Flowise | BLOCKED | missing_fix_or_ref |
| 27 | GHSA-MWXC-M426-3F78 | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 28 | GHSA-V9XM-FFX2-7H35 | apostrophecms/apostrophe | BLOCKED | missing_fix_or_ref |
| 29 | GHSA-W9F8-M526-H7FH | dani-garcia/vaultwarden | BLOCKED | missing_fix_or_ref |
| 30 | GHSA-WVHQ-WP8G-C7VQ | FlowiseAI/Flowise | BLOCKED | missing_fix_or_ref |

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 84. This packet does not rebuild canonical84 and does not support a greater-than-200 claim. Seven gates were not opened on non-hits. Canonical overlap is 0.
