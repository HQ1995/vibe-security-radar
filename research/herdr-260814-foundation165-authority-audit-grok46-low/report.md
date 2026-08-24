# Foundation 165 authority census versus canonical85

## Verdict first

**canonical85 proven floor is 85.** Comparable payloads match for all 85 strict identities. **5 foundation rows are stale** because later terminal NARROW/REJECT/UNKNOWN supersedes stored CONFIRM/PASS. **GHSA-FRVJ-C5QP-XJ4W is pending independent hostile review and is not admitted.** Full JSON lines of foundation versus canonical85 STRICT_RELEASED_CASE rows are never byte-identical (different schemas). This packet does not claim PASS and does not call 165 zero-false-positive.

`zero_false_positive_claim_for_165` is **false**.

Pinned hashes:

- foundation.jsonl sha256 `0b9cd2daae23e33faf3f2ceed46bba4802e2f9b0ef9c739f0bce7e6f4a16f687`
- canonical85 ledger.jsonl sha256 `2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568`
- canonical85 summary.json sha256 `47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c`
- canonical85 negative_controls.json sha256 `c6bbdf661daf06de0d8de611167a842128c1fa3bfd01c19243dc771a41f0c9e0`

## Canonical85 proven floor

85 first-party GHSA identities in `STRICT_RELEASED_CASE` counted=true. All 85 are a subset of foundation unique ids. Negative-control REJECT identities are absent from the floor.

## Foundation rows comparable-payload identical to canonical85

85 rows. GHSA-8359-H9FX-J6V9 is in this set (gates and SHAs match) even though foundation stores verdict NARROW and counted=true; canonical85 stores STRICT counted=true. The stored verdict label is not used as a second counting unit.

## Noncanonical rows still causal-compatible but not strict

74 rows. Stored NARROW (or CONFIRM without a later hostile downgrade) remains compatible; not strict.
- `GHSA-2CM6-R77W-6G96` stored `NARROW`
- `GHSA-2HFG-4FH4-QP7F` stored `NARROW`
- `GHSA-2JRP-274C-JHV3` stored `NARROW`
- `GHSA-2M67-CXXQ-C3H8` stored `NARROW`
- `GHSA-2Q7J-2VHX-56G8` stored `NARROW`
- `GHSA-2QRV-RC5X-2G2H` stored `NARROW`
- `GHSA-2X93-H3HG-2XFP` stored `NARROW`
- `GHSA-3636-3MQQ-Q7X9` stored `NARROW`
- `GHSA-37MF-VQ43-5QP9` stored `NARROW`
- `GHSA-3CVX-236H-M9FJ` stored `NARROW`
- `GHSA-3FP5-V549-9V66` stored `NARROW`
- `GHSA-3J8Q-FWPJ-F8J5` stored `NARROW`
- `GHSA-42M6-XH7C-6XM4` stored `NARROW`
- `GHSA-4524-X6PC-RR9X` stored `NARROW`
- `GHSA-4PQR-V6C3-X77J` stored `NARROW`
- `GHSA-5GVR-V6QV-H5MM` stored `NARROW`
- `GHSA-5J8P-5RRJ-8WJG` stored `NARROW`
- `GHSA-5WP8-Q9MX-8JX8` stored `NARROW`
- `GHSA-5WQV-FHMR-PJGH` stored `NARROW`
- `GHSA-6C8G-7P36-R338` stored `NARROW`
- `GHSA-7C3W-FXGH-FRC7` stored `NARROW`
- `GHSA-7JX6-764P-FGG9` stored `NARROW`
- `GHSA-7X5Q-8F6H-RJRC` stored `NARROW`
- `GHSA-92VG-F4FQ-FXM9` stored `NARROW`
- `GHSA-9C3V-684M-579C` stored `NARROW`
- `GHSA-C339-W3CQ-2RJR` stored `NARROW`
- `GHSA-C4M7-2GWP-VW76` stored `NARROW`
- `GHSA-CW23-QWR7-C655` stored `NARROW`
- `GHSA-F2FQ-4RMP-9X8C` stored `NARROW`
- `GHSA-F38V-77QJ-H4JQ` stored `NARROW`
- `GHSA-F7FH-QG34-X2XH` stored `NARROW`
- `GHSA-FWPR-59HH-GR98` stored `NARROW`
- `GHSA-G353-MGV3-8PCJ` stored `NARROW`
- `GHSA-G5CG-8X5W-7JPM` stored `NARROW`
- `GHSA-G8MR-85JM-7XHM` stored `CONFIRM`
- `GHSA-GC24-PX2R-5QMF` stored `NARROW`
- `GHSA-H2VW-PH2C-JVWF` stored `NARROW`
- `GHSA-H4RQ-P45C-642R` stored `NARROW`
- `GHSA-HFF7-CCV5-52F8` stored `NARROW`
- `GHSA-HHFF-FJ5F-QG48` stored `NARROW`
- `GHSA-J4CX-JVQ7-79VM` stored `NARROW`
- `GHSA-JFV4-H8MC-JCP8` stored `NARROW`
- `GHSA-JJCJ-H3CM-P7X7` stored `NARROW`
- `GHSA-JX5R-P82P-2P8M` stored `NARROW`
- `GHSA-M63V-2G9W-2W6V` stored `CONFIRM`
- `GHSA-M649-24Q9-Q6R4` stored `NARROW`
- `GHSA-MFMP-Q643-VJ39` stored `NARROW`
- `GHSA-MGXW-V6RH-WCV6` stored `NARROW`
- `GHSA-P5RM-JG5C-8C77` stored `CONFIRM`
- `GHSA-PQGX-6WG3-GMVR` stored `NARROW`
- `GHSA-PQH8-P93P-2RX7` stored `NARROW`
- `GHSA-Q447-RJ3R-2CGH` stored `NARROW`
- `GHSA-Q5PP-GVJG-H7V4` stored `NARROW`
- `GHSA-Q6QF-4P5J-R25G` stored `NARROW`
- `GHSA-Q9J6-XCVX-PX63` stored `NARROW`
- `GHSA-QJ77-C3C8-9C3Q` stored `NARROW`
- `GHSA-QJPC-QF9M-XWMR` stored `NARROW`
- `GHSA-R5JH-Q2MW-GCX4` stored `NARROW`
- `GHSA-RQPP-RJJ8-7WV8` stored `NARROW`
- `GHSA-RXXP-482V-7MRH` stored `NARROW`
- `GHSA-V396-V7Q4-X2QJ` stored `NARROW`
- `GHSA-VMW2-QWM8-X84C` stored `NARROW`
- `GHSA-VW3V-WHVP-33V5` stored `NARROW`
- `GHSA-W4H3-GPV2-82QC` stored `NARROW`
- `GHSA-W85G-3H6X-4XH2` stored `NARROW`
- `GHSA-WJHR-76VG-2HVC` stored `NARROW`
- `GHSA-WP73-F3GG-W4VR` stored `NARROW`
- `GHSA-WXW3-Q3M9-C3JR` stored `NARROW`
- `GHSA-X2W7-XR2G-QHJR` stored `CONFIRM`
- `GHSA-X2XQ-QHJF-5MVG` stored `NARROW`
- `GHSA-X34R-63HX-W57F` stored `NARROW`
- `GHSA-X8QQ-M4QC-RPJ5` stored `CONFIRM`
- `GHSA-XMXX-7P24-H892` stored `NARROW`
- `GHSA-XQ94-R468-QWGJ` stored `NARROW`

## Stale / superseded rows

5 rows. Never counted as strict.
- `GHSA-4FXP-2M36-QV64` stored `CONFIRM` superseded by later NARROW/REJECT (`autoresearch/herdr-260813-ghsa200-final-candidate-review-codex/result.json; autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl`)
- `GHSA-4MR5-G6F9-CFRH` stored `CONFIRM` superseded by later NARROW/REJECT (`autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam/cases.jsonl; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/cases.jsonl; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/result.json; autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl`)
- `GHSA-94P4-4CQ8-9G67` stored `CONFIRM` superseded by later NARROW/REJECT (`autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam/cases.jsonl; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/cases.jsonl; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/result.json; autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl`)
- `GHSA-P52P-4VMG-4VQ3` stored `CONFIRM` superseded by later NARROW/REJECT (`autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/cases.jsonl; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/result.json`)
- `GHSA-P538-C434-8V24` stored `CONFIRM` superseded by later NARROW/REJECT (`autoresearch/herdr-260813-ghsa200-incomplete-rem-redteam/cases.jsonl; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/cases.jsonl; autoresearch/herdr-260813-ghsa200-medium5-redteam-grok46-low/result.json; autoresearch/orchestrator-260814-ghsa200-canonical85/ledger.jsonl`)

## Unresolved / unknown rows

Empty.

## Pending independent hostile review (not admitted)

- `GHSA-FRVJ-C5QP-XJ4W` foundation counted=true, verdict NARROW, all seven gates PASS, source next-pool-map_B_proposal+leader_replay. Canvas STATUS.md records a leader replay. canonical85 does not include this identity. Independent hostile review is still required.

## Duplicates / aliases

165 unique first-party GHSA ids; no duplicate rows. Foundation rows do not carry an aliases array. CVE-2026-55389 is the canonical alias of GHSA-8359 and is not a counting unit. GHSA-954P-556P-R752 shares a candidate SHA with GHSA-8359 and is a negative-control REJECT, absent from foundation.

## Method

Only structured foundation.jsonl rows, canonical85 STRICT_RELEASED_CASE / SUPERSEDES_EDGE / negative_controls.json, and named ID lists or cases.jsonl verdicts from terminal hostile/counter-redteam/final-review/redteam/independent-gate packets referenced by the proposal-gap census were used. Prose-only counts were ignored. Snapshot/work/pages/clone trees were not scanned. Canonical85 was not edited.

