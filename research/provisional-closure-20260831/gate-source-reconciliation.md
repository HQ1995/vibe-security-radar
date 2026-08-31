# Canonical gate-source reconciliation for the current 254 published cases

**Verdict: HOLD for gate-provenance write-back, not a claim that all 254 cases are invalid.** The current generated site has 254 unique `class_id` values and all join the 29,593-row ledger, but the canonical ledger export carries **zero top-level `gates` objects for all 254 published rows**. The publisher consequently reconstructs evidence state from coarse `site_tier` values or a Git-HEAD/base84 presentation cache. Exact structured sources can recover 241/254 rows; 13 require new adjudication; 14 of the 241 explicit verdicts contain a gate `FAIL`.

## Snapshot and grain

- Git HEAD: `7455d5c61a45c839c418213b1f828b0997022229`.
- Working generated-site SHA-256: `fd02b9e9287f90e99bf318ce69e1c58dc1efa649542cb640505ce0170989469f`; HEAD generated SHA-256: `f91985d2d90c6a4ed74c880960aede4dc594fb6c1637034d75552b61f97681a0`. Bytes differ because the site working copy is dirty, but the 254 `class_id → (case_id, gates)` tuples are identical.
- Ledger export SHA-256: `59699d7ab3e102cd08907aee1135bc6f0097cdbbe0db55a685571cce9d28fbc2`; rows=29,593; unique class IDs=29,593.
- Ten verdict files, path+NUL+content SHA-256: `4236d1810192fa46f0769b4b0b6d3470ad46bc91e5fd62c3564c0d88ae131338`; 146 rows and 146 unique class IDs.
- Published grain: 254 rows, 254 unique class IDs, 254 unique displayed case IDs, 254/254 ledger joins. The five appendices enumerate each class exactly once.
- Current display labels: confirmed=125, qualified=86, provisional=43. These labels are derived presentation state, not provenance.

## Mutually exclusive provenance result

| Bucket (priority order) | Unique class IDs | What exists now | Safe transaction source |
|---|---:|---|---|
| Existing gate-campaign explicit verdict | 129 | Exact seven-gate JSONL; 111 lack a ledger tier, 18 carry a legacy tier | Campaign verdict joined through its manifest |
| Ledger `site_tier` only | 98 | Coarse tier, no ledger `gates`; publisher uses cache except for `ALL_GATES_PASS` | 97 exact canonical94 rows; 1 needs adjudication |
| Stale cached gates only | 15 | No tier/gates/campaign; all 15 display cached 7/7 PASS | 10 Round9 adjudications + 5 canonical94 strict rows |
| Round11 new cases | 10 | Primary research and independent review, no canonical seven-gate object | New per-gate adjudication |
| No recoverable source | 2 | UltraDAG campaign exclusions; displayed gates all UNKNOWN | New adjudication or explicit HOLD |
| **Total** | **254** |  |  |

Exact-source counts: gate-campaign=129, Round9=10, canonical94=102 (67 `STRICT_RELEASED_CASE`, 35 `PRESERVED_HYPOTHESIS`), total=241. Effective vectors: 142 all-PASS, 82 NARROW/NA without UNKNOWN/FAIL, 3 UNKNOWN without FAIL, 14 with FAIL.

## Why cache is not authority

- `scripts/publish_tp_ledger.py:1216-1227` loads the committed generated site; `:1576-1582` merges it with base84.
- `scripts/publish_tp_ledger.py:1414-1418` chooses `ALL_GATES_PASS` → synthetic PASS, else ledger `gates`, else cached generated `gates`, else UNKNOWN. With no Neon-exported gates, old UI output becomes evidence input.
- `scripts/aggregate_gate_verdicts.py:60-71,97-116` validates campaign rows then writes the local JSONL directly. It never creates a Neon assessment/change set, so the next database export drops `gates` and `gates_source`.
- `scripts/site_preflight.py:949-973` checks that a displayed confirmed row has seven PASS values, but does not check their source. Cached seven-PASS therefore passes preflight.

## Cached PASS values that cannot be carried forward

These current PASS fields are contradicted by selected exact authority:

| class_id | case | stale transition(s) | authority |
|---|---|---|---|
| `alias-4018863fbab23917960da976` | GHSA-WJHR-76VG-2HVC | uniqueness:P→F | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:6` |
| `alias-588f479c8353c335cc5aea90` | GHSA-8X5V-CPV7-8JJP | identity:P→?, ai_hunk:P→N, uniqueness:P→? | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:5` |
| `alias-8ae5a01cbdd3ea4431941888` | GHSA-4FXP-2M36-QV64 | identity:P→N | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:210` |
| `alias-a57df415a930e4db1ef3b6f7` | GHSA-8G98-M4J9-QWW5 | fix_reversal:P→N | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:11` |
| `alias-b9ddf45a821a2ba8b2fed0c7` | GHSA-F38V-77QJ-H4JQ | but_for:P→N, fix_reversal:P→N | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:231` |
| `alias-c98fcd4b377724d652e74fe6` | GHSA-WVPP-8HX9-P66J | but_for:P→N | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:4` |

`alias-c5a7e76e9787edf4ea076555` / GHSA-8G7G-HMWM-6RV2 also displays cached 7/7 PASS solely from ledger line 18,343's `site_tier=ALL_GATES_PASS`. It has no exact selected seven-gate artifact, while that ledger row's advisory IDs are CVE-2026-42449/GHSA-56C3-VFP2-5QQJ and only `site_publication.canonical_case_id` changes the displayed identity. Do not auto-expand this tier; adjudicate the published identity first.

- GHSA-4FXP-2M36-QV64 currently displays 7/7 PASS, but canonical94 line 210 and `research/herdr-260814-confirmhigh-4fxp-grok46-low/report.md:3-11,37-49` set identity=NARROW. The cache is wrong.
- GHSA-5WP8-Q9MX-8JX8 is the inverse: cached topology=NARROW, while canonical94 lines 590-591 explicitly supersede it with a strict 7/7-PASS row. Use the later strict row.

## Explicit FAIL and UNKNOWN verdicts

Any-FAIL rows cannot be described merely as 'under review'. Under `scripts/aggregate_gate_verdicts.py:97-103`, they require HOLD/exclusion unless a later explicit supersession exists.

| class_id | case | failed gate(s) | vector | source |
|---|---|---|---|---|
| `alias-0d3bd8c784475190b98074e6` | CVE-2025-62615 | identity | `FPPPPPP` | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:4` |
| `alias-12f31aff80577e7d406330a8` | GHSA-P7MM-R948-4Q3Q | fix_reversal | `PPPPFPP` | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:15` |
| `alias-14c5e4aade3fb67cb8ae05db` | GHSA-VFGX-5Q85-58Q3 | but_for,uniqueness | `PPPFPPF` | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:1` |
| `alias-303ca6a3bcd91ac79f484238` | GHSA-8X4M-QW58-3PCX | release | `PPPPPFP` | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:4` |
| `alias-4018863fbab23917960da976` | GHSA-WJHR-76VG-2HVC | uniqueness | `PPPPPPF` | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:6` |
| `alias-5215e36f51cb38d13f3063ba` | CVE-2026-46383 | identity,uniqueness | `FPNNPPF` | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:5` |
| `alias-606ffd0fe0d4adb8a222028f` | CVE-2026-2393 | but_for,uniqueness | `PPNFPNF` | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:10` |
| `alias-75103365dffacc4143581f32` | GHSA-64VR-4GR2-M642 | fix_reversal,uniqueness | `PPNNFNF` | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:8` |
| `alias-7c7ceaa679ef609d302575e1` | GHSA-RFR2-MQ9M-X2QX | ai_hunk | `PFPPPPP` | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:13` |
| `alias-8fde3b61bfb7a8b43050519d` | GHSA-VCV2-R9JH-99M5 | identity | `F?N?NN?` | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:11` |
| `alias-965c730a146b51a238a3bf1d` | GHSA-2JCC-MXV7-P3F9 | uniqueness | `PPPPPPF` | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:10` |
| `alias-a57df415a930e4db1ef3b6f7` | GHSA-8G98-M4J9-QWW5 | ai_hunk | `PFPPNNP` | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:11` |
| `alias-ad08edcf98825ffa3306395b` | CVE-2026-45582 | topology,but_for,uniqueness | `PPFFPPF` | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:3` |
| `alias-c12c46f6239faabff2fc306c` | GHSA-P6Q4-FGR8-VX4P | ai_hunk,release | `PFPNPFP` | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:8` |

UNKNOWN occurs in four explicit campaign rows; one also has FAIL:

| class_id | case | unknown gate(s) | vector | also FAIL | source |
|---|---|---|---|---|---|
| `alias-23266042a88424523b7b8f48` | GHSA-8JQH-598V-RFXC | release | `PPPPP?P` | no | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:9` |
| `alias-588f479c8353c335cc5aea90` | GHSA-8X5V-CPV7-8JJP | identity,uniqueness | `?NPPPP?` | no | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:5` |
| `alias-8fde3b61bfb7a8b43050519d` | GHSA-VCV2-R9JH-99M5 | ai_hunk,but_for,uniqueness | `F?N?NN?` | yes | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:11` |
| `alias-c8c257caf20933bc901ef903` | GHSA-4P6X-RJ5H-HG93 | release | `PPPPN?P` | no | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:3` |

## Minimal transactional Neon reconciliation

Use one complete vector from the highest applicable source; never splice fields from several vectors:

1. Latest explicit supersession/accepted per-case verdict. For the current campaign intersection, select the 129 campaign JSONL rows.
2. Round9 `publication-gate-adjudication.json` for its class-keyed cases; lines 4-6 declare `adjudication > review > primary`.
3. Latest effective exact canonical94 row for the official identity: accepted `STRICT_RELEASED_CASE` supersedes its older hypothesis; otherwise use the latest `PRESERVED_HYPOTHESIS`. Canonical94 is globally HOLD/not publication-ready (`report.md:1-3,13-15`), so use matched per-case gate facts, not blanket publication authorization.
4. A source-tagged top-level ledger `gates` object would come next, but none exists. `CONFIRM` and `PARTIAL_EVIDENCE` cannot be expanded; even `ALL_GATES_PASS` needs a cited exact adjudication or new assessment.
5. Generated-site/base84 gates are cache only and have no evidentiary precedence.

Safe transaction boundary:

- Add source-backed assessments recording source path/line/digest, seven exact keys, official case ID, current class ID, and base revision. Round11 needs new gate adjudications: `CONFIRMED` is not 7/7 PASS and `CORRECTION_REQUIRED` is not a gate vector.
- Finalize one change set with `expected_revision` and assessment IDs. `ledger_store.py:230-251,254-305` enforces unique class patches, revision checks, row locks, and assessment ownership; `:213-227` prevents class-ID changes and advisory-ID loss.
- Write `gates`, immutable `gates_source`, and a tier derived from the exact vector: all PASS → `ALL_GATES_PASS`; NARROW/NA with no UNKNOWN/FAIL → `PARTIAL_EVIDENCE`; UNKNOWN or FAIL → no closure tier plus explicit reason. Remove legacy `CONFIRM`.
- Export Neon, regenerate without Git-HEAD gate fallback, and preflight values plus provenance.

Minimum set: backfill 241 exact-source rows; separately adjudicate the 10 Round11 rows, GHSA-8G7G-HMWM-6RV2, and two UltraDAG rows. Resolve/hold 14 FAIL rows and 3 no-FAIL UNKNOWN rows. Current generated gates differ from campaign authority on 30/129 intersecting cases, so partial write-back is unsafe.

## Appendix A — gate-campaign explicit verdicts (129 unique class IDs)

Vector order: `identity, ai_hunk, topology, but_for, fix_reversal, release, uniqueness`; `P/N/?/F/-` = PASS/NARROW/UNKNOWN/FAIL/NA.

| # | class_id | case | current→source | publication | source |
|---:|---|---|---|---|---|
| 1 | `alias-010f70c5d8fa86368c907fce` | GHSA-V9V4-F5WM-PHH4 | `PPPPNNP→PPPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:13` |
| 2 | `alias-024f133d4f7b93604e2f9b92` | CVE-2026-44427 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:11` |
| 3 | `alias-046ebc52fd3e746a2d0a2a54` | GHSA-7P4H-3GXQ-X3H3 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:4` |
| 4 | `alias-04967329955171a53cc2731f` | CVE-2026-47211 | `???????→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:7` |
| 5 | `alias-056f1934775d137d2b9abab6` | GHSA-QCR8-X557-7CP3 | `PPPPPPP→PPPPPPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:3` |
| 6 | `alias-08669df850b6208757ae59cc` | GHSA-4RH7-JWG9-M28M | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:15` |
| 7 | `alias-0959a15d77bdfcf170501a27` | GHSA-XFQJ-R5QW-8G4J | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:14` |
| 8 | `alias-0a13a7ee841e2cc48c75e67d` | GHSA-Q269-XQWW-45MM | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:7` |
| 9 | `alias-0a97ba3bb4787b9352f519d1` | GHSA-8H88-GXP3-J7PG | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:14` |
| 10 | `alias-0c32bc35f9b2fdfd939667e3` | CVE-2026-1979 | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:3` |
| 11 | `alias-0d0e9e558e622b69368380f0` | GHSA-8XPQ-CJCF-3WH9 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:6` |
| 12 | `alias-0d3bd8c784475190b98074e6` | CVE-2025-62615 | `???????→FPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:4` |
| 13 | `alias-12f214da878061b7ee08fe43` | CVE-2026-56679 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:7` |
| 14 | `alias-12f31aff80577e7d406330a8` | GHSA-P7MM-R948-4Q3Q | `???????→PPPPFPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:15` |
| 15 | `alias-13f3613c89f1ddb1e8edaac2` | GHSA-W6H2-FR4Q-XVXV | `PPPPNPP→PPPPNPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:14` |
| 16 | `alias-14c5e4aade3fb67cb8ae05db` | GHSA-VFGX-5Q85-58Q3 | `???????→PPPFPPF` | provisional | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:1` |
| 17 | `alias-18d165b001943a81909d5f2f` | GHSA-VRXG-GM77-7Q5G | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:15` |
| 18 | `alias-197ecfbbf41b33e82830e69d` | GHSA-3WQP-PRF6-2M72 | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:5` |
| 19 | `alias-1b195ec5b5d535d87d64f93c` | CVE-2026-66065 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:6` |
| 20 | `alias-1b957b7ca82602a76e3fa1e2` | GHSA-QF73-2HRX-XPRP | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:9` |
| 21 | `alias-1d21c2a1149d8e93093d3dec` | GHSA-H45M-MGCP-Q388 | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:3` |
| 22 | `alias-23266042a88424523b7b8f48` | GHSA-8JQH-598V-RFXC | `P??PP?P→PPPPP?P` | provisional | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:9` |
| 23 | `alias-265d18f71cb24bedd7788b6c` | GHSA-8HW4-FHWW-273G | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:6` |
| 24 | `alias-27b43f0a6b91a064e5464cc7` | GHSA-8CXW-CC62-Q28V | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:14` |
| 25 | `alias-297f60c15d9dbe59524925fa` | GHSA-V52W-28XH-V562 | `???????→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:12` |
| 26 | `alias-2aa10783579dfa1c5f7f4815` | GHSA-MPHV-75CG-56WG | `PPPPPPP→PPPPPPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:15` |
| 27 | `alias-2b6901f481ce7fec360c3f5d` | GHSA-RP72-5V5Q-2446 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:6` |
| 28 | `alias-2ce9b4bc68d521875ba6f713` | GHSA-PFM2-2MHG-8WPX | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:9` |
| 29 | `alias-303ca6a3bcd91ac79f484238` | GHSA-8X4M-QW58-3PCX | `???????→PPPPPFP` | provisional | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:4` |
| 30 | `alias-305e24587ff88af010e1fc86` | GHSA-HM2H-WWWH-G49X | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:4` |
| 31 | `alias-3300984c3cb1433e97c8c254` | GHSA-6C5R-PJ95-XVQV | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:10` |
| 32 | `alias-377d1d5663291f0794f60154` | GHSA-CR5W-67CM-WR78 | `PPPPNNP→PPPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:4` |
| 33 | `alias-3de20442d5ae44530a898ab0` | GHSA-CHFM-XGC4-47RJ | `PPPPPPP→PPPPPPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:12` |
| 34 | `alias-4018863fbab23917960da976` | GHSA-WJHR-76VG-2HVC | `PPNPP?P→PPPPPPF` | provisional | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:6` |
| 35 | `alias-4110691bd2bc88a0368daf9c` | GHSA-6XQM-JW5J-72JF | `PPPPNNP→PPPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:5` |
| 36 | `alias-4605f95988aa56ed3bfc3032` | GHSA-49MQ-FC6Q-3H46 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-00.jsonl:11` |
| 37 | `alias-470d0cf2ef6e3a7cf2d1be73` | CVE-2025-69288 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:5` |
| 38 | `alias-494842171e83d64933b5e262` | GHSA-XW57-23P8-9WC5 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:15` |
| 39 | `alias-5215e36f51cb38d13f3063ba` | CVE-2026-46383 | `???????→FPNNPPF` | provisional | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:5` |
| 40 | `alias-524dbe5847eded26555f0b7d` | GHSA-75HX-XJ24-MQRW | `P??PP?P→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:7` |
| 41 | `alias-57569b18ed81b84118a1fdb1` | GHSA-PQH8-P93P-2RX7 | `???????→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:8` |
| 42 | `alias-588f479c8353c335cc5aea90` | GHSA-8X5V-CPV7-8JJP | `PP?PP?P→?NPPPP?` | provisional | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:5` |
| 43 | `alias-5b7a15709d5bf7fd2ce76ff2` | GHSA-FC26-M9PF-V56Q | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:1` |
| 44 | `alias-5b7ab826c3552f8622cd54d2` | GHSA-64CV-VXPR-J6VC | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:15` |
| 45 | `alias-5c5f0f6123abd77859b383e0` | GHSA-4PCV-MG8V-VRGF | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:4` |
| 46 | `alias-5faddbd81b68a18d0fe0a6c4` | CVE-2026-54249 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:11` |
| 47 | `alias-606ffd0fe0d4adb8a222028f` | CVE-2026-2393 | `???????→PPNFPNF` | provisional | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:10` |
| 48 | `alias-60cd52b01dca16560b0d1e74` | GHSA-JP7M-XCGX-57QM | `PPPNPNP→PPPNPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:15` |
| 49 | `alias-60fc8591358b6a7abf5d5e54` | GHSA-FR8F-RWJX-F32V | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:1` |
| 50 | `alias-63a1cac4d02e61992ad6cf29` | CVE-2026-34599 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:12` |
| 51 | `alias-6795b24e3cc5a444c844b197` | GHSA-M2H4-J4P2-4J7C | `PPPPNNP→PPPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:3` |
| 52 | `alias-6888f86808d0d235e64c665d` | GHSA-7CWM-FPFH-RRCH | `PPPNNNP→PPPNNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:11` |
| 53 | `alias-6ae12a4e31fb30c60644e285` | GHSA-M6RX-7PVW-2F73 | `PNPPPPP→PNPPPPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:12` |
| 54 | `alias-6cc43b070d8c0d98ab41f2c2` | GHSA-C7RR-QHWX-6Q49 | `P??PP?P→PPPPPNP` | provisional | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:9` |
| 55 | `alias-6d7148c5065803b623df7041` | GHSA-GQQJ-85QM-8QHF | `PPPPNPP→PPPPNPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:1` |
| 56 | `alias-6f203ded2fcc9c7aa8ba52ba` | GHSA-88Q9-CMP2-C2VQ | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:7` |
| 57 | `alias-6f21db30d07db8cc9d9941d3` | CVE-2026-45707 | `PPNNPPN→PPNNPPN` | qualified | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:2` |
| 58 | `alias-70303c93c85d55d590baa876` | GHSA-2C85-RFCC-G74J | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:5` |
| 59 | `alias-71182376fbf8124e6251727f` | GHSA-J6R7-6FHX-77WX | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:8` |
| 60 | `alias-71f27141bf727786fbd31ab5` | GHSA-86QC-R5V2-V6X6 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:10` |
| 61 | `alias-723f95944bf3063587e29f10` | GHSA-QP9J-GFJJ-6H3V | `PPPPNPP→PPPPNPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-00.jsonl:15` |
| 62 | `alias-75103365dffacc4143581f32` | GHSA-64VR-4GR2-M642 | `???????→PPNNFNF` | provisional | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:8` |
| 63 | `alias-774e6c4f6ed1b7d9dd2a08a4` | GHSA-H8JJ-PQWW-5M4W | `PPPPNPP→PPPPNPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:2` |
| 64 | `alias-77cdcbc4570df3ac0370b67c` | GHSA-W253-42QP-5F2X | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:11` |
| 65 | `alias-7950adb2ddf3a72c9b42ec96` | GHSA-GC8W-X73W-P4RH | `PPPPNNP→PPPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:2` |
| 66 | `alias-7c7ceaa679ef609d302575e1` | GHSA-RFR2-MQ9M-X2QX | `???????→PFPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:13` |
| 67 | `alias-7c96b769d0e8d26817538aa3` | GHSA-WFX9-6H8H-F3GM | `PPPPNPP→PPPPNPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-00.jsonl:3` |
| 68 | `alias-7d004526b6fb2d91c8fad507` | GHSA-C65F-X25W-62JV | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:13` |
| 69 | `alias-7dfd4aed4f32367fc1f14713` | CVE-2026-45555 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:12` |
| 70 | `alias-7f066ccf3cf6b5102741290d` | GHSA-2R2P-4CGF-HV7H | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:10` |
| 71 | `alias-84abfbfcdcafd06a6562c6bf` | GHSA-R27J-894H-3W3P | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:12` |
| 72 | `alias-8545a65a3d21ea7ab297ab66` | GHSA-F9M7-VC86-P6JJ | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:13` |
| 73 | `alias-894cfebae953fe1d945479b3` | GHSA-6MG4-788H-7G9G | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:11` |
| 74 | `alias-8eff3fc4b483b48c2ceb498e` | GHSA-8CCJ-P46R-JWQQ | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:2` |
| 75 | `alias-8fde3b61bfb7a8b43050519d` | GHSA-VCV2-R9JH-99M5 | `???????→F?N?NN?` | provisional | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:11` |
| 76 | `alias-92049a48c6ef51cc3bc4e2ab` | GHSA-HHJV-JQ77-CMVX | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:14` |
| 77 | `alias-92abf8c8365feb873c79fb63` | GHSA-RHH5-3XRH-6535 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:12` |
| 78 | `alias-92dcda297a6d603f5544daf9` | GHSA-WV26-J37Q-2G7P | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:1` |
| 79 | `alias-95a7a0407afc16b1e7ed44ed` | GHSA-66R7-M7XM-V49H | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:13` |
| 80 | `alias-9638cedab2290ab95b10127c` | GHSA-6JCQ-6546-QRRW | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:3` |
| 81 | `alias-965c730a146b51a238a3bf1d` | GHSA-2JCC-MXV7-P3F9 | `???????→PPPPPPF` | provisional | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:10` |
| 82 | `alias-9dc5f3e6176baf486fd2696c` | GHSA-5383-J2P9-QFG3 | `P??PP?P→PPPPPNP` | provisional | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:9` |
| 83 | `alias-9fba88509b7988d29fa14a16` | GHSA-Q9PW-VMHH-384G | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:13` |
| 84 | `alias-a45f374601ed322c071603fe` | CVE-2026-34050 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:13` |
| 85 | `alias-a496da1a510b83927655f033` | GHSA-9HX3-5WP9-2QQG | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:5` |
| 86 | `alias-a57df415a930e4db1ef3b6f7` | GHSA-8G98-M4J9-QWW5 | `P??PP?P→PFPPNNP` | provisional | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:11` |
| 87 | `alias-a7ee9486911c2e06bba9f79c` | GHSA-VV65-F55V-XM6G | `NPPPPPP→NPPPPPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:2` |
| 88 | `alias-ab96fa036943e09144b22b2b` | GHSA-72W7-MF9G-733P | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:8` |
| 89 | `alias-ad08edcf98825ffa3306395b` | CVE-2026-45582 | `???????→PPFFPPF` | provisional | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:3` |
| 90 | `alias-ad4422c93367e1ec0fcb4d5e` | GHSA-FVXX-GGMX-3CJG | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:5` |
| 91 | `alias-b2192a7236ebe5381744b724` | GHSA-RRF2-J3H9-99WG | `PPPPNNP→PPPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:1` |
| 92 | `alias-b361d487fcb532ae408d5999` | GHSA-H2V8-4C3F-VQGV | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:8` |
| 93 | `alias-bb9637a317214d1c83579045` | CVE-2026-42282 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:8` |
| 94 | `alias-bf499d08da8dae005eecbbc0` | GHSA-J48Q-4C78-RHF9 | `PP?PP?P→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:2` |
| 95 | `alias-bf56c362053e61b3cc1e478b` | GHSA-2R68-G678-7QR3 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:9` |
| 96 | `alias-c12c46f6239faabff2fc306c` | GHSA-P6Q4-FGR8-VX4P | `???????→PFPNPFP` | provisional | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:8` |
| 97 | `alias-c45218004b47b9754c596ca1` | CVE-2026-54362 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:7` |
| 98 | `alias-c4fa001392ebebca44ab1ba2` | GHSA-FVVM-949W-QJ4W | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:1` |
| 99 | `alias-c6624e4a670e7ce0e02ceb97` | GHSA-G3R5-9H93-4J2C | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:2` |
| 100 | `alias-c819cf08c0a8bf17cf425ccc` | GHSA-J383-Q79V-268X | `P??PP?P→PPPPPNP` | provisional | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:6` |
| 101 | `alias-c86c76df9f7d8759e1d83ebf` | GHSA-3MJM-X6GW-2X42 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:7` |
| 102 | `alias-c87ab32a28eade7c4c019929` | GHSA-47R4-P7WR-42HW | `PNPPNNP→PNPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:6` |
| 103 | `alias-c8c257caf20933bc901ef903` | GHSA-4P6X-RJ5H-HG93 | `PPPPN?P→PPPPN?P` | provisional | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:3` |
| 104 | `alias-c98fcd4b377724d652e74fe6` | GHSA-WVPP-8HX9-P66J | `PP?PP?P→PPPNPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:4` |
| 105 | `alias-ca1d9b49a71fddc2bd6f4d93` | GHSA-GJXX-92W9-8V8F | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:5` |
| 106 | `alias-ca6d2a3f1502af18d7b26f0a` | GHSA-P8RR-9CVG-CX5J | `PP?PP?P→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:4` |
| 107 | `alias-cd8905a09d54912a47ad4c62` | GHSA-6QC9-MQVW-JG7X | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:3` |
| 108 | `alias-ce739b4c84e161aef6fa82ab` | GHSA-WRWR-H859-XH2R | `PPPNPNN→PPPNPNN` | qualified | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:6` |
| 109 | `alias-cfe8a69b17c7144c755c5961` | GHSA-HHFF-FJ5F-QG48 | `???????→PPPPPNP` | provisional | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:11` |
| 110 | `alias-d019f5b5ca91c8bb1d8b320d` | GHSA-W9RM-VVQP-QQ3H | `P??PP?P→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:13` |
| 111 | `alias-d3a04227b8ce964d223fe114` | GHSA-V2JJ-5G64-RXP4 | `PPPPNPP→PPPPNPP` | qualified | `research/gate-campaign-20260830/verdicts/wave-00.jsonl:4` |
| 112 | `alias-d66f50eb57eceedd86508dbb` | CVE-2026-44653 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:8` |
| 113 | `alias-d6a2f067f5adfbfa68207a41` | GHSA-GF29-4F56-R2JF | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:1` |
| 114 | `alias-d6c20dfcc532fa83eb45816b` | GHSA-VXGJ-XG5C-P4H7 | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:15` |
| 115 | `alias-dbe3af76ef839c90ea4540ab` | CVE-2026-28473 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:2` |
| 116 | `alias-e00e27678563e144d7595f94` | GHSA-JCPJ-R94H-977W | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-06.jsonl:7` |
| 117 | `alias-e5e5551b2282ac11f39e3308` | GHSA-G2G8-95QG-V35H | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:9` |
| 118 | `alias-e668a5f0538480b5c4b5d8e1` | CVE-2026-39974 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:10` |
| 119 | `alias-e8d523a0aeaeefe1906dbf68` | GHSA-F67F-HCR6-94MF | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-08.jsonl:10` |
| 120 | `alias-ea1e862d6a7a4a3d1085a27b` | GHSA-PJ2R-F9MW-VRCQ | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:3` |
| 121 | `alias-ea4fd743e6a05d2b80633a1f` | GHSA-F65R-H4G3-3H9H | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:7` |
| 122 | `alias-ece91c8d4f7b96b80d952a72` | GHSA-P4H8-56QP-HPGV | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:2` |
| 123 | `alias-ed9b3734b369568d840f0ed2` | CVE-2026-32718 | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:14` |
| 124 | `alias-f052b9d2ff41c0b23a2ebba1` | GHSA-R8RP-HX65-58JJ | `PPPPNNP→PPPPNNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-07.jsonl:8` |
| 125 | `alias-f0b371318e30448b9a250d8a` | GHSA-WXW3-Q3M9-C3JR | `???????→PPPPPPP` | provisional | `research/gate-campaign-20260830/verdicts/wave-05.jsonl:4` |
| 126 | `alias-f2c6e699f63934ab4a567432` | GHSA-VH5J-5FHQ-9XWG | `P??PP?P→PPPPPNP` | provisional | `research/gate-campaign-20260830/verdicts/wave-09.jsonl:10` |
| 127 | `alias-f419ac3122c41760eda4325f` | GHSA-29HF-RM4X-XXPH | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-03.jsonl:10` |
| 128 | `alias-fa56af7f270ee4dfc8ff3cf8` | GHSA-PGP4-XR4J-H5CG | `PPPPPNP→PPPPPNP` | qualified | `research/gate-campaign-20260830/verdicts/wave-04.jsonl:14` |
| 129 | `alias-fc2a802d53dea92fa59dfdd9` | GHSA-Q9P7-WQXG-MRHC | `PPPPPPP→PPPPPPP` | confirmed | `research/gate-campaign-20260830/verdicts/wave-02.jsonl:11` |

## Appendix B — ledger site_tier only (98 unique class IDs)

| # | class_id | case | tier / ledger line | current→exact | recovery |
|---:|---|---|---|---|---|
| 1 | `alias-0016318cce6fe1880b2ee2ae` | GHSA-FMFG-9G7C-3VQ7 | ALL_GATES_PASS / L6 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:528` |
| 2 | `alias-02fb7aeb21b9f4e1ab18fbce` | GHSA-G39V-CVJH-8FPF | ALL_GATES_PASS / L246 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:531` |
| 3 | `alias-043e2fc26bdd6275f9cae512` | GHSA-VVFR-G83F-8QCV | ALL_GATES_PASS / L364 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:562` |
| 4 | `alias-04c12884686f76c49c025593` | GHSA-425G-FJHQ-5H92 | ALL_GATES_PASS / L413 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:580` |
| 5 | `alias-06ca275f5a582dacb68ec70b` | GHSA-WV46-V6XC-2QHF | ALL_GATES_PASS / L604 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:566` |
| 6 | `alias-08f4ee97e5be53cda71a58d8` | GHSA-FWPR-59HH-GR98 | PARTIAL_EVIDENCE / L817 | `NPPPPNP→NPPPPNP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:67` |
| 7 | `alias-0950f9602f04111bf35b582b` | GHSA-R9MR-M37C-5FR3 | ALL_GATES_PASS / L852 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:554` |
| 8 | `alias-0ae0a984e1b1218e180ef355` | GHSA-WXHM-2MQ7-7697 | ALL_GATES_PASS / L1021 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:567` |
| 9 | `alias-0c2b23907a0335a65c211516` | GHSA-MGXW-V6RH-WCV6 | PARTIAL_EVIDENCE / L1133 | `PPNNPPP→PPNNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:177` |
| 10 | `alias-0d95fed3b98673811030d936` | GHSA-4564-PVR2-QQ4H | ALL_GATES_PASS / L1272 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:502` |
| 11 | `alias-10470c6830a2c45cfe7539af` | GHSA-RG8M-3943-VM6Q | ALL_GATES_PASS / L1504 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:555` |
| 12 | `alias-125fe49a49acf7ef2baeb111` | GHSA-2CM6-R77W-6G96 | PARTIAL_EVIDENCE / L1676 | `NPPNNNP→NPPNNNP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:165` |
| 13 | `alias-12debd2395456ef3aa1dd946` | GHSA-J4XF-96QF-RX69 | ALL_GATES_PASS / L1720 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:538` |
| 14 | `alias-17d78446a20e0607b519cb7d` | GHSA-5GVR-V6QV-H5MM | PARTIAL_EVIDENCE / L2181 | `PPNPNPP→PPNPNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:160` |
| 15 | `alias-1969788cc13f838042e11ce1` | GHSA-P5RM-JG5C-8C77 | CONFIRM / L2316 | `PPPPP-P→PPPPP-P` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:198` |
| 16 | `alias-1a8156c9b0ac4e49d726cdc4` | GHSA-5WP8-Q9MX-8JX8 | PARTIAL_EVIDENCE / L2411 | `PPNPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:591` |
| 17 | `alias-1ac241b6b959b320f90a397c` | GHSA-5WQV-FHMR-PJGH | PARTIAL_EVIDENCE / L2440 | `PPPNPPP→PPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:72` |
| 18 | `alias-1b96ef8b7d6e0e3e1d35e5fd` | GHSA-3WXW-XV34-2FRG | CONFIRM / L2516 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:501` |
| 19 | `alias-203bff3ee3277cd64f94c6bc` | GHSA-J5QP-P44G-2M49 | ALL_GATES_PASS / L2949 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:572` |
| 20 | `alias-21a72d96d703f5d0dd1ce01e` | GHSA-2944-57XV-2682 | ALL_GATES_PASS / L3082 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:573` |
| 21 | `alias-226bc664b77d22042b6f4336` | GHSA-GH4H-34GR-87R7 | ALL_GATES_PASS / L3147 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:534` |
| 22 | `alias-2788167921d685f8a3bb43a5` | GHSA-X2XQ-QHJF-5MVG | PARTIAL_EVIDENCE / L3613 | `PPNNNPP→PPNNNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:153` |
| 23 | `alias-295c38ae310f7eede1119c01` | GHSA-Q9PG-JJ6X-J9P6 | ALL_GATES_PASS / L3785 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:551` |
| 24 | `alias-29dedb40ead513739ee1d647` | GHSA-8WC8-HF36-MJH9 | ALL_GATES_PASS / L3839 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:520` |
| 25 | `alias-2ad5323008ffeebb3948943a` | GHSA-G3XQ-3GMV-QQ8G | ALL_GATES_PASS / L3943 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:532` |
| 26 | `alias-2ba9de9c56b4ef7cb4cd4a55` | GHSA-322X-V876-G883 | ALL_GATES_PASS / L4018 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:577` |
| 27 | `alias-2e4283d234c17809cb8d3294` | GHSA-97RM-XJ73-33JH | ALL_GATES_PASS / L4255 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:521` |
| 28 | `alias-2e7b98eec995ef67762af02a` | GHSA-HC8V-WWC9-VGXM | ALL_GATES_PASS / L4274 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:581` |
| 29 | `alias-2e848b53793009fca2ca1de3` | GHSA-QF5V-M7P4-95RP | CONFIRM / L4279 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:579` |
| 30 | `alias-323bf07420daae79c5a0844f` | GHSA-XW8C-RRVX-F7XQ | ALL_GATES_PASS / L4647 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:570` |
| 31 | `alias-32624290ded12d479653d429` | GHSA-6C8G-7P36-R338 | PARTIAL_EVIDENCE / L4664 | `PPPNPPP→PPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:83` |
| 32 | `alias-3cac93e2e744b1b362bb38a6` | GHSA-5J8P-5RRJ-8WJG | PARTIAL_EVIDENCE / L5636 | `NPNNNPP→NPNNNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:150` |
| 33 | `alias-3ed594d20d11056d42d54528` | GHSA-7GH7-258J-4MPQ | ALL_GATES_PASS / L5867 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:515` |
| 34 | `alias-3f35b69df081559ab1fad010` | GHSA-VVGP-4C28-M3JM | ALL_GATES_PASS / L5895 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:563` |
| 35 | `alias-444d166bd62f8714937b931d` | GHSA-2M67-CXXQ-C3H8 | PARTIAL_EVIDENCE / L6358 | `PPPNNPP→PPPNNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:86` |
| 36 | `alias-469595425f9374edbd871410` | GHSA-6Q7J-XR26-3H2C | ALL_GATES_PASS / L6565 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:512` |
| 37 | `alias-46eb6fca4f0fcaf022787ade` | GHSA-X34R-63HX-W57F | PARTIAL_EVIDENCE / L6589 | `PPNPPPP→PPNPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:218` |
| 38 | `alias-48acec3eadce8bee986a75d3` | GHSA-46Q5-G3J9-WX5C | ALL_GATES_PASS / L6769 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:503` |
| 39 | `alias-4993ddde0ef3f6e023cca94a` | GHSA-5C6W-WWFQ-7QQM | ALL_GATES_PASS / L6853 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:506` |
| 40 | `alias-50a179b091fae05cd3c940e9` | GHSA-W28W-GP39-M4P6 | ALL_GATES_PASS / L7483 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:564` |
| 41 | `alias-51fe77b69f348fed23bad2ab` | GHSA-2HFG-4FH4-QP7F | PARTIAL_EVIDENCE / L7610 | `NNPPPNP→NNPPPNP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:261` |
| 42 | `alias-595e16871859d5a9729dcb6e` | GHSA-XQ94-R468-QWGJ | PARTIAL_EVIDENCE / L8297 | `PPPNPPP→PPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:182` |
| 43 | `alias-5a43c1628113d632bf3692b9` | GHSA-8JPQ-5H99-FF5R | ALL_GATES_PASS / L8380 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:519` |
| 44 | `alias-5b25fd0286a2b24e806f45a9` | GHSA-6P9M-Q3JP-47H4 | ALL_GATES_PASS / L8463 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:511` |
| 45 | `alias-5e18a59fcf06a2471d623c00` | GHSA-Q855-8RH5-JFGQ | ALL_GATES_PASS / L8733 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:550` |
| 46 | `alias-61bd78ccafb20adcb14b905d` | GHSA-Q6QC-XP4Q-RJQ5 | ALL_GATES_PASS / L9062 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:548` |
| 47 | `alias-62042a3acb09a9a9ad48ae77` | GHSA-3CVX-236H-M9FJ | PARTIAL_EVIDENCE / L9090 | `PPPNNNP→PPPNNNP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:95` |
| 48 | `alias-63bd14a11b84b61580352cec` | GHSA-VC8F-X9PP-WF5P | ALL_GATES_PASS / L9244 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:559` |
| 49 | `alias-6d9c04f0858751e3f012e400` | GHSA-9C3V-684M-579C | PARTIAL_EVIDENCE / L10134 | `PPPPPNP→PPPPPNP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:257` |
| 50 | `alias-7119f1cb6cfa481172422dc5` | GHSA-GC24-PX2R-5QMF | PARTIAL_EVIDENCE / L10441 | `NPPNPPP→NPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:99` |
| 51 | `alias-7224ab612b76b7dd1c18d614` | GHSA-FRVJ-C5QP-XJ4W | PARTIAL_EVIDENCE / L10552 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:583` |
| 52 | `alias-77f9a22ad8e8eb7f178f97b9` | GHSA-9HFR-GW99-8RHX | ALL_GATES_PASS / L11116 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:523` |
| 53 | `alias-8099a555171349d287af92d5` | GHSA-H4RQ-P45C-642R | PARTIAL_EVIDENCE / L11894 | `PPNNNPP→PPNNNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:149` |
| 54 | `alias-81f12adb7f1b7ae03d0c07f1` | GHSA-HFF7-CCV5-52F8 | PARTIAL_EVIDENCE / L12027 | `NPPNPPP→NPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:102` |
| 55 | `alias-8a72049063fe25cb8caa1835` | GHSA-VJ3G-5PX3-GR46 | ALL_GATES_PASS / L12809 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:561` |
| 56 | `alias-8ae5a01cbdd3ea4431941888` | GHSA-4FXP-2M36-QV64 | CONFIRM / L12851 | `PPPPPPP→NPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:210` |
| 57 | `alias-8e90b10e3e67d6523b66923e` | GHSA-M4WX-M65X-GHRR | ALL_GATES_PASS / L13197 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:541` |
| 58 | `alias-9012f3e444c033b0f2a19660` | GHSA-G5CG-8X5W-7JPM | PARTIAL_EVIDENCE / L13352 | `PPNNPPP→PPNNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:157` |
| 59 | `alias-91db1e31bf2cda080bd98102` | GHSA-3RP5-JJMW-4WV2 | ALL_GATES_PASS / L13525 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:500` |
| 60 | `alias-92431dcbbb3899c7f124c4dd` | GHSA-7F6V-3GX7-27Q8 | ALL_GATES_PASS / L13573 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:514` |
| 61 | `alias-9315c619e30aa9bd0c69c7d1` | GHSA-X4HG-HFWF-P9MW | ALL_GATES_PASS / L13653 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:576` |
| 62 | `alias-9764e28bbc2e093b13aaac3e` | GHSA-Q447-RJ3R-2CGH | PARTIAL_EVIDENCE / L14068 | `NPPNPPP→NPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:109` |
| 63 | `alias-99ee5f834a00aca5862a1926` | GHSA-76RV-2R9V-C5M6 | ALL_GATES_PASS / L14281 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:513` |
| 64 | `alias-9f69684e62a2b96f144d613f` | GHSA-8359-H9FX-J6V9 | PARTIAL_EVIDENCE / L14784 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:582` |
| 65 | `alias-a05009adfdf51481b4c4ab3d` | GHSA-RV2Q-F2H5-6XMG | ALL_GATES_PASS / L14872 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:557` |
| 66 | `alias-a353279bb68efda133071d61` | GHSA-539M-9XH6-Q6RR | ALL_GATES_PASS / L15137 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:504` |
| 67 | `alias-a8072571949b65fa46002d16` | GHSA-HC36-C89J-5F4J | ALL_GATES_PASS / L15558 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:536` |
| 68 | `alias-a87ef9051feecb7a9cd00c99` | GHSA-2GFJ-FR43-4735 | ALL_GATES_PASS / L15595 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:499` |
| 69 | `alias-ab9933c9d654c2cf54ee3f7b` | GHSA-7P8R-X3MC-P8W7 | ALL_GATES_PASS / L15867 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:516` |
| 70 | `alias-ab9e8be2528e5a71fd3a7ad5` | GHSA-G353-MGV3-8PCJ | PARTIAL_EVIDENCE / L15870 | `NPNPPPP→NPNPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:186` |
| 71 | `alias-ad337734a611a97f040638ad` | GHSA-X22M-J5QQ-J49M | ALL_GATES_PASS / L16038 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:568` |
| 72 | `alias-adaf8ed9e0a157cba9b63805` | GHSA-PV2J-RGHR-V5R9 | ALL_GATES_PASS / L16086 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:546` |
| 73 | `alias-afc1d67fcdd491fd6884883e` | GHSA-5RV5-XJ5J-3484 | ALL_GATES_PASS / L16283 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:507` |
| 74 | `alias-b28a0ef0ee7af1a1097465f2` | GHSA-G8MR-85JM-7XHM | CONFIRM / L16556 | `PPPPP-P→PPPPP-P` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:219` |
| 75 | `alias-b36a7cd7bcd0e76bbb7491b4` | GHSA-Q6QF-4P5J-R25G | PARTIAL_EVIDENCE / L16648 | `NPPNPPP→NPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:122` |
| 76 | `alias-b87b6c39f1e316817dfd1dfc` | GHSA-5XXX-QHH7-9287 | CONFIRM / L17116 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:508` |
| 77 | `alias-b957cebfc80b884b647c24e8` | GHSA-JFV4-H8MC-JCP8 | PARTIAL_EVIDENCE / L17202 | `NPNNPPP→NPNNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:124` |
| 78 | `alias-b9ddf45a821a2ba8b2fed0c7` | GHSA-F38V-77QJ-H4JQ | PARTIAL_EVIDENCE / L17266 | `PPPPPNP→PPPNNNP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:231` |
| 79 | `alias-bea508942342f0c4320b400d` | GHSA-68V4-HMWV-F43H | ALL_GATES_PASS / L17692 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:509` |
| 80 | `alias-bea67a3b6bb5fe42289b5787` | GHSA-877V-W3F5-3PCQ | ALL_GATES_PASS / L17693 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:518` |
| 81 | `alias-c4cd9379a4920e9fd9fed577` | GHSA-7X5Q-8F6H-RJRC | PARTIAL_EVIDENCE / L18263 | `PPNPNPP→PPNPNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:148` |
| 82 | `alias-c5a7e76e9787edf4ea076555` | GHSA-8G7G-HMWM-6RV2 | ALL_GATES_PASS / L18343 | `PPPPPPP→adjudicate` | `NO EXACT SOURCE` |
| 83 | `alias-d15c3d1da6dab91042d63c2e` | GHSA-243V-5F97-VFQ3 | ALL_GATES_PASS / L19422 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:498` |
| 84 | `alias-d6382d230e136d6c15eadf35` | GHSA-4524-X6PC-RR9X | PARTIAL_EVIDENCE / L19898 | `PPPPNPP→PPPPNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:136` |
| 85 | `alias-d99838bbcb30d442ba9f5a47` | GHSA-CW23-QWR7-C655 | PARTIAL_EVIDENCE / L20226 | `PPNPPPP→PPNPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:169` |
| 86 | `alias-da613206a4e663837e4c6661` | GHSA-Q6RR-FM2G-G5X8 | ALL_GATES_PASS / L20309 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:549` |
| 87 | `alias-dbd0a92c62e19f8c406c2078` | GHSA-R5JH-Q2MW-GCX4 | PARTIAL_EVIDENCE / L20461 | `PPPNPPP→PPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:195` |
| 88 | `alias-df787a23a3ac89c4e14c8a5e` | GHSA-R48C-V28R-PF6V | ALL_GATES_PASS / L20787 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:553` |
| 89 | `alias-e08284f85ea883d18c60e813` | GHSA-F7FH-QG34-X2XH | PARTIAL_EVIDENCE / L20884 | `NPPPPPP→NPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:140` |
| 90 | `alias-e185a69fdf0f5a626f9bc3d0` | GHSA-VMW2-QWM8-X84C | PARTIAL_EVIDENCE / L20986 | `PPNNNPP→PPNNNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:141` |
| 91 | `alias-e2cc51620788e401ab7a587c` | GHSA-W85G-3H6X-4XH2 | PARTIAL_EVIDENCE / L21107 | `PPPNPPP→PPPNPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:183` |
| 92 | `alias-e3d133722201958d73d54649` | GHSA-MF5G-6R6F-GHHM | ALL_GATES_PASS / L21208 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:542` |
| 93 | `alias-e60f8c222932c1dfd63656a3` | GHSA-RV39-79C4-7459 | ALL_GATES_PASS / L21422 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:558` |
| 94 | `alias-e8e15a41dbb7f098796c61f7` | GHSA-PMCH-G965-GRMR | ALL_GATES_PASS / L21678 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:578` |
| 95 | `alias-ebdfb56b10acc655505c434e` | GHSA-5C7W-4WM3-85VW | ALL_GATES_PASS / L21971 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:574` |
| 96 | `alias-ec754f179ba2cc618a27a98b` | GHSA-4PQR-V6C3-X77J | PARTIAL_EVIDENCE / L22017 | `PPNPNNP→PPNPNNP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:144` |
| 97 | `alias-ef917a24bf7209fd1f889026` | GHSA-G8P2-7WF7-98MQ | ALL_GATES_PASS / L22333 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:533` |
| 98 | `alias-fdeaf38897f73c8d938cfa65` | GHSA-RXXP-482V-7MRH | PARTIAL_EVIDENCE / L23677 | `NPPNNPP→NPPNNPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:147` |

## Appendix C — stale cached gates only (15 unique class IDs)

| # | class_id | case | cached→source | recovery |
|---:|---|---|---|---|
| 1 | `alias-08277d0aedc4ae2c09aa5de1` | GHSA-6H3P-88P7-M8GP | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:7` |
| 2 | `alias-0ae1e9b85f4a9eebb8ee56b3` | GHSA-CCP9-5G7C-PJ86 | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:26` |
| 3 | `alias-1438f5c08078efa8c5cbbba9` | GHSA-R654-XCXM-6JPC | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:45` |
| 4 | `alias-14cf4e0a4ab182b9a957901e` | GHSA-X98J-GH4V-7P7G | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:64` |
| 5 | `alias-17a4dce2bfe03aac28aaaa95` | GHSA-9J5F-PJWJ-62R3 | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:83` |
| 6 | `alias-209b2d91214b63de2866760f` | GHSA-P2G6-JJWG-33V4 | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:102` |
| 7 | `alias-2ae2eefcec8475abdb79a1a5` | GHSA-PJ24-VJ9G-8VG8 | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:121` |
| 8 | `alias-2d420fc19cb5fabda6edbe92` | GHSA-FPMV-5WGW-QHHR | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:529` |
| 9 | `alias-31916f3402c3846231816b53` | GHSA-VGPJ-V99M-7H5J | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:159` |
| 10 | `alias-38a46fcbb9217789f939e775` | GHSA-76PC-MQXP-3RQ5 | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:178` |
| 11 | `alias-4746e8151755cf3b6ee6d14d` | GHSA-C4HM-4H84-2CF3 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:525` |
| 12 | `alias-7d98616a88feef796bff2552` | GHSA-GWMJ-HF32-5V8V | `PPPPPPP→PPPPPPP` | `research/round9-top200-20260828/publication-gate-adjudication.json:216` |
| 13 | `alias-7e96caa20b835ee167518f82` | GHSA-X9QH-W4C4-54F9 | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:569` |
| 14 | `alias-bd1a0da23e1a76c824287b27` | GHSA-6MWV-4MRM-5P3M | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:510` |
| 15 | `alias-d9cd1a5b55e1884558bbeb6d` | GHSA-QPMQ-6WJC-W28Q | `PPPPPPP→PPPPPPP` | `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl:552` |

## Appendix D — Round11 without exact seven-gate adjudication (10 unique class IDs)

| # | class_id | case | worker verdict | review source | ledger line |
|---:|---|---|---|---|---:|
| 1 | `alias-67d47274d2d864426a971733` | GHSA-QGP8-V765-QXX9 | w295: CONFIRMED | `research/round11-top500-20260829/independent-review/w295.json` | 26309 |
| 2 | `alias-7a67e4c2cdfe7bc6ade411ee` | GHSA-723W-CRW6-P9HX | w000: CONFIRMED | `research/round11-top500-20260829/independent-review/w000.json` | 26727 |
| 3 | `alias-7c031e998c13768caf64a245` | GHSA-JJ45-W38G-GFRJ | w078: CORRECTION_REQUIRED | `research/round11-top500-20260829/independent-review/w078.json` | 26769 |
| 4 | `alias-7e22d7fa18af10c1d907af89` | GHSA-2664-HR5V-554W | w001: CONFIRMED | `research/round11-top500-20260829/independent-review/w001.json` | 26821 |
| 5 | `alias-7e64c88c0c888e3970b52934` | GHSA-C7VW-VFXJ-3MVH | w002: CORRECTION_REQUIRED | `research/round11-top500-20260829/independent-review/w002.json` | 26826 |
| 6 | `alias-85443fa0b01cc0d808288b99` | GHSA-H5RM-9FHH-5PHJ | w006: CORRECTION_REQUIRED | `research/round11-top500-20260829/independent-review/w006.json` | 26979 |
| 7 | `alias-94e43bc58f8dba40785f7dca` | GHSA-4PC9-X2FX-P7VJ | w297: CONFIRMED | `research/round11-top500-20260829/independent-review/w297.json` | 27305 |
| 8 | `alias-96f4c59aa038773f281647b9` | GHSA-GVQ9-CMXR-844M | w011: CORRECTION_REQUIRED | `research/round11-top500-20260829/independent-review/w011.json` | 27346 |
| 9 | `alias-c1c247c618bb54f97b64b4fb` | GHSA-HW36-J4Q7-VJXX | w093: CONFIRMED | `research/round11-top500-20260829/independent-review/w093.json` | 28235 |
| 10 | `alias-db82daf2886088440e14b14f` | GHSA-Q8HH-M6V5-4F3X | w019: CORRECTION_REQUIRED | `research/round11-top500-20260829/independent-review/w019.json` | 28783 |

GHSA-HW36-J4Q7-VJXX is a positive contrast: w093 independently passes its checks and reports no remaining gap, but that schema still is not the canonical seven-gate object. GHSA-Q8HH-M6V5-4F3X is negative: w019 is `CORRECTION_REQUIRED`, and lines 14-31 say the aggregate remains partially unpatched. Neither maps mechanically to seven PASS values.

## Appendix E — no recoverable gate source (2 unique class IDs)

| # | class_id | case | current vector | disposition |
|---:|---|---|---|---|
| 1 | `alias-3695e775e541b8d8f707ccde` | CVE-2026-42278 | `???????` | ledger L5050; UltraDAG exclusion in `scripts/aggregate_gate_verdicts.py:12,43,73-75` |
| 2 | `alias-ff3fa870e1a23f5c964f7fb2` | CVE-2026-40583 | `???????` | ledger L23793; UltraDAG exclusion in `scripts/aggregate_gate_verdicts.py:12,43,73-75` |

Coverage check: 129 + 98 + 15 + 10 + 2 = **254**, with 254 distinct class IDs and no omissions or overlaps.
