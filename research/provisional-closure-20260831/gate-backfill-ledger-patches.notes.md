# Gate backfill ledger patch notes

Status: **draft, validated, not applied**. No Neon mutation, ledger export, publisher run, generated-site rewrite, commit, or push was performed.

## Result

- `gate-backfill-ledger-patches.jsonl` contains 214 complete Neon rows, sorted by `class_id`, with 214 unique class IDs.
- Exact-source composition: 103 gate-campaign rows, 102 canonical94 rows, and 9 Round9 publication adjudications.
- Tier result: 133 `ALL_GATES_PASS`, 79 `PARTIAL_EVIDENCE`, and 2 explicit no-FAIL UNKNOWN vectors with `site_tier=null`.
- Every row changes only `gates`, `gates_source`, and `site_tier` relative to its fresh Neon base row. `assessment_ids` is intentionally empty.
- Patch SHA-256: `a3c784e04a9f7d280ab04e371c179f3acb6e0eadef0869318c879d1f0876599d`; bytes=767223.
- Reconciliation report SHA-256: `e6a85e2b77d46c4b50a8d15fce356fc512d395f1711ee45c2ad5626d47852f6d`.

## Selection equation

The fixed report inventory has 241 cases with an exact structured source. Fourteen vectors contain `FAIL` and are left to fail re-review, leaving 227 source-backed no-FAIL cases. The four business patch files contain 36 disjoint class IDs; 13 intersect those 227. Therefore:

`241 exact - 14 FAIL - 13 business overlaps = 214 gate-backfill rows`

The 13 cases that still need new adjudication were never included in the 241 exact-source set and are absent. No generated-site or base84 cached PASS value was used.

## Explicit UNKNOWN handling

These are preserved because their UNKNOWN values come from an explicit campaign verdict, not cache. Neither receives a closure tier:

| class_id | case | vector | source |
|---|---|---|---|
| `alias-23266042a88424523b7b8f48` | CVE-2026-49141 | `PASS/PASS/PASS/PASS/PASS/UNKNOWN/PASS` | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:9` |
| `alias-c8c257caf20933bc901ef903` | CVE-2026-19288 | `PASS/PASS/PASS/PASS/NARROW/UNKNOWN/PASS` | `research/gate-campaign-20260830/verdicts/wave-01.jsonl:3` |

## Patch-set exclusion and overlap

All 36 class IDs in the original four business patch files are excluded from this patch, including the 13 that otherwise qualified. The two fail-re-review IDs were already absent because their prior exact vectors contained `FAIL`. At generation time, the five auxiliary patch files below contained 38 IDs disjoint from this 214-row gate patch and from one another. Later patch files must be checked with the complete transaction set immediately before apply.

| Auxiliary patch | IDs | source-backed/no-FAIL overlap |
|---|---:|---:|
| `ready-ledger-patches.jsonl` | 26 | 8 |
| `duplicate-ledger-patches.jsonl` | 4 | 3 |
| `not-ai-ledger-patches.jsonl` | 5 | 2 |
| `cve45582-ledger-patch.jsonl` | 1 | 0 |
| `fail-rereview-ledger-patches.jsonl` | 2 | 0 |
| **Union** | **38** | **13** | class IDs pairwise disjoint |

### `ready-ledger-patches.jsonl`

- `alias-04967329955171a53cc2731f` — exact-source overlap; business patch owns the row.
- `alias-12f31aff80577e7d406330a8`
- `alias-14c5e4aade3fb67cb8ae05db`
- `alias-297f60c15d9dbe59524925fa` — exact-source overlap; business patch owns the row.
- `alias-3695e775e541b8d8f707ccde`
- `alias-4018863fbab23917960da976`
- `alias-5215e36f51cb38d13f3063ba`
- `alias-524dbe5847eded26555f0b7d` — exact-source overlap; business patch owns the row.
- `alias-57569b18ed81b84118a1fdb1` — exact-source overlap; business patch owns the row.
- `alias-606ffd0fe0d4adb8a222028f`
- `alias-67d47274d2d864426a971733`
- `alias-75103365dffacc4143581f32`
- `alias-7c031e998c13768caf64a245`
- `alias-7e22d7fa18af10c1d907af89`
- `alias-7e64c88c0c888e3970b52934`
- `alias-85443fa0b01cc0d808288b99`
- `alias-8fde3b61bfb7a8b43050519d`
- `alias-94e43bc58f8dba40785f7dca`
- `alias-965c730a146b51a238a3bf1d`
- `alias-96f4c59aa038773f281647b9`
- `alias-c1c247c618bb54f97b64b4fb`
- `alias-c98fcd4b377724d652e74fe6` — exact-source overlap; business patch owns the row.
- `alias-cfe8a69b17c7144c755c5961` — exact-source overlap; business patch owns the row.
- `alias-d019f5b5ca91c8bb1d8b320d` — exact-source overlap; business patch owns the row.
- `alias-db82daf2886088440e14b14f`
- `alias-f0b371318e30448b9a250d8a` — exact-source overlap; business patch owns the row.

### `duplicate-ledger-patches.jsonl`

- `alias-0a97ba3bb4787b9352f519d1` — exact-source overlap; business patch owns the row.
- `alias-0ae1e9b85f4a9eebb8ee56b3` — exact-source overlap; business patch owns the row.
- `alias-7a67e4c2cdfe7bc6ade411ee`
- `alias-bf499d08da8dae005eecbbc0` — exact-source overlap; business patch owns the row.

### `not-ai-ledger-patches.jsonl`

- `alias-0d3bd8c784475190b98074e6`
- `alias-588f479c8353c335cc5aea90` — exact-source overlap; business patch owns the row.
- `alias-7c7ceaa679ef609d302575e1`
- `alias-c12c46f6239faabff2fc306c`
- `alias-c819cf08c0a8bf17cf425ccc` — exact-source overlap; business patch owns the row.

### `cve45582-ledger-patch.jsonl`

- `alias-ad08edcf98825ffa3306395b`

### `fail-rereview-ledger-patches.jsonl`

- `alias-303ca6a3bcd91ac79f484238` — GHSA-8X4M-QW58-3PCX; excluded from gate backfill by its prior explicit `FAIL` vector.
- `alias-a57df415a930e4db1ef3b6f7` — GHSA-8G98-M4J9-QWW5; excluded from gate backfill by its prior explicit `FAIL` vector.

The two NOT_AI overlaps remain owned entirely by `not-ai-ledger-patches.jsonl`: `alias-588f479c8353c335cc5aea90` and `alias-c819cf08c0a8bf17cf425ccc`. Gates are intentionally not restored to those NOT_AI rows.

## Validation

- Parsed all 214 JSONL lines independently; exact top-level schema is `{expected_revision,row,assessment_ids}` and every `assessment_ids` list is empty.
- Confirmed sorted/unique class IDs, zero overlap with all 38 auxiliary-patch IDs, pairwise-disjoint auxiliary files, exact seven gate keys, no `FAIL`, and line-specific source paths.
- Rebuilt all 214 expected vectors from the reconciliation sources and matched `gates`, `gates_source`, and derived tier exactly.
- Re-read all 29,593 Neon rows. Every `expected_revision` matched: revision 1 = 178, revision 2 = 30, revision 3 = 6.
- Ran `scripts.ledger_store.validate_update(old, new)` on every line and confirmed that, after removing the three gate fields, each new row is identical to its Neon base row.
- Neon snapshot/export SHA-256 at validation: `59699d7ab3e102cd08907aee1135bc6f0097cdbbe0db55a685571cce9d28fbc2`.

Re-check revisions immediately before any later `ledger_store.py apply`; this draft does not reserve rows or prevent concurrent updates.
