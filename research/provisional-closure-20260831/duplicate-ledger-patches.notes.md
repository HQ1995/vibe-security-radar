# Duplicate-ledger patch draft notes

Date: 2026-08-31

This is a non-applied Neon ledger patch draft rebuilt from four fresh, full `ledger_store get` rows.

| class_id | expected revision | draft action |
|---|---:|---|
| `alias-0a97ba3bb4787b9352f519d1` | 1 | Retain the reviewed vendor class; preserve `GHSA-8h88-gxp3-j7pg` and add `GHSA-723W-CRW6-P9HX` plus `CVE-2026-74876`. |
| `alias-7a67e4c2cdfe7bc6ade411ee` | 2 | Preserve its advisory IDs and fold it into `GHSA-8H88-GXP3-J7PG` with `site_publication.publish=false`. |
| `alias-0ae1e9b85f4a9eebb8ee56b3` | 3 | Retain the merged Whirlpool class; preserve CCP9/CVE IDs, add reviewed vendor ID J48Q, and publish the accurate unpatched state. |
| `alias-bf499d08da8dae005eecbbc0` | 2 | Preserve its advisory ID and fold it into retained J48Q with `site_publication.publish=false`. |

For the retained Whirlpool row, the publication-authoritative fields are top-level: `candidate_set=[cb07e5f8…]`, `carrier_set=[f6770c1e…]`, `minimum_fix_set=[]`, `fixed_release=null`, and `unpatched.confirmed=true`. The same unpatched record is mirrored into the selected causal record so that record remains independently complete.

The retired J48 row also carries `minimum_fix_set=[]`, `fixed_release=null`, and the explicit unpatched record. Its historical `963d0d1…` `fix_sha/direct_fix_sha` values are cleared; the legacy reversal/release/uniqueness gates are corrected to FAIL, and the prose now states that the commit leaves the direct loaders intact. Commit `fdb5d72999914f5604a419225949db669d4be3f2` appears only as `potential_fix.reference_commit`; it is never a minimum fix or fixed-release claim.

The retained row's seven PASS values are sourced by `gates_source=provisional-closure-20260831/duplicate-second-review`. Release PASS records the verified absence of a containing public release through v1.4.9, while `fixed_release` remains null. Both retired rows are filtered by `site_publication.publish=false`.

Draft schema is exactly `{expected_revision,row,assessment_ids:[]}`. No advisory ID from a live row is removed. No database apply, ledger export, publisher run, generated-data write, or commit was performed; refresh optimistic revisions if any live row changes before apply.
