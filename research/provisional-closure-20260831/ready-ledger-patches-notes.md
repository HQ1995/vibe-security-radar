# Ready ledger patch draft

This is a non-applied Neon patch draft assembled from `shard-01.md` through
`shard-05.md`. `ready-ledger-patches.jsonl` contains 26 complete current rows
with optimistic `expected_revision` values and empty `assessment_ids`.

## Included decisions

- 19 rows have seven `PASS` gates and `site_tier=ALL_GATES_PASS`.
- 7 rows have only `PASS`/`NARROW` gates and
  `site_tier=PARTIAL_EVIDENCE`: Q8HH, H5RM, GVQ9, WVPP, W9RM, 64VR, and
  CVE-2026-42278.
- Every row has exactly the seven named gates and a shard-local
  `gates_source` such as `provisional-closure-20260831/shard-01`.
- P7MM is normalized to `status=AI_ROOT_CAUSE`,
  `ledger_best=AI_ROOT_CAUSE`, and `site_scope=AI_ROOT_CAUSE`: its
  Claude-marked candidate is the first writer of the reachable vulnerable
  flow, not a later flawed remediation.
- Candidate, carrier, minimum-fix, scope, release, and unpatched fields were
  changed only where the corresponding shard report gave a concrete value or
  a bounded statement.
- The vLLM row also stores its reader-facing `code_evidence` canonically: three
  candidate hunks, three production fix hunks, distinct annotations, selected-
  hunk hashes, and the review source in `code_evidence_source`.

## Deliberate omissions

No merge-only, `NOT_AI_REVIEW`, or `RESEARCH_GAP` row is present. In
particular, this excludes GHSA-723W, GHSA-J48Q, GHSA-5383, and all causal or
release negatives listed in the shard reports.

The draft does not invent schemas for these report-only facts:

- H5RM's two-stage loader/MCP lower bound and its release-specific fix variants.
- 2664's branch-specific fix edges beyond the reported canonical minimum fix.
- GVQ9's development-server versus PyPI artifact boundary.
- VCV2's per-candidate carrier edge object; the scope text preserves that the
  carrier belongs only to the first candidate.
- W9RM's `v1.3` first-release-containing-fix fact; both release fields are
  explicitly null because no vulnerable release existed.
- 64VR's `v3.260302.2` successor-removal witness; the affected v2 line is
  recorded as unpatched and `fixed_release` is null.
- CVE-2026-42278's human exploit-completing contributor, exact commit interval,
  and deleted-upstream availability note; both release fields are null.
- HHFF's dormant human origin and other auxiliary parent/provenance metadata.

These facts need an agreed ledger field or existing nested structure before
they are added. The current publisher already gives top-level row candidates,
carriers, fixes, scopes, and release fields precedence, including explicit
null release values.

## Validation

The file was parsed line by line and as one JSONL set. It has 26 lines, 26
unique `class_id` values, exact top-level patch schema
`{expected_revision,row,assessment_ids}`, 19/7 tier accounting, and exact
seven-gate keys. Each untouched part of every complete row was compared with a
fresh `ledger_store.py get`, and all 26 revisions still matched at validation
time (13 at revision 1 and 13 at revision 2).

No database transaction, ledger export, publisher run, generated-data update,
test change, or commit was performed.

The targeted P7MM correction was revalidated against the live revision-2 row
with `ledger_store.validate_update()` on 2026-08-31; the optimistic revision
still matched. This targeted refresh does not reassert the revisions of the
other 25 unapplied rows.

The vLLM evidence merge was independently verified against local full Git in
`research/summary-readability-20260831/vllm-78684-annotated-diff.md`; its row
still targets live revision 2, and both selected-hunk hashes were recomputed
after the merge.
