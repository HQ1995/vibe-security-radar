# Web Publication Pipeline Audit

Date: 2026-08-14

## Verdict

Do not rewrite the release pipeline. Its atomic writer, evidence archive,
receipt, and verifier machinery remain useful. Replace only the legacy semantic
projection from CVE-level model labels to public case data.

The current site must remain a legacy snapshot. Neither canonical84 nor the
effective publication adjudication artifact is publication-ready.

## Root cause

The old public-data path collapses case-level labels into an ID allowlist:

```text
CVE-level AI_CAUSAL
  -> audit override ID
  -> complete analyzer result
  -> every AI-signal BIC subject
  -> public bug_commits[] and model evidence
```

This is not a causal binding. In the current 36-page snapshot, 145 routed
subjects include 55 model `CONFIRMED`, 23 `UNLIKELY`, 58 `UNRELATED`, and 9
unresolved rows. The old top-level label cannot identify the authoritative
candidate, carrier, or minimum-fix sets.

The shared release entry point also accepted a builder-current adjudication
artifact without checking `artifact_kind` or `publication_ready`. The checked-in
artifact says `publication_ready: false`.

## Decision

Keep:

- `scripts/web_data/writer.py`
- `scripts/web_data/release_evidence.py`
- `scripts/web_data/verifier_contract.py`
- inventory, statistics, TypeScript generation, staging, and atomic promotion

Replace after a READY canonical artifact exists:

- the CVE-label and `audit_overrides` publication projection
- raw public `BugCommit`, model reasoning, confidence, and signal-text fields
- runtime alias deduplication that prefers CVE IDs

The future primary case ID is the first-party GHSA identity. CVE and other IDs
are aliases or redirects, not additional cases.

## Immediate safeguards

This audit added the following fail-closed behavior:

1. Formal generation rejects the wrong adjudication artifact kind.
2. Formal generation rejects `publication_ready` unless it is exactly `true`.
3. The JavaScript release loader consumes receipt schema v5 and rejects v4.
4. The JavaScript inventory contract validates Python's `stage_predictions`.
5. Standalone output tracing includes `data/inventory.json`.
6. The catalog client receives a summary DTO instead of full BIC and model
   evidence. The current serialized payload falls from 366,461 to 16,793 bytes.
7. Legacy detail pages publish no causal commit, fix edge, model reasoning, or
   raw signal. They explicitly withhold code evidence.
8. Recharts and its unused wrapper were removed; trend and distribution charts
   are server-rendered HTML and CSS.
9. The displayed canonical count, status, and ledger hash are pinned to the
   tracked canonical84 summary by its SHA-256 and a regression check.

## Required canonical input

A future publisher should consume one immutable `canonical_publication_cases`
artifact with global READY gates and exact case rows containing:

- `case_id`, aliases, tombstones, repository, and analysis subject
- canonical row key and source hashes
- contribution class
- independent `candidate_set`, `carrier_set`, and `minimum_fix_set`
- all seven gate results
- vulnerable and fixed release-containment witnesses
- row, ledger, manifest, and artifact provenance hashes

Sets must remain sets. The projector must not manufacture a Cartesian
candidate-to-fix edge. Carrier metadata must not transfer AI authorship to a
human member or vice versa.

## Minimum admission tests

- Reject global HOLD before reading campaign results or staging output.
- Require a one-to-one exact join between canonical cases, adjudications, and
  campaign analysis subjects.
- Reject missing, extra, duplicate, malformed, or tombstoned public IDs.
- Require exact equality of candidate, carrier, and minimum-fix sets.
- Reject missing or mutable release witnesses.
- Reject any public raw BIC, model verdict, reasoning, confidence, or signal
  text field.
- Preserve output under alias input reordering; reject conflicting aliases.
- Bind all canonical source and case hashes into the release receipt.

## Current boundary

The 36 existing pages are legacy records only. Canonical84 remains HOLD, so no
canonical case pages or annotated code diffs were generated in this change.
When a publication-ready canonical artifact lands, the detail page can render
frozen parent-to-candidate and candidate-or-carrier-to-minimum-fix hunks without
browser-time inference or network fetches.
