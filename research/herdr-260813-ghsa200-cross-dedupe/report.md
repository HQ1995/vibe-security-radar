# Cross-shard dedupe and release-containment adversarial layer - report

Date: 2026-08-13
Lane: `autoresearch/herdr-260813-ghsa200-cross-dedupe/`
Role: veto / narrow / route. This lane emits no PASS rows, promotes no case, and
writes nothing outside its own directory.

## Verdict

1. The frozen fp211 public-ID projection is **alias-clean at the ID level**: no
   CVE is claimed by more than one GHSA, no GHSA case is also used as an alias,
   and no disposition maps one public ID to multiple cases. Zero exact
   CVE/GHSA alias-class duplicates.
2. There are **no duplicate-case-id split rows** and **no case that carries
   more than one `mechanism_key`** in the projection. The one cross-advisory
   overlap (ChurchCRM ordinal 200) is a same-mechanism/different-ID overlap,
   not a split.
3. The projection contains **substantial shared-SHA structure that must never
   be deduplicated by SHA alone**: 25 candidate SHAs, 9 fix SHAs, and 8 carrier
   SHAs are each shared across two or more distinct mechanisms. Five clusters
   share *both* candidate and fix and are all distinct mechanisms.
4. The deterministic checker re-derives the canonical overlay's **exactly two
   DUPLICATE rows** (coolify shell-grammar, coolify activity-scope) from a
   SHA-free source/sink/invariant fingerprint plus first-party identity - not
   from SHA overlap - and classifies all 77 shared-SHA pairs as DISTINCT.
5. Release containment was **git-verified 14/14** on every PASS row with a
   local clone: the vulnerable tag contains the candidate (carrier), the fixed
   tag contains the fix, and the fix is absent from the vulnerable tag.
6. The five batch1 terminal proposals are **all MISSING release evidence** and
   cannot be release-certified; three of them are the same-advisory split rows
   for `GHSA-8G7G-HMWM-6RV2` (n8n-mcp), correctly classified
   ALIAS_SAME_COMPONENT.

## Audit of the public-ID projection

Inputs (frozen): `final_mechanisms.jsonl` (211), `public_cases.jsonl` (212),
`public_id_dispositions.jsonl` (381), canonical `ledger.jsonl` (216 component
rows).

### A - exact CVE/GHSA alias-class duplicates: none

- `cve_claimed_by_multiple_ghsa`: `{}`
- `disposition_rows_with_multiple_cases`: `[]`
- `case_id_also_used_as_alias`: `[]`

Every public ID maps to exactly one case. Formal CVE<->GHSA aliases are carried
inside a single case's `aliases`, not spread across case rows.

### B - same-advisory split rows: none at the case-id level

- `duplicate_case_id_rows`: `{}` (212 distinct `case_id`s)
- `cases_with_multiple_mechanism_keys`: `{}`

### C - same candidate/fix but distinct mechanisms: 25/9/8 shared SHAs

Shared-SHA census across the 211 mechanisms:

| dimension | shared SHAs | shared across 2+ ordinals |
|---|---:|---:|
| candidate | 25 | yes |
| fix | 9 | yes |
| carrier | 8 | yes |

Five clusters share *both* candidate and fix; every one is a **distinct
mechanism** (checker verdict DISTINCT):

| cluster | ordinals | verdicts |
|---|---|---|
| `4286755f..` / `5b4121d6..` | 31, 58 | NARROW / CONFIRM |
| `847d08bd..` / `64511ce4..` | 165, 166 | FALSE_POSITIVE / CONFIRM |
| `47bf71cc..` / `8aa2bb6d..` | 61, 67 | NARROW / FALSE_POSITIVE(same_mechanism_duplicate) |
| `3cd664bf..` / `179cab02..` | 127, 128 | CONFIRM / CONFIRM (PraisonAI ssrf vs python-exec) |
| `5afeaf6b..` / `c7101fcb..` | 158, 159 | FALSE_POSITIVE / FALSE_POSITIVE |

The PraisonAI pair is the canonical counterexample to SHA-based dedup: one
fix commit closes two unrelated mechanisms.

### D - same mechanism under different IDs

- One `mechanism_key` spans two advisories: `churchcrm-notes-object-scope-authorization`
  -> `GHSA-3J8Q-FWPJ-F8J5` + `GHSA-JJCJ-H3CM-P7X7` (cross-advisory same-component
  overlap, not a formal alias). Checker verdict **ALIAS_SAME_COMPONENT**; the
  canonical overlay already stores it as one component `posthold:G01`.
- The frozen audit already declared two `duplicate_of` rows: ordinal 67
  (`same_mechanism_duplicate` -> ordinal 61) and ordinal 68 (`identity_mismatch`
  -> ordinal 35). These are first-party audit declarations, not SHA inferences.

## Checker

`dedupe_checker.py` is deterministic and stdlib-only. Modes: `audit`, `check`,
`self-test`.

### Fingerprint (SHA-free by construction)

`semantic_fingerprint = sha256({repository, source, sink, invariant})`.
`mechanism_key` is deliberately **excluded** - it is a pre-existing label and
must never be sufficient for a duplicate. `source/sink/invariant` are read
directly or parsed from the `mechanism`/`scope_statement` text.

### Classification precedence

| condition | verdict |
|---|---|
| missing identity or mechanism evidence | UNKNOWN |
| SAME fingerprint + same ID / formal alias | DUPLICATE |
| SAME fingerprint + first-party `duplicate_of` linkage | DUPLICATE |
| SAME fingerprint + different non-aliased IDs (any SHA or identical affected range present) | CONFLICT |
| KEY/TEXT match + same ID / alias | ALIAS_SAME_COMPONENT |
| KEY/TEXT match + different non-aliased IDs | CONFLICT (never merge on key alone) |
| same ID / alias + distinct mechanism | ALIAS_SAME_COMPONENT (split rows) |
| shared SHA only, distinct mechanism + advisory | DISTINCT |
| distinct advisory + distinct mechanism | DISTINCT |

### Acceptance correction encoded as negative controls (`self-test`)

| control | premise | verdict |
|---|---|---|
| nc1 | shared candidate + fix, distinct mechanisms | DISTINCT |
| nc2 | same mechanism + shared candidate/fix, no alias identity | CONFLICT |
| nc3 | same `mechanism_key`, different IDs, no alias | CONFLICT |
| nc4 | same public ID + same mechanism | DUPLICATE |
| nc5 | formal alias + same mechanism | DUPLICATE |
| nc6 | same public ID, distinct mechanisms | ALIAS_SAME_COMPONENT |
| nc7 | two advisories, same repo, row-local FORMAL_ALIAS | DISTINCT |

All seven pass. In particular nc2/nc3 pin the correction: an umbrella commit
(candidate+fix) and a pre-existing `mechanism_key` are **never** sufficient for
DUPLICATE; the "independently demonstrated exact source/sink/invariant/affected
range/PoC with publication equivalence" path is surfaced as CONFLICT for human
adjudication, never auto-merged.

### Release containment check

Per-row `release_check` validates declared evidence: vulnerable tag/version
precedes fixed tag/version, candidate != fix, `candidate_in_vulnerable` not
false, `fix_in_fixed` not false, `fix_in_vulnerable` not true, and the
vulnerable tag falls within the advisory affected range when
`advisory_*_version` is present.

Empirical git verification (14 PASS rows with local clones) confirms
candidate-in-vulnerable-tag, fix-in-fixed-tag, fix-not-in-vulnerable-tag for
all 14.

## Results on the effective publication corpus

- Canonical overlay (216 component rows, 23 220 pairwise relations): **2
  DUPLICATE, 77 DISTINCT (shared-SHA), 0 CONFLICT, 0 UNKNOWN, 0
  ALIAS_SAME_COMPONENT**. The overlay is currently conflict-free; its only two
  duplicates are the two coolify pairs it already marks DUPLICATE.
- Batch1 terminal proposals (5): three n8n-mcp rows share `GHSA-8G7G-HMWM-6RV2`
  and classify ALIAS_SAME_COMPONENT (one case, three mechanisms); release
  containment is MISSING for all five.

## Boundary / blockers

- This lane never counts, promotes, or edits canonical/publication files.
- The frozen `public_cases.jsonl` carries `mechanism_key` for only 131 of 212
  rows and no source/sink/invariant, so full SHA-free fingerprinting is only
  possible against the canonical overlay's `mechanism` text and future
  proposals that carry a `scope_statement`/`mechanism`.
- Five batch1 proposals lack release evidence and are routed back for
  release-containment before any counting is possible.
