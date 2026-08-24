# Publication Pipeline Structural QA — herdr-260813-publication-structural-deepseek

**Mode:** independent, read-only structural QA. Temp mutations only; no shared implementation edits.
**Date:** 2026-08-13 · **Worktree:** 1287ccd ("Gate publication on causal audit")
**Overall:** PASS on all nine structural checks, with one forward fail-closed blocker found by synthetic probe (no current-corpus impact).

## What was checked

Scope: `scripts/build_publication_adjudications.py`, generated effective corpus `scripts/publication_adjudications.json`, `scripts/web_data/loader.py`, `scripts/generate_web_data.py`, both evaluators, `scripts/cohort/publication_admission.py`, and their tests.

## Findings

### 1. 257-class expansion — PASS
The effective corpus contains 257 adjudication rows = 45 preserved base rows + 212 fp211 public cases. The base file has 78 rows: 33 whose subjects overlap the fp211 source public-ID universe are replaced; the other 45 are preserved. A rebuild from the committed inputs is byte-identical to the committed corpus, and `build_publication_adjudications.py --check` exits 0. The count is reproducible: 257 rows, 419 distinct subjects, labels AI_CAUSAL 53 / NOT_AI_CAUSAL 83 / INCONCLUSIVE 121.

### 2. Base preservation — PASS
All 45 preserved rows deep-equal their originals in `scripts/audit_adjudications.json` (spot-check: CVE-2025-64420 identical). No base subject duplication; base and fp211 subject universes are disjoint.

### 3. fp211 replacement — PASS
211 final mechanisms, 211 manifest rows, 212 public cases; every mechanism has at least one case and every case's row_key/verdict/confidence/causal_class/source_tier match its joined mechanism and manifest. Every case maps to exactly one corpus row with identical case_id and aliases (212 == 212). Ordinal 200 is the sole two-case mechanism — two distinct GHSA-led identity pairs (GHSA-3J8Q-FWPJ-F8J5 ↔ CVE-2026-58407; GHSA-JJCJ-H3CM-P7X7 ↔ CVE-2026-58410) whose union equals the mechanism's kept public IDs. The fp211 artifact verifier (`verify.py`) also passes 211/211 shard rows.

### 4. Ten tombstones — PASS
`removed_public_ids` has exactly 10 entries (5 CVE + 5 GHSA). Each appears exactly once as an `excluded_alias` and never as `cve_id` or `alias` anywhere in the corpus. Loader tombstone semantics verified in-memory: excluded aliases are filtered during transitive alias expansion and cannot be resurrected, including across adjudication rows.

### 5. Alias/class conservation — PASS
For all 211 mechanisms: `public_ids_keep ∪ public_ids_remove == manifest public_ids` and keep/remove are disjoint (0 failures). Per mechanism, public case subjects equal the kept IDs exactly. Globally, keep (371 IDs) and remove (10 IDs) universes are disjoint across mechanisms, and no identity appears in two corpus rows. Conflicting labels for one alias class, and duplicate same-label overlaps, raise ValueError (fail closed).

### 6. No leak classes — PASS
- FALSE_POSITIVE → AI_CAUSAL: 0 rows.
- UNKNOWN → AI_CAUSAL: 0 (9 UNKNOWN/MEDIUM rows all INCONCLUSIVE).
- CONFIRM/MEDIUM → AI_CAUSAL: 0 (14 rows all INCONCLUSIVE/HOLD).
- Removed IDs absent from every subject.
- Release-only rows (8 FALSE_POSITIVE with release_gate FAIL and all decisive gates PASS) are labeled INCONCLUSIVE, never NOT_AI_CAUSAL.
- FALSE_POSITIVE total 54 → 46 NOT_AI_CAUSAL (decisive gate FAIL) + 8 INCONCLUSIVE (release-only).
- AI_CAUSAL fp rows (48) equal exactly the mechanisms with `may_publish`; every admitted row is CONFIRM/HIGH on a released tier (34 STRICT_RELEASED, 14 INCOMPLETE_RELEASED).
- Independent re-computation of admission + `_label` for all 211 mechanisms matches the committed corpus with 0 mismatches.

### 7. Source-hash fail-closed — PASS
`--check` compares the complete canonical artifact bytes, including `provenance.input_sha256`, so the committed corpus is bound byte-for-byte to all six sources (base, final mechanisms, manifest, public cases, builder source, admission helper). Temp-mutation probes all exited 2:
- relabeled committed corpus → stale;
- tampered final-mechanism verdict → stale;
- mutated builder copy (label inversion) → stale;
- mutated helper copy — even an adjudication-neutral change — → stale via provenance hash binding.

Generator: a semantically tampered (relabeled) corpus raises `ReleaseGateError` in `_release_input_hashes`; a current corpus binds 64-hex hashes for all seven related sources including the new fp211 inputs; the release phase loop re-checks the hash set each phase. Loader: schema_version ≠ 1 or malformed JSON → ValueError; current corpus loads 257 rows. Any builder failure exits non-zero, so the generator's subprocess gate cannot pass on failure.

### 8. One GHSA identity = one case — PASS
All 212 public cases have GHSA canonical case_ids; all 212 GHSA identities are unique; no case subject appears in two cases; no GHSA appears in the keep or remove set of two mechanisms. The builder rejects duplicate case identity, enforcing the invariant on future inputs.

### 9. Strict PASS-vs-NA future-input check — FORWARD BLOCKER FOUND (no current impact)
Current state is clean: all 48 released ADMIT rows have all seven gates strictly PASS with zero NA; only `release_gate` ever carries NA in current data (ordinals 132, 136, 152, 155, 157, 181), all on commit-only tiers, all held or excluded (`may_publish` false). No released-tier row carries NA today.

Forward blocker: `_closed_gate` in `scripts/cohort/publication_admission.py` treats NA as closed, and `released_publication_admitted` strictly checks only `release_gate == "PASS"`. A synthetic released row (STRICT_RELEASED, CONFIRM/HIGH, `topology_gate=NA`, `release_gate=PASS`, all other gates PASS) yields `may_publish=true`, ADMIT, no errors. The fp211 leader contract requires all required gates for the row's claimed scope to close for CONFIRM and forbids inferring PASS from absence of evidence, so a future released row with any non-release causal gate NA would be admitted — and then labeled AI_CAUSAL by the builder — in violation of the contract. Current corpus counts are unchanged because no such row exists.

Recommendation (not applied, read-only QA): for released publication tiers, require all seven gates `== "PASS"` inside `released_publication_admitted`, keeping NA-as-closed only in the CONFIRM-validity computation where NA legitimately marks out-of-scope gates on commit-only rows.

## Test run

543 passed / 0 failed across 14 files:
- `test_build_publication_adjudications.py`, `test_cohort_publication_admission.py`, `test_publication_quality.py`, `test_web_data_loader.py`: 71 passed
- `test_release_evidence.py` (release fixture suite, previously not-rerun): 118 passed
- `test_generate_web_data.py`, `test_detector_quality.py`: 79 passed
- `test_release_promotion.py`, `test_published_web_data.py`, `test_web_data_entry.py`, `test_web_data_filters.py`, `test_web_data_schema.py`, `test_web_data_severity.py`, `test_web_data_writer.py`: 275 passed

Environment: Python 3.13.7 via uv (cve-analyzer project), pytest 9.0.2.

## Hygiene

All mutations ran under `/tmp/pubqa-260813` (sandbox copies, tampered inputs, mutated builder/helper copies restored afterward). The committed corpus was never rewritten (builder probes used temp outputs or `--check`, which never writes). Git status of the six scoped scripts is unchanged from session start; no commit/push performed.
