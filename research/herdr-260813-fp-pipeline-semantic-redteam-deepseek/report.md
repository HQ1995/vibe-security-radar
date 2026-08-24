# Semantic acceptance review - fp211 canonical overlay, publication admission helper, effective publication corpus

Date: 2026-08-13
Reviewer: independent DeepSeek semantic acceptance reviewer (read-only; no shared
pipeline file was modified, committed, or pushed)
Verdict: **ACCEPT**

## Verdict first

The fp211 canonical overlay (`autoresearch/orchestrator-260813-fp211-canonical/`),
the publication admission helper (`scripts/cohort/publication_admission.py`),
and the effective publication corpus
(`scripts/publication_adjudications.json`, sha256 `bfec060f...`, the
`publication_adjudications_sha256` pinned by the leader baseline) mechanically
exclude every learned false-positive class from released publication. The
corpus admits exactly 48 first-party GHSA cases, all CONFIRM/HIGH with all
seven gates PASS and released containment; nothing else is labeled publishable.
The corpus itself declares `publication_ready=false`, which is the correct
contract state: 48 strict released cases do not support a >200 claim
(baseline: 153 net admissions still required). No semantic blocker found.

## Requirement-by-requirement evidence

### 1. All learned false-positive classes are mechanically excluded

The 54 `FALSE_POSITIVE` rows in `final_mechanisms.jsonl` carry 17 distinct
learned classes. Every one maps to admission `EXCLUDE`, `may_publish=false`,
and a non-`AI_CAUSAL` label in the corpus:

| requirement class | learned class(es) | rows | excluded |
|---|---|---:|---:|
| wrong edge | WRONG_EDGE, wrong_edge | 20 | 20 |
| old bug/refactor | old_bug_preserving_refactor, OLD_BUG_PRESERVING_REFACTOR | 8 | 8 |
| carrier-vs-member | not_origin_of_named_mechanism | 3 | 3 |
| insufficient fix reversal | different_invariant, preexisting_incomplete_predicate, HUMAN_WEAKENED_AI_PREDICATE | 4 | 4 |
| identity mismatch | identity_mismatch | 1 | 1 |
| duplicates | same_mechanism_duplicate | 1 | 1 |
| causal-but-unreleased (release-only) | unreleased_commit_only, unreleased_dangerous_revert, unreleased_counted_as_released | 7 | 7 |
| other learned negatives | unattempted_env_family, sibling_endpoint_unattempted_old_bug, unattempted_route_preflight, not_causal | 10 | 10 |

Mechanical guarantees in the helper: CONFIRM requires all seven gates PASS/NA
(error otherwise); FALSE_POSITIVE requires a fatal FAIL gate; UNKNOWN/BLOCKED
require an unresolved gate and yield HOLD (`unresolved_unknown`); NARROW
requires an explicit NARROW gate and yields HOLD; ADMIT additionally requires
confidence HIGH, `source_tier` in {STRICT_RELEASED, INCOMPLETE_RELEASED}, and
`release_gate=PASS`. Commit-only tiers yield HOLD
(`commit_only_not_released`); CONFIRM/MEDIUM yields HOLD
(`confirm_requires_high_confidence`).

### 2. One case counted by first-party GHSA identity

All 212 corpus fp rows are keyed by unique `GHSA-*` case ids (the
`public_cases.jsonl` `case_id`); CVE aliases never create rows. Example:
`CVE-2026-10855` appears only as an alias of exactly one row
(`GHSA-243V-5F97-VFQ3`, ordinal 73, ADMIT). The 48 ADMIT case ids are pairwise
subject-disjoint, so no alias bridge double-counts them.

### 3. Public-ID keep/remove conservation

Per row, `public_ids_keep U public_ids_remove == manifest public_ids`
(builder hard-errors otherwise) and the two sets are disjoint. Globally:
371 unique kept + 10 removed = 381 source-declared public ids, exactly
matching the canonical overlay structural counts. Corpus `excluded_aliases`
equals `public_ids_remove` per row, and no removed id appears as any corpus
subject.

### 4. Ten tombstones

`summary.removed_public_ids` contains exactly 10 ids (5 CVE, 5 GHSA; listed in
`result.json`). The web-data loader treats `excluded_aliases` as tombstones:
transitive alias expansion cannot resurrect a removed id
(`test_excluded_alias_tombstone_blocks_transitive_source_expansion`,
`test_default_alias_expansion_does_not_resurrect_removed_fp211_ids` - both pass
against the live corpus).

### 5. Shared SHA never implies duplication

Five ADMIT pairs share candidate/minimum-fix SHAs
(`847d08bdd...`, `4286755f26bc...`, `db97de475518...`, `079af0d0b...`) and
both members of every pair remain ADMIT with `uniqueness_gate=PASS`.
`herdr-260813-ghsa200-cross-dedupe/dedupe_checker.py` codifies the rule:
shared SHA ALONE never yields DUPLICATE; DUPLICATE requires a SHA-free
semantic match AND a formal alias/component identity link (negative controls
nc1 DISTINCT, nc2 CONFLICT).

### 6. Duplicates

Two fp rows declare `duplicate_of` (GHSA-4VFF-6J8J-QHCG,
GHSA-CJP7-PM9Q-XHQG); both are FALSE_POSITIVE with `uniqueness_gate=FAIL` and
admission EXCLUDE. Their targets exist in the canonical ledger with states
UNKNOWN and NARROW (admitted=false), so no mechanism is counted twice. The
canonical verify pins ordinals 67/68 duplicate_of to canonical row keys.

## Replays (all read-only against shared tree; bytecode writing disabled)

- `python3 autoresearch/orchestrator-260813-fp211-canonical/build.py --check`
  -> byte-identical regeneration PASS
- `python3 autoresearch/orchestrator-260813-fp211-canonical/verify.py` -> PASS
  (211 hypotheses; verdicts 65/54/83/9; publication=HOLD)
- canonical `unittest test_canonical` -> 5/5 OK
- `python3 scripts/build_publication_adjudications.py --check` -> current
- pytest (venv 3.13): `test_cohort_publication_admission.py`,
  `test_build_publication_adjudications.py`, `test_web_data_loader.py` ->
  51/51 passed
- unified verifier `verifier.py --output /tmp/uverif-result.json` -> byte-
  identical to shared `result.json` (HOLD, 5 blockers); `test_verifier.py` ->
  12/12 OK
- leader `verify_baseline.py` -> PASS (frozen baseline 48 strict released;
  106 disjoint upgrades; gap 153)

## Adversarial mutations (temp copies only; source untouched)

Corpus/helper (20/20 expected failures or holds observed):
release-gate NA/UNKNOWN flips (ADMIT drops 48->47, HOLD), tombstone
resurrection into keep or case aliases (builder exits 2), UNKNOWN with all
gates PASS (exit 2), FALSE_POSITIVE without FAIL (exit 2), MEDIUM demotion
(HOLD), NARROW without NARROW gate (exit 2), duplicate_of without uniqueness
FAIL (exit 2), duplicated case_id (exit 2), same kept GHSA across two
ordinals (exit 2), corpus label tamper detected as stale (exit 2), shared
candidate SHA injected into a second admitted row (both still ADMIT -
positive control).

Canonical overlay mirror (4/4 fail closed, exit 1): tampered
`final_mechanisms.jsonl` input (sha256 pin), tampered `ledger.jsonl` output
(byte-identity in both `build --check` and `verify`).

## Non-blocking observations

- OBS-1: 8 release-only/duplicate FALSE_POSITIVE rows are labeled
  INCONCLUSIVE (not NOT_AI_CAUSAL) because `_label` requires a decisive
  noncausal gate FAIL. They remain EXCLUDE and unpublished; label nuance only.
- OBS-2: `herdr-260813-ghsa200-unified-verifier/report.md` claims 30 blockers
  while the reproducible `result.json` shows 5; report is stale documentation.
  The lane is HOLD either way; no corpus impact.
- OBS-3: 5 legacy base rows labeled AI_CAUSAL (March-July 2026 audit vintage)
  coexist with the 48 fp211 ADMIT rows; they are outside the seven-gate
  discipline and outside the strict released bound. The corpus is
  `publication_ready=false`; the >200 claim remains unsupported, as the
  contract requires.

## Conclusion

ACCEPT. The exclusion mechanics are complete, deterministic, and fail closed
under adversarial mutation; counting is by first-party GHSA identity with
conservation and ten tombstones enforced; shared SHAs do not collapse cases;
and the corpus honestly reports publication_ready=false at 48 strict released
cases.
