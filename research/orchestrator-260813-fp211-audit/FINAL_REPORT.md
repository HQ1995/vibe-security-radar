# Canonical 211 false-positive audit — final report

Date: 2026-08-13

Pinned baseline: `cd97a295956a8d3d46330bf9b0300ddded21f737`

First-pass commit: `e0491f7e1b6773fe3f6126bcf1364df7a19f2373`

Independent cross-review commit: `48853c0031625ad6c203f31d3f834cc17d4d46cf`

## Answer

The old number **211 was not a case count**. It was a mechanism-component hypothesis inventory.

After a complete first pass, a different-worker second pass over all 211 rows, and third-party adjudication of all 45 row-level disagreements:

| Unit | CONFIRM | NARROW | FALSE_POSITIVE | UNKNOWN | Total | Causal-valid |
|---|---:|---:|---:|---:|---:|---:|
| Public GHSA/CVE cases | 65 | 84 | 54 | 9 | 212 | **149** |
| Mechanism components | 65 | 83 | 54 | 9 | 211 | **148** |

`CONFIRM` is the strict publication-grade subset. `NARROW` still has a real AI causal contribution, but only under the scope recorded in the row. It must not be described as a strict first-root result. `UNKNOWN` is excluded from both valid counts.

This audit does **not** support a 200-case claim.

The one case/mechanism difference is ChurchCRM ordinal 200: two distinct first-party advisories, `GHSA-3J8Q-FWPJ-F8J5` / `CVE-2026-58407` and `GHSA-JJCJ-H3CM-P7X7` / `CVE-2026-58410`, overlap on one notes-authorization mechanism but are not formal aliases. They count as two public cases and one mechanism component.

## Public-ID accounting

The frozen input contained 381 unique public IDs: 217 GHSA and 164 CVE.

- 212 GHSA case identities are retained.
- 159 CVEs are retained as their associated public IDs.
- 5 GHSA plus 5 CVE identities are removed because they were polluted, packed sibling identities, or unproven wrappers for the audited mechanism.
- Every one of the 381 input IDs occurs exactly once in `public_id_dispositions.jsonl`; there are no missing or multiply assigned IDs.

Case counting uses a first-party GHSA as `case_id`. A formal CVE alias is associated with that case. Multiple mechanisms inside one GHSA do not multiply cases. Multiple GHSAs merge only on formal alias or duplicate-publication proof; same repository, fix, or mechanism is insufficient.

## Audit method

1. Six Grok 4.6 workers audited disjoint deterministic shards covering all 211 components.
2. The same six tabs were cleared and rotated to other shards. Every row received a second independent review against first-party advisories and Git parent/candidate/fix/release evidence.
3. First and second passes disagreed on 15 verdicts and 45 verdict/gate/public-ID fields. A deterministic builder distributed those 45 rows to a third reviewer who was neither the first nor second reviewer for that row.
4. Third reviewers produced full final rows; no majority vote was used. Unclosed evidence could remain `UNKNOWN`.
5. Final builders conserved 211 mechanisms, 212 public cases, and 381 public IDs. All outputs replay byte-identically.

Mechanical coverage was never treated as causality. OSV `introduced`, matching fix references, ancestry intersections, model labels, and prior reports were routing evidence only. Required proof included relevant-hunk AI provenance, topology, but-for causality, minimum fix reversal, release containment, and identity/uniqueness.

## Main false-positive lessons

The 54 rejected mechanisms cluster into reusable failure modes:

- `wrong_edge`: 20. The candidate/fix pair was a sibling, later change, multi-purpose mismatch, or did not reverse the named mechanism.
- `old_bug_preserving_refactor`: 8. Removing the AI refactor leaves the same exploit path in its parent.
- `unattempted_env_family`: 7. A candidate that hardens one environment-key family is not incomplete remediation for sibling keys it never attempted.
- `unreleased_commit_only`: 5. The origin and fix first coexist in the same published artifact, or no vulnerable artifact contains the origin without the fix.
- `not_origin_of_named_mechanism`: 3. AI touched the repository or nearby surface, but a human or earlier code introduced the advisory sink.
- `different_invariant`: 2. Similar files/fixes do not establish the same source, sink, and security invariant.
- Remaining singleton failures include identity mismatch, duplicate mechanism, pre-existing incomplete predicate, sibling endpoint not attempted, and human weakening of an AI predicate.

The most important positive lessons are also retained:

- A new AI-authored surface can be a real contributor even when the product already had sibling vulnerable surfaces; describe it as a contributor, not whole-product root.
- AI incomplete remediation counts only when the AI change explicitly attempts the same boundary and the advisory later closes its residual.
- A squash/merge carrier is not the AI origin member. Compare relevant blobs and hunks; ancestry alone is insufficient.
- A first-party GHSA 404 in one index does not erase a preserved repo advisory object, but an unavailable or polluted identity must remain explicit.
- `npm gitHead`, Git tags, package artifacts, and advisory version strings are separate release evidence and may disagree.

The complete tag and false-positive-class census is machine-readable in `experience.json`.

## Durable artifacts

- `final_mechanisms.jsonl`: 211 final mechanism rows.
- `public_cases.jsonl`: 212 GHSA-keyed public cases.
- `public_id_dispositions.jsonl`: lossless disposition of 381 input IDs.
- `experience.json`: reusable adjudication tags and false-positive classes.
- `summary.json`: answer-level counts and claim boundary.
- `build_final.py --check`: deterministic replay.
- `verify_final.py`: final coverage, identity, case, and conservation gates.

## Remaining boundary

Nine cases remain `UNKNOWN`: ordinals 35, 51, 53, 56, 84, 116, 129, 153, and 154. They are not counted among the 149 causal-valid cases. Resolving them could move cases between `CONFIRM`, `NARROW`, and `FALSE_POSITIVE`, but cannot silently change the current result; the ledger must be rebuilt and verified.
