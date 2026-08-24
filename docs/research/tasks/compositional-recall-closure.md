# Compositional recall closure

## Inputs

- The immutable forward-cohort advisory candidate inventory.
- Forward-cohort units with repository, PR number, and merge topology.
- Locally materialized GitHub pull-request refs.
- An explicit repository-alias ledger.
- Separate development and repository-disjoint held-out `AI_CAUSAL` ledgers.
- A frozen complex ledger covering multi-origin, multi-fix, and
  cross-repository obligations.
- A source scan whose summary explicitly names complete repositories, including
  complete scans with zero AI-attributed commits.

## Outputs

- `relations.jsonl`: every PR-head member to landed squash relation, with an
  explicit flag indicating whether the atomic member was already observed as
  a cohort unit.
- `relation_roots.jsonl`: every attempted landed squash as `RESOLVED` or `BLOCKED`.
- `candidates_expanded.jsonl`: direct ancestry edges plus compositional edges.
- `control_recall.json`: public-source recall and relation-engine recall reported separately.
- `import_carriers.jsonl` and `import_roots.jsonl`: explicit target-history
  source declarations, with absent or incomplete source scans retained as
  `BLOCKED`.
- `ambiguous_source_mentions.jsonl`: bare `owner/repo`-shaped transfer prose
  retained as `BLOCKED`; it is neither promoted to a repository declaration nor
  silently discarded.
- `complex_control_recall.json`: every target and upstream obligation scored
  separately; one matched origin cannot make a multi-origin case pass.

## Acceptance

- Repository aliases are explicit, acyclic, and content-evidenced.
- PR membership is reconstructed from Git refs, not copied from golden labels.
- Every PR-head member linked to an ancestral landed squash yields a
  compositional candidate edge to the fix. Requiring the atomic member to also
  appear as a mainline cohort unit is forbidden: squash normally erases that
  topology and the intersection caused held-out misses.
- Missing PR refs remain `BLOCKED`; already proven direct edges are retained.
- The four development controls reach 4/4 and the five repository-disjoint
  held-out controls reach 5/5 relation recall when exact fix roots are supplied
  as an evaluation overlay.
- Public advisory-source recall is reported independently and may remain lower.
- No model call is made before the applicable relation gate passes.
- Cross-repository carrier discovery scans every fix-reachable target commit,
  not only AI-tagged commits. Once a source is explicitly declared, every
  AI-attributed commit in its complete source scan remains a candidate; dates
  and similarity may rank but never exclude it.
- Only transfer-qualified GitHub URLs and explicit `plugin by @owner` forms are
  declarations. Bare slugs remain in the ambiguity ledger until an independent
  acquisition policy resolves them.
- Multi-root target history is walked once. Arbitrary-width bitmasks propagate
  all fix roots through the parent graph; per-carrier `merge-base` loops are
  forbidden because they repeat the same graph work thousands of times.

The recall-first expansion deliberately increased the held-out graph from
1,201 direct edges to 3,391 conserved edges (2,190 composite additions). This
is not a precision claim: unobserved and human PR members are allowed to enter
the queue, because later routing may defer them but candidate construction may
not delete them.

## Complex falsification batch (2026-07-31)

The frozen batch contains nine independently audited cases: 20 target-repository
origin/import-to-fix obligations, four upstream-origin-to-import obligations,
and nine public exact-fix diagnostics. The no-model gate passed all 20/20 target
and 4/4 upstream obligations, so all 9/9 cases were complete. Public exact-fix
coverage was separately 8/9. The missing row was Quay `CVE-2026-2376`; none of
the 46 sealed local OSV archives contained that advisory, so this is public
source coverage debt rather than a relation miss.

The broad six-target run retained 193,065 direct edges and added 52,554 squash
composition edges. It also retained 40 blocked fix roots and 345 blocked PR
relation roots. These unknowns prevent a global completeness claim even though
the frozen obligations passed.

The first cross-repository implementation performed one `merge-base` query for
every declared carrier/fix pair and did not finish in several minutes. A single
parent-graph traversal reduced the same 604-root run to about 30 seconds. A
second bug treated ordinary GitHub merge text (`Merge pull request ... from
owner/branch`) as a source-repository declaration, producing 217,188 carriers.
Requiring transferred-code syntax and an explicit `plugin by @owner` form
initially reduced this to 2,901 carriers while preserving the four frozen
upstream obligations. The next replay separated bare slugs mechanically:
1,127 explicit carriers remained and 1,774 mentions moved to a first-class
`BLOCKED` ambiguity ledger. The resulting campaign still recovered all 20/20
target and 4/4 upstream obligations (9/9 cases). It produced the same 29,680
cross-repository candidate edges, with 25/26 source-import roots blocked by
missing scans. These unknowns are not negatives.

## Repository-disjoint claim-grade batch (2026-07-31)

Before any new model request, two previously unused repositories were frozen:
Graphiti `CVE-2026-32247` (two origins, one semantic fix) and ClearanceKit
`CVE-2026-34218` (three origins, two semantic fixes). They share no repository
with the nine-case development split. Candidate generation read only the sealed
three-row fix manifest; its summary records
`sealed_fix_only_no_golden_ledger_read`.

The no-model run retained 1,225 direct candidates and added 694 compositional
candidates. It recovered all 5/5 held-out origin-to-fix obligations, both 2/2
complete cases, and all 3/3 exact semantic fix roots. Four unrelated public OSV
roots whose objects were unavailable remain `BLOCKED`, so this result is a
frozen-obligation recall result, not a global completeness claim.
