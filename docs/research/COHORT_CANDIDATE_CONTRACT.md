# Forward-cohort advisory candidate contract

## Objective

Build the recall inventory for the forward cohort without using SZZ, commit
message keywords, path overlap, a time window, sampling, or an LLM as an
exclusion rule.

The observable candidate unit is a cohort commit SHA that is reachable before
an advisory fix in the same repository. Advisory aliases that name the same fix
share one edge. A failed or incomplete history walk is `BLOCKED`, never a
negative result. Commit dates do not bound the graph walk because timestamp
skew is not an ancestry proof.

`BLOCKED` applies to the completeness of a fix root, not to already proven
positive edges. If a walk proves candidates before reaching a shallow or
missing-parent boundary, those edges remain in `candidates.jsonl` and carry the
root's incomplete-coverage status.

## Artifacts

- `candidates.jsonl`: immutable candidate edges. Every edge is identified by
  repository, shipped cohort SHA, fix SHA, and provenance relation.
- `fix_roots.jsonl`: every unique advisory fix root, exactly once, as
  `RESOLVED` or `BLOCKED`.
- `routing.jsonl`: every candidate edge, exactly once, as `PROMOTE`, `DEFER`,
  or `BLOCKED`. Before screening, all candidate edges are `DEFER`.
- `fix_source_observations.jsonl`: every public, cached-enriched, ranked-carrier,
  and repository-reference observation, with local SHA resolution recorded as
  `RESOLVED` or `BLOCKED`.
- `repository_fallback_candidates.jsonl`: every observed cohort unit paired
  with every known advisory in the same repository. These rows have no
  `fix_sha` and make no ancestry claim; they are the source-independent recall
  floor when all proposed fix roots are absent or wrong.
- `summary.json`: input identities, content hashes, coverage state, and the
  conservation equations.

The per-archive advisory index under `.ai-slop/cache/` is a derived performance
cache, not an evidence artifact. Each shard is selected by the source archive's
full SHA-256 and validates its own payload digest. Source archive hashes and
the combined manifest remain in `summary.json`; cold and warm runs must produce
identical candidate, fix-root, public-reference, and routing artifacts.

## Fix-source union

OSV is one source, not a completeness gate. The default no-token source pass
unions four tiers:

1. direct OSV commit references (`public_exact`);
2. locally cached Phase-2 selections (`enriched_selected`), explicitly labeled
   as inherited model evidence rather than public exact evidence;
3. every cached ranked candidate, including candidates from a `NOT_FOUND`
   result (`ranked_search_carrier`); and
4. every local commit message that names a repository-scoped CVE, GHSA, issue,
   or pull-request anchor (`repository_reference_carrier`).

Every resolvable row may add a graph root. No tier votes another tier out, and
model rejection has no deletion authority. Carrier roots are deliberately
allowed to be false positives and must not be described as verified fixes.
The separate repository/advisory fallback pairs every known advisory with
every observed AI-attributed unit in that repository, so a wrong or missing
fix source cannot erase the unit. That fallback is screened with advisory and
candidate evidence later; it is never fabricated into a fix-SHA ancestry edge.

Source evaluation is a separate process over a sealed fix-only manifest. It
reports public exact coverage, public plus enriched selection, all source
candidates, and repository fallback coverage independently. It never upgrades
a carrier into a public-exact result.

## Claim-grade fix input

An evaluation replay must pass `--fix-manifest`, not a golden control ledger.
The sealed schema permits exactly five top-level fields (`schema_version`,
`artifact_kind`, `split_id`, `frozen_at`, and `fixes`) and exactly three fields
per fix (`advisory`, `repository_identity`, and a full `fix_sha`). Any origin,
landed-commit, relation, description, or extra metadata field fails closed.

`--fix-manifest`, `--complex-controls`, and `--positive-controls` are mutually
exclusive. A claim-grade summary records
`generation_process_boundary=sealed_fix_only_no_golden_ledger_read`, the input
hash, split identifier, and fix count. Gold relations are loaded only later by
the evaluation process.

## Population input

Discovery and outcome-rate estimation are different populations even when they
start from the same AI-attributed commit scan. The discovery path must carry a
content-bound `all_age_discovery` contract with `min_followup_days=0`. A
`mature_outcome_estimation` contract must use a positive follow-up threshold
and is ineligible for advisory candidate generation.

`scripts/cohort_prepare_populations.py` creates both branches from one scan and
hashes the scan summary plus commit corpus into each contract. Exposure and
stated-outcome summaries propagate those hashes. Candidate generation verifies
the complete chain before reading advisory archives; a missing, drifted, or
maturity-filtered contract fails closed. This prevents an outcome-estimation
threshold from becoming an accidental vulnerability-discovery exclusion rule.

## Invariants

1. `fix_roots = resolved_fix_roots + blocked_fix_roots`.
2. `candidate_edges = promoted_edges + deferred_edges + blocked_edges`.
3. The sets in each equation are disjoint and content-sealed.
4. Model rejection maps to `DEFER`; it never removes an edge.
5. Unknown model-returned edge IDs and duplicate IDs fail closed. Incomplete
   history preserves proven edges and marks the root `BLOCKED`.
6. SZZ, path overlap, commit messages, and semantic scores may rank an edge but
   cannot change the immutable candidate inventory.
7. A claim-grade generation process never reads the golden origin/relation
   ledger; a strict fix-only manifest is its only evaluation overlay.
8. Advisory discovery accepts only a hash-valid `all_age_discovery` population;
   the maturity-filtered estimation branch can never enter candidate generation.
9. Cached model rejection cannot remove a ranked source carrier, and no model
   call is made while consuming cached evidence.
10. Every repository fallback candidate is `DEFER`, has no `fix_sha`, and is
    conserved separately from ancestry edges.

## Claim boundary

Completeness is conditional on the forward cohort's observable AI-attribution
policy, locally available repository history, resolvable advisory fix roots,
and SHA reachability. Unattributed AI use, undisclosed vulnerabilities, private
history, and patch-equivalent copies that lost their attribution remain outside
this first contract and must not be described as negatives.

## First milestone acceptance

- Pure contract tests cover reachability, advisory alias deduplication,
  deterministic identities, blocked history, and routing conservation.
- No external API call is made.
- Existing forward-cohort tests remain green.

## Bounded screening pilot

The first model run is a routing calibration, not a destructive filter:

1. Freeze the candidate, fix-root, and routing hashes before any request.
2. Build compact evidence packs locally and measure their tokens without an API
   call. Do not send repository-wide history.
3. Stratify the pilot across repository, exposure route, resolved versus blocked
   root coverage, and high-precision positive controls. Reserve every control
   before selecting same-fix comparators so a shared-fix control cannot become
   another control's comparator. Unprocessed edges remain `DEFER`.
4. Freeze explicit input and output price assumptions plus an operator hard cap
   before dispatch. CLIProxyAPI's absent price contract must not silently become
   a zero-cost assumption.
5. Record actual input, cached-input, and output usage after every response,
   keeping provider-known cost separate from a frozen-price budget estimate.
   Parse failures and exhausted budget map to `BLOCKED`, model negatives to
   `DEFER`, and only positive evidence maps to `PROMOTE`.
6. Do not expand past the pilot until positive-control recall, parse success,
   prompt-token distribution, and cost per edge are measured from the ledger.

This budget never changes inventory recall: it only limits how many immutable
edges receive early prioritization.

## Finite-budget origin priority

Deleted-line SZZ is one ranking lane, not the origin candidate generator. For
each resolved fix, the finite-budget queue unions copy-aware and file-local
SZZ with add-context blame, enclosing-function history, exhaustive pickaxe
token history, affected-file history, and cross-file security-surface/guard
bridges. Add-only checks and global middleware fixes therefore receive direct
lanes instead of waiting behind every SZZ hit. Direct lanes are interleaved
within a priority class so a prolific lane cannot consume the whole model
budget.

The full reachable-ancestor inventory remains the recall floor outside this
compact queue. Missing objects, failed blame/log operations, or incomplete
history mark the fix `BLOCKED`; they are never interpreted as no origin.

Model routing is evaluated only after both the fix-only generation artifact
and model responses are frozen. `PROMOTE` moves a candidate earlier,
`BLOCKED` stays ahead of model-negative rows, and `DEFER` remains retained.
With multiple models, the comparison order is: all models promote, any model
promotes, any model blocks, then all models defer; structural rank breaks ties.
Report `recall@budget` separately for the structural queue, every model, and
the ensemble. Gold origins must never enter prompt construction or routing.

## Deterministic finite origin reduction

The model inventory is not the structural signal union. For repository `R`,
freeze the complete observed AI-attribution inventory `O_R`. For fix `F` with
pre-fix parents `P_F`, the same-repository candidate set is exactly:

`C_F = O_R ∩ union(Anc(parent) for parent in P_F)`

This is a deterministic, finite intersection. An observed AI commit outside
the pre-fix ancestry receives a Git non-ancestor certificate. SZZ, paths,
symbols, commit time, affected-version ranges, and model output cannot remove
members of `C_F`.

The zero-miss claim is conditional on `O_R`: an unobserved AI-authored commit
is outside the attribution policy, not a proven negative. Every fix therefore
records both the full ancestor digest and the unobserved-ancestor digest. If
the AI scan is incomplete, the reducer fails open to every pre-fix ancestor.
Cross-repository copies and upstream imports require the separate relation
closure; absence from the target repository's AI metadata is not an exclusion
certificate.

## Squash-member conservation and atomic refinement

A landed squash commit is a carrier, not proof that the carrier itself is the
atomic origin. When a pull-request relation is available, expansion adds every
PR member as a retained `(member, fix)` edge and keeps the landed carrier as a
fallback. Empty members, members without an AI regex hit, and members without a
fix-file overlap remain visible. A carrier AI signal supports PR-level exposure
but is never silently upgraded into member-level AI authorship.

Fix-hunk context may be matched back to the PR head and blamed across the PR's
member history. This `squash_internal_fix_context_blame` evidence only reorders
the squash-member lane; it cannot delete candidates or displace the existing
direct, add-check, cross-file, or SZZ lanes. Ambiguous matches are retained as
ranking evidence rather than causal verdicts.

Any gold carrier-to-member refinement is frozen in a separate ledger only
after fix-only generation artifacts are sealed. The refinement ledger is an
evaluation overlay: candidate generation, packet construction, and model
prompts must not read it.

## Mixed-origin dependency closure

Per-commit causal adjudication is not a complete unit of analysis. A directly
AI-attributed commit may introduce a latent validator, parser, sink, source,
default, or helper that is not independently triggerable until a later human
commit selects or connects it. Rejecting the AI commit because its own parent
to-candidate state is not exploitable would lose a real compositional causal
contribution.

For every retained security fix, mitigation, and non-AI activation candidate,
the add-only dependency lane therefore records the definitions and values used
by each changed call, guard, source, sink, and default. It blames those semantic
dependencies to atomic commits and intersects their origins with the complete
observed AI-attribution inventory. A retained tuple has the form
`(AI dependency origin, activation commit, advisory mechanism)`; it does not
replace or delete either ordinary ancestor candidates or squash members.

The dependency lane has three claim levels that must not be collapsed:

1. `independent_ai_root`: the AI commit's own delta makes the defect
   independently triggerable;
2. `vulnerable_path_activation`: the AI commit activates a pre-existing unsafe
   primitive through a new source, sink, caller, default, or input path; and
3. `compositional_causal_contributor`: the AI commit supplies a concrete unsafe
   primitive, but another commit is required to activate it.

One advisory mechanism is deduplicated as one finding even when different
commits supply its primitive, raw source, activation, and sink. The provenance
ledger retains every role and SHA. Missing language analysis, unresolved blame,
or uncertain dispatch is `BLOCKED`; it is never a negative certificate. Gold
compositional controls are frozen only after generation and review artifacts
are sealed, and they remain evaluation-only.

Earliest roots and later causal path extensions are reported in separate
ledgers. A later member is a path-extension positive only when a
parent/candidate/fix witness shows the parent safe for a member-specific
trigger, the candidate unsafe, and the fix safe again. Same-file overlap or a
model vote is insufficient, and a path extension is never double-counted as an
earliest root.

Model evidence packs include each selected candidate's Git parents and any
direct parent/child aliases present in the same packet. This does not change
membership or structural rank; it lets the downstream router distinguish an
atomic introducing delta from an earlier prerequisite or a later same-file
touch without guessing from authored timestamps.

Review closure is measured over the complete frozen squash-member inventory,
not over a model-selected subset. Every non-empty member must receive at least
one completed model review. Every empty member remains retained with an
explicit zero-content certificate, whether or not a signal lane also sent it
to a model. The lossless union of `likely` and `possible` promotions is then
adjudicated separately: a patch mechanism or executable witness is required
for a causal positive, while a rejected independent-causality claim remains in
the candidate inventory. Earliest roots, path extensions, and default-path
activations are counted separately, and carrier-level AI context never becomes
member-level authorship evidence.

## Lossless model work packets

Repeated `(candidate, fix)` edges for one advisory are folded into one
candidate unit that retains the complete list of fix edges. Candidate units
are then assigned exactly once to bounded advisory/repository packets. Packet
membership and fix-edge counts obey separate conservation equations.

The response schema requires exactly one result for every packet-local ID.
Missing, duplicate, unknown, truncated, or malformed IDs block the whole
packet. A transport failure is retried; a response-contract failure is retried
once. If it still fails, the packet remains `BLOCKED` and must be re-packetized
at a smaller size before any negative conclusion. `unlikely` remains `DEFER`,
never a deletion. Thus batching reduces repeated fix context and physical
calls but does not change candidate inventory recall.
