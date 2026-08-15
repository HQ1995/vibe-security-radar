# Recall-first origin pilot — 2026-08-01

> Superseded as the current status summary by the
> [2026-08-03 closure audit](origin-recall-closure-20260803.md). This document
> remains the frozen pilot record.

## Verdict

The direction is viable, but only if SZZ is a ranking lane rather than an
exclusion rule. In nine known-positive origin edges across six public
repositories, deleted-line SZZ recovered 7/9. The recall-first structural
union recovered 9/9. Both real SZZ misses were recovered by non-SZZ history
lanes.

A later proof-carrying reduction now defines the finite screening inventory as
the intersection of the frozen AI-attribution inventory and exact pre-fix Git
ancestry. Across seven fix roots, this reduced 4,807 ancestor pairs to 895
candidate pairs (81.4%) while retaining 9/9 controls. After folding repeated
fix edges, 542 candidate units remain. This is the new recall floor; the old
structural union is only a ranking overlay.

`deepseek-v4-flash` at low reasoning effort is the current default promotion
assistant, never a deletion filter. It
improved weighted recall@25 from 7/9 to 9/9 while retaining every candidate.
Grok was useful as an independent check, but was substantially broader and did
not improve recall beyond DeepSeek-low on this pilot. DeepSeek-high was less
reliable and must not be the bulk-routing default.

These are selected-control results, not population recall or precision. The
zero-miss boundary is conditional on the frozen AI-attribution policy,
semantic-fix inventory, local Git completeness, and cross-repository closure.
Unattributed AI use is not a negative result.

## Frozen evaluation boundary

- Generation read strict fix-only manifests and local Git history.
- Atomic or complex origin ledgers were joined only after generation froze.
- Model prompts were constructed before the control ledger was read by the
  comparison process.
- `unlikely` maps to `DEFER`; parse/transport failures map to `BLOCKED`.
- Every route artifact conserves its complete candidate inventory.
- Four atomic controls were combined with five repository-disjoint complex
  held-out edges. The resulting scope is six repositories and nine origin
  edges.

## Structural recall

| Metric | Result |
|---|---:|
| Materialized by the structural union | 9/9 |
| Deleted-line SZZ | 7/9 |
| Add/context/function/pickaxe lanes | 7/9 |
| Real cross-file bridge controls | 0/9 |

The two real SZZ misses were:

| Repository | Origin | Structural rank | Recovering signals |
|---|---|---:|---|
| `getzep/graphiti` | `dcc9da3f6887b84830758d7e89974eb4f2af8f92` | 50 | add-context, affected-file history, function history, pickaxe |
| `craigjbass/clearancekit` | `5a887953c45551879797fd9e11a2055cf9386d7e` | 5 | affected-file history, function history, pickaxe |

The cross-file bridge has Git-level synthetic coverage for route additions and
global middleware guards, but no positive real control in this nine-edge
sample. It remains a research gap rather than a validated real-world gain.

## Proof-carrying finite reduction

| Metric | Result |
|---|---:|
| Pre-fix ancestor pairs | 4,807 |
| Retained observed-AI ancestor pairs | 895 |
| Deterministic reduction | 81.4% |
| Structural-signal candidates within the inventory | 98 |
| Exact AI-ancestry fallback candidates | 797 |
| Retained known-positive origins | 9/9 |
| Reduced structural recall@1 | 4/9 |
| Reduced structural recall@5 | 9/9 |
| Advisory/candidate units after multi-fix folding | 542 |
| Eight-candidate work packets | 72 |

Every observed AI commit outside a pre-fix parent closure carries a
`git_non_ancestor_of_pre_fix_state` certificate. The 3,912 ancestor pairs not
matched by the frozen attribution policy are recorded as a scope boundary,
not claimed as safe negatives. Incomplete attribution coverage fails open to
all ancestors.

Affected-version metadata did not provide a safe lower history bound for this
batch: the available package ranges start at `0`. More generally, a release
reported as unaffected does not prove that an earlier dormant causal component
can be deleted. Version ranges therefore remain evidence, not a universal hard
filter.

## Lossless batch-routing pilot

The 895 candidate/fix pairs fold losslessly into 542 advisory/candidate units.
With eight units per packet, the complete inventory is 72 packets. A blinded
pilot routed the first two packets per advisory/repository: 12 physical calls
covering 78 units.

| Metric | DeepSeek-low batch |
|---|---:|
| Parsed packets at 4,000 output-token cap | 12/12 |
| Input tokens | 70,103 |
| Output tokens | 9,998 |
| Known-positive origins promoted | 4/9 |
| Known-positive origins labeled `unlikely` | 5/9 |
| Recall@1 after routing | 6/9 |
| Recall@5 after routing | 9/9 |
| Candidate/fix pairs retained | 895/895 |

At a 1,600 output-token cap, 3/12 packets exhausted their budget in hidden
reasoning before emitting valid JSON. At 4,000, all 12 parsed in the final run.
The exact-ID response contract blocks malformed packets, transport failures are
retried, and contract failures are retried once. A repeated failure remains
`BLOCKED` until the packet is deterministically re-created at a smaller size.

The most important result is negative: DeepSeek-low explicitly labeled five of
nine real origins `unlikely`. It is useful for promotion and batching reduced
repeated context substantially, but AI rejection is not safe filtering.

## Recall at finite AI budget

| Ranking | recall@1 | recall@5 | recall@10 | recall@25 |
|---|---:|---:|---:|---:|
| Structural | 2/9 | 5/9 | 7/9 | 7/9 |
| DeepSeek-low | 2/9 | 7/9 | 8/9 | 9/9 |
| Grok | 2/9 | 6/9 | 7/9 | 8/9 |
| Low+Grok comparison ensemble | 2/9 | 7/9 | 8/9 | 9/9 |

Important rank changes include:

| Repository/control | Structural | DeepSeek-low | Grok |
|---|---:|---:|---:|
| `franklioxygen/mytube` | 5 | 2 | 4 |
| `safedep/vet` | 9 | 3 | 5 |
| `tinyobjloader/tinyobjloader` | 55 | 8 | 25 |
| `getzep/graphiti`, first origin | 10 | 5 | 9 |
| `getzep/graphiti`, SZZ miss | 50 | 20 | 42 |
| `craigjbass/clearancekit`, SZZ miss | 5 | 2 | 5 |

The two-model ensemble matched DeepSeek-low's aggregate recall and added no
recall in this sample. Grok should therefore be an advisory second opinion or
a fallback for DeepSeek `BLOCKED` rows, not an equal-weight bulk promoter.

## Model-effort and token evidence

Across the six low-versus-Grok comparisons:

| Route | Calls parsed | Promoted | Input tokens | Output tokens |
|---|---:|---:|---:|---:|
| DeepSeek-low | 433/445 | 82 | 2,209,413 | 166,560 |
| Grok model-controlled | 445/445 | 231 | 5,905,140 | 1,000,693 |

Grok consumed about 2.7x the input and 6.0x the output tokens while promoting
2.8x as many candidates. That is consistent with a high-recall second opinion,
but not with a narrow first-stage router.

DeepSeek-high was tested on SafeDep and TinyObj (236 calls total). It parsed
203/236 responses and emitted 212,063 output tokens. On the matching low runs,
231/236 parsed and 77,390 output tokens were sufficient. High moved the
SafeDep origin from rank 3 to rank 2, but turned the TinyObj gold response into
`BLOCKED` and left it at rank 27 instead of low's rank 8. The highest supported
effort is therefore a targeted retry only; low remains the bulk default.

CLIProxyAPI reported zero known marginal cost for these quota-backed calls.
That is not a provider-price claim.

## Implemented workflow

1. Parse deleted, replacement, and add-only hunks without a fixed hunk cap.
2. Union copy-aware SZZ, file-local SZZ, add-context blame,
   enclosing-function history, batched pickaxe history, affected-file history,
   and cross-file guard/surface lanes.
3. Intersect the frozen full-history AI observation set with exact pre-fix
   ancestry; incomplete observation fails open to every ancestor.
4. Interleave direct lanes within a priority class, preventing a prolific SZZ
   lane from consuming the finite AI budget.
5. Fold multi-fix edges into lossless candidate units and bounded packets.
6. Freeze fix-only generation artifacts before joining origin controls.
7. Route candidates through loopback CLIProxyAPI with model negatives retained.
8. Evaluate base, per-model, and ensemble recall@budget in a separate process
   that verifies candidate and route hashes.

Primary code:

- `scripts/cohort/origin_signals.py`
- `scripts/cohort/security_bridge.py`
- `scripts/cohort/origin_controls.py`
- `scripts/cohort_origin_signal_pilot.py`
- `scripts/cohort_origin_recall_controls.py`
- `scripts/cohort_origin_ai_route.py`
- `scripts/cohort_origin_ai_recall.py`
- `scripts/cohort/origin_reduction.py`
- `scripts/cohort_origin_candidate_reduce.py`
- `scripts/cohort/origin_packets.py`
- `scripts/cohort_origin_packetize.py`
- `scripts/cohort/origin_batch.py`
- `scripts/cohort_origin_ai_batch_route.py`

## Next falsifiable batch

Do not spend the next model budget on broader routing yet. First audit the
attribution-policy boundary and add at least ten independently frozen real
controls selected specifically for add-only, cross-file/global-guard, and
cross-repository-copy fixes. The next gate is:

- structural materialized recall 10/10;
- cross-file lane hits at least one genuine cross-file control;
- DeepSeek-low does not reduce recall@25 relative to the structural order;
- every parse failure is retried or retained as `BLOCKED`;
- observed-AI ancestry inventory recall remains 10/10 before ranking;
- every candidate unit and fix edge passes packet conservation;
- Grok is kept only if it recovers a control that DeepSeek-low misses or blocks.

If the cross-file lane still has zero real hits, narrow or drop its research
claim while retaining it as a conservative candidate-expansion heuristic.
