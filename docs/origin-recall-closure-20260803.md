# Origin-recall research closure — 2026-08-03

## Verdict

The old workflow failed the main recall-first objective. It admitted only
commits with observable AI metadata and then measured conservation downstream.
In the frozen v4 cases this kept 550 of 45,133 local pre-fix ancestor pairs and
discarded 44,583 before the recall accounting began.

The repaired workflow makes candidate membership independent of AI attribution:
every local pre-fix ancestor is retained; SZZ, attribution regexes, structural
signals, squash relations, and model output only change review order. This
eliminates the demonstrated admission bug but does **not** prove zero population
misses.

The full interactive technical report is
[`reports/origin-recall-v4/report.html`](../reports/origin-recall-v4/report.html).
The canonical machine-readable result and replay commands are in
[`scripts/heldout_studies/prospective-origin-heldout-20260803-v4-final/`](../scripts/heldout_studies/prospective-origin-heldout-20260803-v4-final/).

## What the held-out established

The repository-disjoint association-only split selected 12 cases. Independent
fix-root review resolved 3 and left 9 unknown, for a 25% resolution rate and a
one-sided 95% Clopper-Pearson lower bound of 7.19%.

Two independent causal reviewers then inspected five fixes across Azure SDK for
Python, Litestream, and Eigent. They reviewed the complete old top-10 unit union:
22 unique units carrying 34 exact fix edges. All 34 edges were noncausal.

The reviewers agreed on nine causal-history commits and proposed six additional
reviewer-only contributors. Every proposed commit was absent from the frozen
observed-AI inventory. No confirmed observed-AI causal case was found.

Therefore:

- conditional AI-origin recall is not estimable because its confirmed-positive
  denominator is zero;
- the 34 reviewed top-ranked edges are an operational-yield sample, not a
  precision or false-positive-rate denominator;
- the nine unresolved selected cases remain unknown, not negatives;
- metadata absence is not proof of human-only authorship.

This is a negative held-out result, not a successful zero-miss certification.

## Root-cause repairs

Two shared-path defects were fixed.

1. `origin_reduction` now admits all local pre-fix ancestors. Attribution and
   structural evidence are rank-only, and negative model output means `DEFER`.
2. Candidate-unit scoring now preserves each exact edge's per-fix rank. A good
   rank under one fix can cause the unit to be reviewed once, but it can no
   longer falsely place another carried edge inside that other fix's top-B
   prefix.

No new ranking heuristic was added. Existing ancestry enumeration, squash
closure, unit folding, and edge-specific adjudication were reused.

## Repaired finite workload

The frozen replay produced:

| Stage | Exact edges | Review units |
|---|---:|---:|
| Old observed-AI direct reduction | 550 | — |
| Old squash-expanded schedule | 8,449 | 4,542 |
| Repaired local ancestry | 45,133 | 22,912 before relation closure |
| Repaired recursive squash closure | 50,862 | 26,057 |

The recursive closure added 5,729 exact atomic-member edges across four used
depths. It resolved 386 of 388 squash roots. The two unresolved roots retain
their landed squashes as explicit `BLOCKED` fallbacks; there were no depth-limit
gaps. All 50,862 exact edges are preserved in 26,057 deduplicated units and
3,258 packets.

Fourteen consensus causal-history exact edges were replayed only as post-hoc
repair controls. All 14 are present in the repaired schedule. Unit review
recovers 9/14 at B=10 per fix, 11/14 at B=25, 12/14 at B=200, and 14/14 at
B=5,000. These values diagnose ranking and folding; they are not AI-origin
recall estimates.

## Cost boundary

The v4 causal reviews and repaired replay made zero external model/API calls.

Using the historical Luna low-effort pilot shape—53,026 input tokens, 2,613
output tokens, 17 calls, and $0.0137408 recorded cost—the linear projection is:

| Per-fix budget | Unique units | Luna projection |
|---:|---:|---:|
| 10 | 39 | $0.032 |
| 25 | 85 | $0.069 |
| 100 | 327 | $0.264 |
| 1,000 | 2,425 | $1.96 |
| 5,000 | 6,757 | $5.46 |
| Full schedule | 26,057 | $21.06 |

This is a historical-token-shape projection, not a quote or actual bill.
Batching, prompt size, retries, cache discounts, and future prices can move it.
The comparable normalized full projections are $37.58 for DeepSeek and $139.47
for Grok. CLIProxy's reported zero cost is not treated as proof that a model is
free.

## Exact guarantee and remaining gaps

The repair guarantees this statement by construction:

> Every commit in the frozen local pre-fix ancestry is a candidate, and every
> recoverable public squash member is added without deleting its carrier.

It does not cover:

- unresolved fix roots or the nine association-only cases still marked unknown;
- cross-repository copies and vendored or generated preimages;
- missing, rewritten, private, or deleted repository history;
- undisclosed AI assistance without observable attribution;
- exact atomic members behind the two blocked public pull-ref roots;
- population recall, precision, or prevalence.

Candidate conservation after entry must never again be reported as entry recall.

## Claim-grade next experiment

Freeze a new forward split from observable AI commits or pull requests, then
follow those subjects to later fixes and advisories. Independent reviewers must
adjudicate causal positives before opening candidate ranks. Unresolved cases
remain unknown.

For a one-sided 95% exact lower recall bound of at least 0.95, the study needs
59 independent positive cases with zero misses. For a bound of at least 0.99,
it needs 299/299. Candidate edges and folded units cannot substitute for
independent positive cases.

Until that gate is met, the defensible conclusion is narrower: the admission
bug is fixed, the local-history universe is finite, and a complete Luna review
is projected below $100—but zero miss is not certified.
