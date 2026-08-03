# Origin-recall research closure — 2026-08-03

## Verdict

The workflow is now recall-first in the only defensible finite sense:

> For every frozen fix, every readable local pre-fix ancestor is retained, and
> every recoverable public squash member is added without deleting its landed
> carrier. SZZ, AI-attribution regexes, structural signals, and model output can
> change review order but cannot remove a candidate.

Both regression gates pass:

- sealed-schedule v6 re-adjudication: 2/2 confirmed cases and 3/3 consensus
  exact edges recovered at the preregistered B=100 carrier budget;
- v5 method-repair replay: 12/12 cases and 16/16 exact edges recovered at B=100.

Both sets were already complete at the tested B=25 point. B=25 is an observed
diagnostic, not a post-hoc replacement for the preregistered B=100 gate.

This closes the demonstrated candidate-admission and squash-budget failures.
It does **not** provide a fresh method-independent positive denominator and does
**not** certify zero population misses.

The canonical machine-readable result is
[`final_result.json`](../scripts/heldout_studies/prospective-origin-heldout-20260803-v6-reserved/final_result.json).

## What changed

The final workflow has four rules.

1. Enumerate all readable pre-fix ancestors. Attribution absence is a ranking
   fallback, never an exclusion.
2. Expand public squash relations recursively. Keep the landed commit even when
   atomic members are recovered.
3. Budget by a repo/advisory-scoped carrier component. Selecting a carrier for
   one fix expands all of its atomic members, while recall credit remains
   same-fix only.
4. Fail closed on evidence integrity. Packet census, conservation counts,
   candidate units, connector provenance, atomic ranks, carrier ranks, schedule
   rows, and hashes are independently recomputed before scoring.

The implementation reuses the existing ancestry, packetization, and scheduling
paths. No new heuristic classifier was added.

SZZ can still miss a useful signal. That is no longer a recall failure because
SZZ does not control membership.

## Squash boundary

Squash commits are handled in two different proof states:

- `RESOLVED`: exact public atomic members are readable and added;
- `CARRIER_ONLY`: the complete parent-to-landed binary patch is readable, so the
  vulnerability surface can be screened, but atomic membership and individual
  attribution remain unknown.

`CARRIER_ONLY` is not presented as atomic provenance. Unknown atomic counts are
`null`, never fabricated as zero.

The v5 replay contains 611 resolved roots and 144 carrier-only roots. It has no
uncovered candidate surface, but it still has 144 atomic-provenance gaps. The v6
split resolves all four roots and has no atomic gap.

## Sealed v6 protocol and independence audit

The v6 split froze three repositories that were disjoint from the 12-repository
v5 split:

- `github.com/franklioxygen/mytube`
- `github.com/craigjbass/clearancekit`
- `github.com/j178/prek-action`

The candidate schedule and both sealed reviewer-file hashes were committed in
`96b7f1e` before the primary researcher opened either review. Both reviewers
worked fix-first and did not read candidate, packet, rank, schedule, ledger, or
ground-truth artifacts.

They agreed on all case statuses: two confirmed and one unknown. They disagreed
on one possible compositional precursor. The strict ground truth takes the
intersection of exact accepted subjects, leaving three consensus edges and
recording the disputed edge as excluded diagnostic evidence.

The unknown case remains unknown; it is not converted into a negative.

The schedule/reviewer blindness above is real, but the stronger
method-independence claim is not. A later exposure audit found that all three
repositories had already appeared during method development:

- MyTube and ClearanceKit origins and ranks were used in the 2026-08-01 recall
  pilot;
- prek-action already existed in the verified corpus and the v5 selector.

Therefore v6 is retained as a sealed-schedule, label-blind re-adjudication
regression. It is not counted as fresh external validation. The original v6
selection gate proved disjointness only from v5, not from all prior research.

## Exact results

| Evidence set | Role | Final edges | Surface gaps | Positive cases | Exact edges | First tested complete B | B=100 expanded units |
|---|---|---:|---:|---:|---:|---:|---:|
| v6 reserved | sealed-schedule regression | 1,724 | 0 | 2/2 | 3/3 | 25 | 227 |
| v5 lane-fair | post-hoc regression | 51,218 | 0 | 12/12 | 16/16 | 25 | 2,574 |

At B=25:

- v6 selects 63 carrier groups and expands 77 atomic units;
- v5 selects 300 carrier groups and expands 787 atomic units.

At B=100:

- v6 selects 213 carrier groups and expands 227 atomic units;
- v5 selects 1,168 carrier groups and expands 2,574 atomic units.

The full v5 inventory contains 49,058 carrier groups over 51,218 atomic units.
The largest carrier has 55 members. The full v6 inventory contains 1,710 carrier
groups over 1,724 units.

## Cost boundary

The scripted repair, replay, scheduling, and scoring artifacts record zero
external API calls and zero billed model tokens. This does not meter the
interactive Codex and subagent research session that produced the code and
independent reviews.

For comparability only, the older measured Luna low-effort pilot cost
$0.0137408 for 17 calls, or $0.000808282 per normalized unit. Applying that old
prompt shape linearly gives:

| Workload | Expanded units | Historical Luna projection |
|---|---:|---:|
| v6 B=25 | 77 | $0.06 |
| v6 B=100 | 227 | $0.18 |
| v6 full inventory | 1,724 | $1.39 |
| v5 B=25 | 787 | $0.64 |
| v5 B=100 | 2,574 | $2.08 |
| v5 full inventory | 51,218 | $41.40 |

These are historical-shape projections, not current prices or actual bills.
Prompt size, batching, retries, caching, model behavior, and prices can change
them.

## What is proved

The artifacts prove all of the following within the frozen boundary:

- candidate admission is independent of observable AI attribution;
- no candidate is hard-filtered after admission;
- parent candidates and exact fix edges are conserved;
- public squash members are added when recoverable;
- a complete landed patch remains reviewable when atomic provenance is missing;
- the v5 and v6 accepted exact edges are present in the full inventories;
- the B=100 same-fix carrier gate recovers every accepted case and edge;
- schedule ranks and carrier groups cannot be self-signed independently of the
  frozen source candidate units.

## What is not proved

The workflow still cannot recover facts absent from its inputs:

- an incorrect or missing fix/advisory anchor;
- private, deleted, rewritten, or force-pushed history;
- cross-repository copies, vendored code, or generated preimages outside the
  frozen ancestry;
- undisclosed AI assistance without exact-subject attribution evidence.

The fresh method-independent positive denominator is currently zero, so no
population recall interval can be estimated from v5 or v6. Reaching a one-sided
95% exact lower bound of 0.95 requires 59 independent positives with zero
misses; reaching 0.99 requires 299.

Therefore the current claim is finite-inventory completeness plus successful
regression, not fresh blind confirmation or universal zero-miss AI-origin
detection.

## Decision

Stop adding ranking heuristics for now. The remaining research bottleneck is no
longer SZZ or candidate truncation; it is acquiring more independent, strictly
attributed positive cases and extending the inventory boundary to missing or
cross-repository history.

Keep B=100 as the frozen operating gate until a larger forward split justifies a
lower value. Before counting toward the 59-case milestone, a v7 case must pass a
frozen all-research exposure exclusion and must be selected without opening its
causal origin or candidate ranks.
