# Recall-safe AI routing pilot

## Purpose

Measure whether a cheap model can prioritize audited causal edges without ever
turning a low score into deletion. This is a routing eval, not ground truth.

## Frozen slice

- Four exact `AI_CAUSAL` controls that already passed relation closure.
- Three deterministic, unlabeled same-fix comparators per control.
- Labels are retained for evaluation but omitted from model requests.
- Merge commits are rendered against their first parent so a merge-based
  security fix cannot be mistaken for an empty or unreadable diff.

Held-out runs may use `--allow-fewer-comparators`: the control is conserved
even when its fix has fewer than three alternative cohort candidates, and the
actual count for each control is frozen in `pilot_spec.json`. This avoids
silently selecting only repositories with dense candidate histories.

The four controls in the first two runs are a development split. The second
prompt was changed after inspecting a miss, so its 4/4 result is not held-out
evidence. `scripts/cohort_heldout_controls.json` freezes the next split before
any further model request: five manually audited controls from five repositories
that are disjoint from the development repositories. The split admits only an
exact atomic origin, exact fix, and a direct cohort unit or audited landed
squash; historical positives outside the forward cohort remain `BLOCKED`
rather than becoming false negatives.

## Cost contract

- The paid reference run used exact model `gpt-5.6-luna`, low reasoning.
- CLIProxyAPI runs verify that the requested alias exists exactly once in the
  live `/models` response and retain both the requested and provider-reported
  model names.
- CLIProxyAPI reasoning is either encoded by an explicit model suffix
  (`backend-alias`) or sent as an explicit `reasoning_effort` request field. A
  suffix-free model such as `gpt-5.6-terra` may not use `backend-alias`.
- One physical request per item; no automatic retries.
- Input-token ceiling is conservatively bounded by request UTF-8 bytes plus
  message overhead.
- Each request sends an output-token cap, but compatibility providers may
  account hidden reasoning outside that visible cap. Measured reconciled usage,
  rather than the request field alone, is the audit surface.
- Live LiteLLM model-info prices must equal or undercut the prepared prices.
- The complete worst-case reservation must fit the operator cap before the
  first paid request.
- CLIProxyAPI currently exposes no per-token pricing contract. A recorded known
  cost of zero means "price unavailable locally", not that the upstream request
  was free.
- OpenAI-compatible providers disagree on whether hidden reasoning is included
  in `completion_tokens`. Usage accounting therefore takes the larger of
  reported completion tokens and `total_tokens - prompt_tokens`; if no total is
  available, separately reported reasoning is added conservatively.

## Routing contract

- `likely` and `possible` become `PROMOTE`.
- `unlikely` and `insufficient` remain `DEFER`.
- Transport, parse, or evidence failures become `BLOCKED`.
- Every pilot edge receives exactly one disposition; no edge is deleted.
- Do not scale unless all controls are promoted and the comparison
  promotion rate remains informative.

## Observed runs (2026-07-31)

The development prompt-v1 run promoted 3/4 controls. Inspection showed that a
large Coolify fix placed the relevant path after the global 8,000-character
prefix. Prompt-v2 prioritized candidate-changed paths and promoted 4/4 on the
same items; because that change used the miss, both runs remain development
evidence.

The repository-disjoint held-out run froze five controls before execution. The
first relation pass found only 3/5: relation construction intersected PR members
with mainline cohort units, deleting atomic commits erased by squash. Retaining
every PR member raised relation recall to 5/5, with 149/149 relation roots
resolved and no model use. Public exact-fix source recall was separately 4/5.

The frozen Luna run contained five controls and twelve unlabeled same-fix
comparators. It made 17 physical calls with no retries or failures, used 53,026
input and 2,613 output tokens, and cost $0.0137408. All 5/5 controls were
`PROMOTE`; all 12/12 comparators remained `DEFER`; all 17 routes were conserved.
The comparator rows are not adjudicated negatives, so 0/12 is queue-separation
evidence, not a precision estimate. Total model spend across both development
runs and this held-out run was $0.0416898.

### Local CLIProxyAPI replay

The same frozen 17 items and prompts were replayed through local CLIProxyAPI.
The semantic and byte hashes were identical across models; neither labels nor
prompt text changed. Three representative aliases were chosen before seeing
their results rather than searching all exposed aliases for a winner:

| Requested model and effort | Controls promoted | Unlabeled comparators promoted | Input tokens | Reconciled completion/reasoning tokens | Gate |
| --- | ---: | ---: | ---: | ---: | --- |
| `gemini-3.5-flash-low` (`backend-alias`) | 5/5 | 0/12 | 62,518 | 8,817 | pass |
| `gpt-oss-120b-medium` (`backend-alias`) | 4/5 | 0/12 | 54,114 | 5,752 | fail |
| `gpt-5.6-terra` (legacy unspecified default) | 5/5 | 3/12 | 58,058 | 1,481 | pass, not selectable |
| `gpt-5.6-terra` (explicit `medium`) | 5/5 | 2/12 | 58,058 | 1,533 | pass |

The Gemini response reported provider alias `gemini-default`; the requested
exposed alias remains frozen separately. Its raw responses reported only 874
visible completion tokens, but `total_tokens - prompt_tokens` was 8,817 because
7,943 hidden reasoning tokens were accounted outside `completion_tokens`. The
raw artifacts exposed this provider mismatch and motivated the conservative
usage reconciliation above.

GPT-OSS missed the Taylored PayPal-webhook control
(`GHSA-8g98-m4j9-qww5`) and is rejected as a sole router. The legacy Terra run
did not send an explicit effort and is retained only as diagnostic evidence.
The explicit Terra-medium run is the local default: cross-commit causality is a
reasoning task, medium passed all frozen controls, and high is not justified
unless medium first fails a separately frozen development batch.

A routine Gemini second opinion is not justified by this batch. Running
Gemini-low only over the ten Terra-medium `DEFER` items would add 38,568
reconciled tokens and promoted none of them. On these items, the OR ensemble is
therefore identical to Terra-medium while using about 65% more tokens. Gemini
is retained only as a candidate transport/provider fallback. The current router
keeps a failed or unreadable primary response `BLOCKED`; it does not yet
silently invoke or trust a second provider.

This is a successful small falsification batch, not proof of global zero false
negatives. The next claim-grade step is a larger repository-disjoint held-out
set frozen under the same contracts, without further prompt edits.

### Expansion batch: discovery recall before model quality

The next split was frozen from a fail-closed census of all 37 independently
adjudicated `AI_CAUSAL` rows. The census found 17 atomic rows, 5 multi-origin,
3 cross-repository origins, 1 multi-fix, 8 rows under an obsolete audit
contract, and 3 below the confidence threshold. After excluding every prior
development or held-out repository, it selected three atomic controls:
Karakeep `CVE-2026-27627`, mruby `CVE-2025-13120`, and ZeptoClaw
`CVE-2026-32232`. Every unselected row retains an explicit disposition; the
three convenient atomic cases do not stand in for the complex cases.

A cold replay through the old 180-day outcome cohort found 0/3 expected
origin-to-fix edges. No model was called. The failure decomposed into two
independent candidate-generation bugs:

- Karakeep and ZeptoClaw were newer than 180 days. The follow-up threshold is
  valid for estimating outcome rates but invalid for vulnerability discovery.
  Discovery now uses an all-age candidate population; the mature 180-day slice
  remains a separate estimation population.
- mruby used the exact marker `Co-authored-by: Atlassian Rovo Dev` without an
  email address. The broad shadow detector saw it, but the production source
  matcher discarded it. Source policy v3 registers that exact bare marker as
  candidate evidence. Generic or near-match bare co-author lines remain
  ineligible, and this evidence does not itself certify downstream causality.

The all-age population under the old source matcher recovered 2/3 controls.
After the source-policy fix, a fresh three-repository scan contained 2,120
AI-attributed units and relation closure retained 2,120 direct plus 1,806
composite edges. The final no-token gate recovered 3/3 audited relations and
3/3 public exact fixes. It still reported 15 blocked relation roots: 12
ambiguous PR-to-landed mappings and 3 missing PR refs. Ambiguous PR numbers now
fail closed per landed commit instead of aborting the campaign or fabricating a
relation.

Only after that 3/3 gate passed was the new blind routing batch sent to local
CLIProxyAPI. The frozen batch contained 3 controls and 9 unlabeled same-fix
comparators, with no role or audit-label fields in the requests. Explicit
`gpt-5.6-terra` medium reasoning made 12 physical calls with no failures, used
40,114 input and 809 reconciled completion/reasoning tokens, promoted all 3/3
controls, and promoted 1/9 comparators. CLIProxyAPI exposes no token-price
contract, so the artifact's known cost of zero means unpriced, not free.

### Remaining workflow debt

- Exact source identities are a curated registry. Unknown bare tool markers
  remain shadow telemetry and need a periodic false-negative census rather than
  silent exclusion.
- Shallow history, missing PR refs, and ambiguous squash mappings remain
  `BLOCKED`, never negative. More history can reduce this unknown set, but no
  score may erase it.
- The first complex development batch now has explicit recall tests, but a new
  repository-disjoint complex split must be frozen before claiming that the
  result generalizes.

### Complex-structure development batch

Nine audited complex cases were frozen before replay: five multi-origin, three
cross-repository, and one additional multi-fix dimension (some cases have more
than one dimension). Candidate generation received exact fix roots as an
evaluation overlay; the gate required every one of 20 target relations and four
upstream import relations. The no-token relation result was 24/24 and 9/9
complete cases. This is development-set recall, not proof of zero false
negatives outside the ledger.

Only after that gate passed, local CLIProxyAPI `gpt-5.6-terra` with explicit
medium reasoning evaluated the 20 same-repository target obligations. There
were no comparators in this diagnostic batch. The run made 20 calls, used
63,509 input and 2,814 reconciled output/reasoning tokens, and promoted 19/20.
The sole `insufficient` result was ZeptoClaw
`d3480ca94087b74f110bb5b80fc8219b32c8b8b5` to
`68916c3e4f3af107f11940b27854fc7ef517058b`: the 6,000-character global
candidate prefix ended in documentation before reaching
`src/security/shell.rs`, although the fix evidence showed that exact path.

Prompt evidence retrieval now prioritizes paths changed by both candidate and
fix before adding a global prefix. A single, explicitly post-hoc repair probe
then exposed the vulnerable regex and corresponding fix and changed the same
Terra-medium route from `insufficient` to `likely` (3,627 input and 108 output
tokens). This 1/1 probe validates the truncation mechanism; it must not be
combined with the original 19/20 as an unbiased 20/20 model result. High
reasoning was not tried because the failure was missing evidence, not failure
to reason over present evidence.

CLIProxyAPI reported 111 exposed aliases and no price contract, so both runs
record zero *known* cost. That is not an upstream billing claim. The 21 calls
used 67,136 input and 2,922 reconciled output/reasoning tokens in total.

### Repository-disjoint claim-grade continuation

- A full six-target candidate inventory contains 193,065 direct edges before
  squash expansion. At the measured 3,175 input tokens per complex target
  prompt, sending the whole queue would be roughly 613 million input tokens.
  The model must remain a budgeted prioritizer; low scores stay `DEFER`.
- Candidate generation now accepts a strict, separately sealed fix-only
  manifest. The repository-disjoint replay records
  `sealed_fix_only_no_golden_ledger_read`; extra origin or relation fields are
  rejected and the full gold ledger is evaluation-only.
- Bare `owner/repo`-shaped transfer prose now enters a first-class `BLOCKED`
  ambiguity ledger. The development replay preserved 4/4 upstream obligations
  while separating 1,774 ambiguous mentions from 1,127 explicit carriers.
- Public exact-fix coverage needs an independently sealed source beyond the
  current local OSV snapshot for advisories such as `CVE-2026-2376`.
- A repository-disjoint split was frozen before any request: Graphiti
  `CVE-2026-32247` and ClearanceKit `CVE-2026-34218`, five target obligations in
  total. The sealed no-token gate passed 5/5 and 2/2 cases. Five Terra-medium
  prompts were then frozen with shared-path evidence and a five-request cap.
  Execution used the loopback CLIProxyAPI at `127.0.0.1:8317`; the earlier
  external `goldbug.gtisc.gatech.edu:41414` value was stale process environment,
  not the intended pilot endpoint. All five responses completed with the
  requested `gpt-5.6-terra` model and explicit `medium` reasoning: three were
  `likely`, two were `possible`, and all five were conservatively promoted.
  Held-out routing recall is therefore 5/5 and the scale gate passes. The run
  used 18,943 input and 383 reconciled output tokens. It has no negative
  comparators, so this establishes held-out positive retention but says nothing
  yet about precision. CLIProxyAPI exposed 43 aliases and no price contract;
  recorded known cost is zero, which is not an upstream billing claim.

A second frozen batch kept those five control edges and prompts byte-identical
and added two same-fix, same-relation, date-nearest comparators per obligation.
Shared-fix controls are now all reserved before comparator selection, preventing
one known origin from being consumed as another origin's comparator. The 15
Terra-medium calls retained all 5/5 controls and promoted 2/10 unlabeled
comparators; the other 8/10 were deferred, not deleted. The run used 47,131
input and 879 output tokens. At the frozen operator assumptions of `$0.20/M`
input and `$1.20/M` output, estimated cost is `$0.010481` against a conservative
`$0.046396` reservation and `$0.10` hard cap. Both promoted comparators look
post-hoc like non-causal semantic near neighbors: one overlaps the broad policy
domain and one touches the same adapter lifecycle. That is a useful failure
mode, but the unlabeled comparator rate is not a claim-grade false-positive
rate. Future CLIProxyAPI pilots must provide explicit input and output price
assumptions because the proxy's zero known price is not a budget contract.

### Population-contract hardening

The observed 0/3 cold-replay miss was not merely documented. Discovery and
fixed-window estimation now carry different content-bound population roles.
`scripts/cohort_prepare_populations.py` creates both branches from one scan:
`all_age_discovery` mechanically requires zero minimum follow-up, while
`mature_outcome_estimation` requires a positive threshold. The exact scan
summary and commit corpus are hashed into both contracts. Stated-outcome
artifacts inherit the contract and bind the exposure summary hash. Advisory
candidate generation accepts only `all_age_discovery`, before it reads OSV
archives or constructs any candidate edge.

A real no-network smoke over the frozen expansion scan conserved 2,120 units in
discovery but only 1,090 in the 180-day estimation slice. Thus the old wiring
would have removed 1,030 young units, or 48.6% of this scan, before candidate
generation. Deliberately feeding the mature outcomes to the candidate CLI now
fails immediately with an expected/observed population-role mismatch and does
not create an output directory.

The positive branch then processed Karakeep without a model call: 75 direct
candidate edges remained `DEFER`, relation closure added 329 composite edges,
and the frozen Karakeep gate recovered 1/1 audited relation plus 1/1 public
exact fix. The artifacts are under
`.ai-slop/state/cohort-v1/populations-contract-smoke-20260731-v1`. The smoke
also confirmed that rereading the full local OSV archive dominated this small
one-repository run, motivating the content-addressed index below rather than
another model experiment.

### Content-addressed advisory index

The advisory parser now persists one gzip-compressed fix-index shard per OSV
archive content hash. Candidate generation still hashes every source archive
and records the combined manifest; the cache is only a derived accelerator.
An archive content change selects a new shard, a corrupt or schema-mismatched
shard is reparsed, and a non-empty historical reproduction cutoff bypasses the
cache so its old in-window accounting remains exact. Cache failures fall back
to parsing and are recorded rather than deleting fix references.

The real corpus contained 46 archives, 874,612 records, and 126,215 records
with commit references. A cold build had 46 misses and spent 108.76 seconds in
shard construction. Its compressed cache is 9.6 MB versus 1.4 GB of source OSV
archives. The warm run had 46/46 hits: archive manifest hashing took 1.098
seconds, shard loading and repository filtering took 1.012 seconds, and the
complete advisory-index stage took 2.11 seconds. Cold and warm
`candidates.jsonl`, `fix_roots.jsonl`, `public_fix_references.jsonl`, and
`routing.jsonl` were byte-identical. Both runs kept all 75 Karakeep edges and
made zero model calls.

### Audit correction without post-hoc split inflation

An independent Anchorr `CVE-2026-32890` history review corrected the legacy
manual audit. `403ccf079be0ee5e6660f0ed2fa64174d76eff2f` is the single
Claude-attributed causal origin of the reported Discord display-name XSS.
`8690a9f89e69f250d14614a4876f63c465177fce` is AI-attributed but changed a
different already-existing avatar-display path and is not a second origin.
`6ea6bbb5bc5140f5e1561f5970cefd778ed7e359` is a partial text-escaping repair
immediately before public final fix
`d5ae67e5b455241274ed0072cf2db43a6eb3f0b2`; public reference `64bc627` only
changes reporter credits.

Anchorr is the only genuinely new repository left after accounting for the
already-frozen expansion and complex held-out splits. It is retained as a
corrected audit obligation, not advertised as a one-case held-out batch and not
used to justify another model call. Freezing a split after inspecting that sole
case would add a number while weakening the claim boundary.

### Repository-disjoint audit-debt recovery batch

The remaining obsolete audit-contract population was enumerated before new
history work. All eight `AUDIT_CONTRACT_MISSING` census rows received a frozen
disposition: ZeptoClaw was excluded because its repository was already in a
prior split, Graphiti because its advisory was already a prior control, and all
six remaining repositories were selected without inspecting their new history.
This is a known-positive structural-recovery batch, not a blinded detector,
prevalence, precision, or global zero-false-negative evaluation.

Independent full-history review produced four atomic controls and two true
multi-fix controls, eight origin-to-fix obligations in total. The six-repository
scan found 392 AI-attributed commits. The fix-only generation process resolved
31/31 fix roots and conserved 819 direct candidate edges. Relation closure added
324 composite edges, for 1,143 conserved edges. Two additional PR roots remain
explicitly `BLOCKED` because no PR ref could be recovered; neither is part of a
frozen control obligation.

The no-token structural gate recovered all 4/4 atomic and 4/4 complex target
relations. Public exact-fix coverage was separately only 5/8: the local public
archive lacked the Claude Code fix and both n8n-workflows fixes. Those three
misses are advisory-source coverage debt, not ancestry/relation-engine misses.
The 8/8 result is therefore evidence over these frozen known positives only.

That source debt now has a recall-first repair. Candidate generation unions the
original OSV references with locally cached description-search selections,
every ranked candidate even when a cached model rejected the advisory, and a
no-date-window local commit-message scan over repository-scoped
CVE/GHSA/issue/PR anchors. The tiers remain explicit: cached selections are enriched evidence,
and ranked/reference matches are carriers rather than verified public fixes.
It also emits a separate repository×advisory fallback containing every observed
AI-attributed unit and no fabricated fix SHA.

A source-only replay over the same six repositories did not pass the sealed fix
manifest or either golden origin ledger to generation and made zero model/API
calls. It resolved 67/67 proposed roots, produced 2,219 direct ancestry edges,
and retained 4,378 additional fallback rows as `DEFER`. Evaluation loaded the
fix-only manifest afterward: public exact remained 5/8, public plus cached
selection reached 7/8, all source candidates reached 8/8, and repository
fallback coverage was 8/8. Relation closure produced 2,766 conserved direct
plus composite edges; the frozen atomic obligations remained 4/4 and complex
target obligations 4/4. Three unrelated PR roots were `BLOCKED` on missing PR
refs and were not converted to negatives.

This 8/8 source result is a post-hoc repair check on the batch that exposed the
three misses, not an unbiased estimate of future source recall. The stronger
mechanism claim is conditional: once an advisory-to-repository association is
known, a missing or wrong fix source no longer removes any observed cohort unit
because the repository fallback remains available. Advisories whose repository
association is itself absent remain outside that guarantee and are the next
source-intake problem.

Two blind, budget-capped CLIProxyAPI batches then used `gpt-5.6-terra` with
explicit medium reasoning and two same-fix comparators per control. The atomic
batch promoted 4/4 controls and 1/8 unlabeled comparators, using 55,583 input and
1,258 reconciled output/reasoning tokens. The complex batch promoted 3/4
controls and 1/8 comparators, using 52,684 input and 922 output tokens. Under the
frozen `$0.20/M` input and `$1.20/M` output assumptions, the 24 calls cost an
estimated `$0.0242694`. The proxy's reported known cost of zero remains
unpriced, not free. Comparator promotion is diagnostic and is not a precision
estimate.

The sole model miss isolated another evidence-retrieval failure. Bambuddy
candidate `a7319f0e7087cee59f1aa658c52c6408f1fb71e8` added an unauthenticated
state-changing debug route in `backend/app/api/routes/printers.py`, while the
primary fix `c31f2968889c855f1ffacb700c2c9970deb2a6fb` added global authentication
middleware in `backend/app/main.py`. The old shared-path-first prompt exposed
only the candidate's unrelated `main.py` timing work, so more reasoning effort
could not recover the absent route evidence.

Prompt retrieval now adds a deterministic cross-file security-surface bridge.
When a candidate adds a route/controller/handler surface in a path not changed
by a later global guard, relevant added hunks and global middleware/auth guard
hunks are placed before shared-path and global-prefix evidence. This heuristic
only adds prompt evidence; it does not score or delete candidate edges, and
false-positive bridges are acceptable in the recall-first queue.

One explicitly post-hoc mechanism probe reran only the missed Bambuddy control
with the same Terra-medium model. The route and middleware were both visible,
and the result changed from `unlikely` to `possible`, returning the edge to
`PROMOTE`. It used 4,341 input and 55 output tokens, estimated at `$0.0009342`.
This validates the retrieval mechanism but must not be combined with the
original complex batch as an unbiased 4/4 result; the prospective result remains
3/4. High reasoning was not tried because the diagnosed failure was missing
evidence. Across the original two batches plus this diagnostic probe, total
usage was 25 calls, 112,608 input tokens, 2,235 output tokens, and an estimated
`$0.0252036`.
