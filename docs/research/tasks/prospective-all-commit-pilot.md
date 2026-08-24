# Prospective all-commit recall pilot

Date: 2026-08-01

## Decision

SZZ and AI-attribution regexes are ranking signals, not candidate gates. The
recall floor for a selected advisory is every commit in the repository's local
object graph. Source roots add a compressed ancestry overlay; they never remove
the repository fallback.

## Frozen intake

The split was frozen before target histories, fix SHAs, commit messages, SZZ
results, or audit judgments were read by the selector.

- Split ID: `prospective-all-commit-20260801-v1`
- Deterministic rule: global SHA-256 ordering over split ID, source class,
  repository, and advisory
- Quota: six `association_only` and six `public_exact_present`
- Minimum legacy AI exposure: eight units
- Repository disjointness: one advisory per repository
- Prior-case exclusion: 79 advisories and 53 repositories
- Strict projected pool: 798 repository/advisory rows from 8,566 description
  associations intersected with 1,757 AI-exposed repositories
- Model calls during projection and selection: zero

The selector accepts exactly seven fields: candidate ID, repository identity,
advisory, aggregate AI-unit count, routes, tools, and source class. A row that
contains `fix_sha`, origin, message, description, search output, SZZ output, or
an audit label fails the contract.

| Source class | Repository | Advisory | AI units |
| --- | --- | --- | ---: |
| association only | huggingface/transformers | CVE-2025-14921 | 26 |
| association only | mervinpraison/praisonai | GHSA-pv2j-rghr-v5r9 | 247 |
| association only | churchcrm/crm | CVE-2025-11938 | 217 |
| association only | openc3/cosmos | CVE-2025-28389 | 55 |
| association only | langflow-ai/langflow | CVE-2026-10140 | 198 |
| association only | open-metadata/openmetadata | CVE-2025-50468 | 482 |
| public exact present | nltk/nltk | CVE-2026-33236 | 23 |
| public exact present | gogs/gogs | CVE-2026-26195 | 10 |
| public exact present | sgl-project/sglang | CVE-2026-3059 | 132 |
| public exact present | mail-0/zero | CVE-2025-52557 | 75 |
| public exact present | charmbracelet/soft-serve | CVE-2026-24058 | 17 |
| public exact present | openssl/openssl | CVE-2025-9230 | 14 |

## All-commit universe result

The final v3 artifact chooses among same-origin local clones using only graph
completeness, frozen AI-unit conservation, commit count, and lexical path order.
For a stale shallow marker, it may use the complete local object graph only when
an alternate read-only traversal succeeds and parent closure remains complete.

- Selected repositories conserved: 12/12
- Repository fallbacks conserved: 12/12
- Visible commits retained once: 292,938
- Legacy AI-overlay commits: 1,496
- Commits without a legacy AI label: 291,442
- Complete local repository universes: 11/12
- `BLOCKED`: OpenC3/COSMOS, because a parent object is genuinely unavailable
- Model calls and cost: zero / USD 0

The 291,442 unlabeled commits are the concrete false-negative exposure of using
AI regex attribution as an entrance gate. They are not claims of AI authorship;
they remain candidates so later evidence can recover missed attribution.

## Zero-token source replay

After intake freeze, the replay attached public exact references, cached
enriched selections, ranked search carriers, and local commit-message carriers.
Every resolved root is a candidate hint, not an adjudicated fix.

- Selected associations conserved: 12/12
- Source observations: 155, all locally resolvable
- Evidence kinds: 11 public exact, 9 enriched selected, 120 ranked-search
  carriers, and 15 repository-reference carriers
- Unique root hints: 131
- Roots with complete coverage: 120
- Roots blocked by the incomplete COSMOS universe: 11
- Compressed root-membership rows: 168,533
- Full-repository fallbacks still present: 12/12
- Model calls and cost: zero / USD 0

All 12 pairs have at least one resolved hint, but this is not 12/12 fix-source
recall: every pair inherited ranked-search candidates. In particular, the six
`association_only` rows have no public exact root. The fallback covers the
remaining 124,405 commits that have no root-mask membership and also protects
against a wrong root.

## Claim boundary

This pilot proves candidate conservation and measures queue expansion. It does
not yet estimate vulnerability prevalence, detector precision, true fix-source
recall on the association-only stratum, or vulnerable-origin recall. A
`BLOCKED` root or repository is unknown, never negative.

## Blinded root-adjudication result

The first 2+2 diagnostic failed because the packet used the cached search title
instead of the full CVE description. For Mail-0 this reduced “malicious email
executes JavaScript because of improper sanitization” to “session hijacking”
and sent the model toward a session-cache patch. Packet v3 and later use the
hash-verified CNA title and full description when available.

The second diagnostic exposed a different control defect. NLTK's public SHA is
a merge whose tree is identical to the feature parent selected by the model.
The sealed scorer now reports raw exact-SHA recall separately from a narrow
structural closure that accepts only a tree-identical parent of a referenced
merge.

The complete 12-packet run then exposed a source-label defect. The SGLang
“public exact” SHA is a machine-inferred OSV range boundary and is an unrelated
GPU hotfix; that SHA is absent from the frozen CVE record, which points to a PR
and release. Public-control eligibility now requires that the SHA occur
literally in the hash-verified CVE record. Inferred range boundaries remain
candidate signals but cannot act as ground truth. This rule was applied to all
six nominal controls.

- Model: local CLIProxyAPI `gpt-5.6-luna`
- Calls: 12, all resolved
- Reasoning: medium for nominal controls, high for association-only targets
- Prompt / completion / reasoning tokens: 113,580 / 9,557 / 8,469
- Input-price assumption: USD 0.20 per million tokens
- Estimated input cost: USD 0.022716; output price remains unspecified
- Raw OSV-boundary exact hits: 4/6
- Source-qualified controls: 5/6
- Qualified narrow-closure hits: 5/5
- Root hints selected for priority: 20/131

The full run is a revised diagnostic, not a pristine estimate: the eligibility
rule and merge closure were introduced after failures exposed those defects. A
fresh held-out control set must validate both rules before a paper claim.

## Recall-preserving origin queue

The source-qualified score was projected into a compressed priority overlay.
Model selections and explicit public controls create a top queue; corroborated
and ranked-only roots follow. No class is a filter.

- All commits retained exactly once: 292,938
- All source roots retained: 131
- Priority roots: 21
- Legacy-AI ancestors of priority roots: 364
- Unlabeled ancestors of priority roots: 138,188
- Other-root ancestors: 29,981
- Repository-fallback commits: 124,405
- Hard filters: zero
- Compressed overlay size: about 7.6 MB

The large unlabeled priority ancestry is why AI attribution cannot be an
entrance gate. It is also why the next stage must collect cheap structural
signals before sending individual commits to a model.

## Langflow origin-signal diagnostic

The high-confidence association-only Langflow root was used for a zero-token
comparison. This is candidate expansion, not a measurement of SZZ recall,
because no origin ground truth is available.

- union of copy-aware and file-local blame SZZ: 6 candidates
- complete history of the two affected files: 12 candidates
- file-history candidates absent from SZZ: 6
- ancestors of the selected root retained by reference: 18,166
- full repository fallback retained by reference: 58,357
- old explicit-AI attribution among the 12 file-history candidates: 0

The earliest voice-mode feature commit is present in the SZZ set, but its large
squash message has only weak automation/generated-summary style signals, not a
production-grade explicit AI attribution. It must remain an attribution-review
candidate rather than being labeled AI.

## Next falsifiable gate

1. Freeze a new held-out control set using explicit-CVE-commit eligibility
   before inference; require full qualified-control closure recall.
2. Add weak AI regex/style signals as a shadow routing lane only. Measure their
   incremental yield and false-positive rate against explicit attribution; do
   not merge them into AI ground truth.
3. Blindly adjudicate the 12 Langflow affected-file candidates for origin
   plausibility at high reasoning. Compare selected hypotheses with SZZ and
   file-history-only lanes, while retaining both ancestor and repository
   fallbacks.
4. Repeat on another complete-history, high-confidence unknown root. Keep
   OpenC3/COSMOS `BLOCKED` until its missing parent object is recovered.

## Frozen artifacts

- `.ai-slop/state/cohort-v1/prospective-pool-20260801-v1`
- `.ai-slop/state/cohort-v1/prospective-intake-20260801-v1`
- `.ai-slop/state/cohort-v1/all-commit-universe-20260801-v3`
- `.ai-slop/state/cohort-v1/prospective-source-replay-20260801-v1`
- `.ai-slop/state/cohort-v1/prospective-source-replay-20260801-v1/validation.json`
- `.ai-slop/state/cohort-v1/root-adjudication-packets-20260801-v6`
- `.ai-slop/state/cohort-v1/root-adjudication-execution-20260801-v3`
- `.ai-slop/state/cohort-v1/origin-priority-overlay-20260801-v1`
- `.ai-slop/state/cohort-v1/origin-signal-pilot-langflow-20260801-v1`

The superseded v1 and v2 all-commit universes were removed after v3 passed the
independent conservation validator, reclaiming approximately 133 MiB.
