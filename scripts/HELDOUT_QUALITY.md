# Independent held-out detector-quality gate

This lane measures the current fixed-contract campaign on labels that have never
been used for detector calibration, adjudication, publication override, or
inclusion. It complements `evaluate_detector_quality.py`, whose existing audit
corpus has known selection bias.

## Two explicit estimands

`heldout_quality_gate.py` retains the conditional classifier study among classes
where the pipeline already found an AI signal. Its report field remains
`recall`, with `measurement_boundary` naming the candidate-positive denominator.

`build_recall_audit.py` measures end-to-end recall from a complete formal
detector inventory. It samples these alias-class strata independently:

- detected positive
- no fix commit
- fix found with no BIC
- BIC found with no trusted authorship signal
- trusted authorship signal with a negative or incomplete classifier result

Classes with missing, incomplete, or errored current campaign coverage are
assigned to the dedicated `coverage_failure` stratum. API/PR lookup failures,
uncached classes, and missing campaign results never enter a negative stratum.
Any coverage failure withholds the formal recall result. Prior labeled/protected
classes stay outside the random sample. Schema-4 selection simultaneously seals
a full census of every protected class that overlaps the formal alias population.
Conclusive independent census labels contribute exact positive counts; the report
withholds whole-population `recall` until every overlap is covered exactly once.
The report may retain a clearly named covered-unprotected diagnostic while either
coverage or census evidence is incomplete. Every nonempty measured stratum has a
positive, recorded selection
probability. The estimator expands each sample with `N_h * y_h / n_h`, inverts
the finite-population hypergeometric distribution for integer positive-count
bounds, and applies a Bonferroni family-wise 95% interval across strata.

An empty detected-positive stratum is a valid formal population state. When
the missed-positive estimate is positive, the report records point recall `0`,
interval `[0, 0]`, and status `defined_zero_no_detected_positives`. When both
the detected and missed positive estimates are zero, the recall denominator is
zero; `recall_point` and `recall_interval` are null and `recall_status` is
`zero_estimated_actual_positives`. `recall_denominator_estimate` records that
boundary explicitly. Protocol, coverage, protected-population, and unresolved-
review blockers continue to control `evaluation_complete` independently.

Create and commit the label-free selection before reviewers receive packets:

```bash
uv run --project cve-analyzer python scripts/build_recall_audit.py select \
  --repo-root . \
  --inventory web/data/inventory.json \
  --sample-sizes scripts/heldout_studies/recall-sample-sizes.json \
  --protected-source path/to/additional-calibration-inputs \
  --output scripts/heldout_studies/recall-selection-<sha256>.json
```

The selection output path must be new. The selector rejects an existing file or
symlink before scanning protected inputs, preserving prior sealed evidence and
keeping the pending output outside its own protected-input manifest.

The selector scans the same authoritative protected roots listed below, hashes
every source file, extracts and alias-expands every referenced advisory ID, then
adds any repeated `--protected-source` roots. The deprecated `--protected-ids`
option is accepted only as one additional source file; it cannot replace or
shrink the mandatory roots. Schema-4 selection evidence seals the complete root
and file manifest plus the protected-subject count and digest. Its independently
hashed `protected_census` sub-artifact binds the detector `inventory_id`, source
snapshot, formal alias-class manifest, authoritative protected-input identity,
and an ordered exact-once assignment for every overlapping alias class.

The selector also generates a 256-bit seed from the operating-system CSPRNG,
embeds the revealed seed and exact sample-size contract, and seals the result.
The evaluator re-resolves every recorded root, requires every current mandatory
root, rehashes the files, rebuilds alias expansion, and excludes only the current
selection/label pair so historical studies remain protected. It then rebuilds
the selection from that protected inventory and the immutable detector inventory;
any omitted root, provenance drift, swapped sample, or resealed sample fails
closed. Alias classes must be globally disjoint and contain their canonical class
ID.

The generated random and census `blinded_review_packets` contain packet and
advisory IDs only.
Detector output, stratum, and signature matches remain in the sealed assignment
map. Each conclusive review cites repository-hosted PR/issue/commit history,
authenticated audit logs, or attributable maintainer evidence. `UNKNOWN` and
review disagreement trigger a distinct third review; any unresolved packet keeps
`evaluation_complete=false` and withholds the recall estimate.

Recall labels use schema 3. The top-level `audit_protocol` covers both lanes;
`protected_census.census_manifest_sha256` binds census adjudications to the
separate census seal, and `audit_protocol_sha256` binds them to the same blinded
dual-review attestations. Census adjudications use the same primary, secondary,
optional third-review, evidence-reference, and rationale shape as random packets.

Commit the canonical selection JSON before creating labels. Put
`<full-selection-commit>:<repository-relative-selection-path>` in
`audit_protocol.selection_commit_reference`. Evaluation proves that commit is a
strict ancestor of the current label commit, the label path was absent from the
selection commit, and both tracked files match exact bytes.

```bash
uv run --project cve-analyzer python scripts/build_recall_audit.py evaluate \
  --inventory web/data/inventory.json \
  --selection scripts/heldout_studies/recall-selection-<sha256>.json \
  --labels scripts/heldout_studies/recall-labels-<sha256>.json \
  --repo-root . \
  --output .ai-slop/state/data-refresh/end-to-end-recall-current.json
```

## Measurement boundary

Two samples are sealed from raw, receipt-backed campaign results:

- **Precision trials**: alias classes that the final detector predicts positive.
- **Recall trials**: an independently ranked sample of alias classes where at
  least one raw candidate bug-introducing commit already carries an AI signal,
  before the final inclusion decision.

Each lane uses one global, domain-separated SHA-256 ranking and takes its top
`k` alias classes. Every class in a lane population therefore has the same
inclusion probability. Canonical ID families are reported only as diagnostics;
they do not receive quotas or change selection probabilities. Human labels never
enter selection. CVE/GHSA/OSV/RUSTSEC aliases form one trial.

Recall therefore covers the final causal classifier within the discovered
AI-signal candidate population. Advisory discovery and AI-signature discovery
recall remain separate, unmeasured boundaries. A later discovery-recall study
needs a precommitted random sample from the full advisory population and manual
repository investigation for every case.

## 1. Finish and prove the campaign

Every planned batch needs a valid schema-6 marker and exact staged result
manifest. Every raw result needs a successful `gpt-5.6-luna` / `max` receipt.
Selection exits with status 2 while any proof is missing, stale, malformed, or
contains infrastructure failures.

## 2. Seal the sample before auditing

```bash
uv run --project cve-analyzer python scripts/heldout_quality_gate.py select \
  --precision-sample-size 100 \
  --recall-sample-size 300 \
  --output-dir .ai-slop/state/data-refresh/heldout-v1
```

The selector automatically hashes and excludes every ID and source-backed alias
found in:

- `scripts/audit_adjudications.json`
- `scripts/audit_overrides.json`
- `scripts/audit_removed_94.json`
- `scripts/audit_results/`
- `scripts/fixtures/`
- `scripts/heldout_studies/`
- `.ai-slop/state/data-refresh/adjudicated-corpus-subjects.txt`

These current defaults are authoritative during selection, standalone
evaluation, and formal release generation. A recorded selection cannot omit a
default that exists in the current code. Recorded non-default roots are retained
as add-only protected sources. Pass every additional calibration, inclusion,
audit, or hand-labeled source with repeated `--protected-source PATH`. The
selection records the exact file inventory, hashes, alias-expanded protected-ID
hash, campaign proof hash, and raw result hashes. Any later input or campaign
change blocks evaluation and promotion.

Protected-input scanning is case-insensitive and covers filenames, URL-decoded
text, and recursively decoded JSON keys and string values. JSON escapes, lower
case advisory IDs, and percent-encoded URL IDs therefore remain protected. Files
are read through no-follow descriptors and are rejected if their inode or
metadata changes during the read.

The command writes a content-addressed `selection-<sha256>.json` plus an
intentionally incomplete schema-3 `labels-<sha256>.template.json`. The label
packet contains selected IDs and aliases while omitting detector predictions,
prediction reasons, and precision/recall lane membership. Before anyone creates
labels, copy the selection into the permanent study registry and commit its exact
bytes. Keep the final label path absent from this commit:

```bash
mkdir -p scripts/heldout_studies
cp .ai-slop/state/data-refresh/heldout-v1/selection-<sha256>.json \
  scripts/heldout_studies/
git add scripts/heldout_studies/selection-<sha256>.json
git commit -m "Protect detector-quality measurement from label leakage" \
  -m $'Confidence: high\nScope-risk: narrow\nTested: held-out selection seal'
git rev-parse HEAD
```

Set the label file's `selection_commit_reference` to
`<full-commit-oid>:scripts/heldout_studies/selection-<sha256>.json`. The evaluator
accepts a full 40- or 64-hex Git object ID and a safe repository-relative path. It
proves artifact order from Git topology: the selection commit is a strict
ancestor of current `HEAD`, the label path is absent from the selection commit,
the selection bytes exactly match that earlier blob, and the final label bytes
are tracked exactly at current `HEAD`. Commit timestamps and adjudication
timestamps remain audit metadata rather than ordering evidence.

Both tracked JSON artifacts use one exact encoding: UTF-8, sorted keys,
two-space indentation, unescaped Unicode, and one trailing newline. The Git
proof clears caller-supplied `GIT_*` controls, disables system/global config and
replacement objects, binds every command to the discovered worktree and Git
directory, and rejects shallow repositories or object alternates. This keeps
namespace, index, config, shallow-file, object-directory, and alternate-object
environment overrides outside the proof boundary.

## 3. Conduct the independent audit

Give each reviewer a separate copy of the generated null-label packet and the
repository/advisory evidence needed to determine causality. Collect each completed
copy without showing either reviewer the other copy, then merge the two reviews
into the final schema-3 label artifact. Keep the sealed selection's prediction
fields, lane membership, and aggregate detector scores hidden until every review
and disagreement resolution is complete.

Every selected alias class requires `primary_review` and `secondary_review`.
Each review independently records:

- a reviewer ID distinct after whitespace trimming and Unicode case folding
- the conclusive label `AI_CAUSAL` or `NOT_AI_CAUSAL`
- a timezone-qualified review timestamp
- one or more evidence references
- a nonempty causal rationale

Agreeing reviews require `resolution.status: "agreed"` and an exact matching
`resolved_label`; resolver metadata stays null/empty. Disagreeing reviews require
`resolution.status: "resolved"`, a third resolver ID distinct from both reviewers,
a timezone-qualified resolution timestamp at or after both reviews, one or more
resolution evidence references, and a nonempty resolution rationale. The final
`resolved_label` drives both metrics. `INCONCLUSIVE` is rejected at the formal
label-schema boundary.

The exact schema-3 audit protocol requires all independence, review blinding,
score blinding, and completed-resolution attestations to be `true`. Reviewers
attest that they are independent from detector development and from one another,
and that neither review had access to the other review. The schema mechanically
rejects prediction, lane, or score fields in each adjudication and the generated
null packet omits them. The immutable selection commit reference remains
mandatory.

Human reviewers create every review through repository-level inspection of each
null template entry. Commit the completed label file in a later commit:

```bash
cp .ai-slop/state/data-refresh/heldout-v1/labels-<sha256>.json \
  scripts/heldout_studies/
git add scripts/heldout_studies/labels-<sha256>.json
git commit -m "Preserve independent held-out adjudications" \
  -m $'Confidence: high\nScope-risk: narrow\nTested: complete held-out label schema'
```

A missing review, unresolved disagreement, unresolved campaign result, or
infrastructure result fails closed.

`scripts/fixtures/heldout-quality-labels.template.json` documents the strict
schema. Prefer the generated template because it contains the exact selected IDs,
aliases, and selection digest while withholding lane memberships, detector
predictions, prediction reasons, and aggregate quality scores.

## 4. Evaluate point quality and confidence bounds

```bash
uv run --project cve-analyzer python scripts/heldout_quality_gate.py evaluate \
  --selection scripts/heldout_studies/selection-<sha256>.json \
  --labels scripts/heldout_studies/labels-<sha256>.json \
  --precision-target 0.95 \
  --recall-target 0.95 \
  --output .ai-slop/state/data-refresh/heldout-quality-current.json
```

The standalone evaluator requires complete evidence and point precision/recall
of at least 0.95 by default. Add `--require-certified` to require both one-sided
95% exact Clopper-Pearson lower bounds to reach 0.95 as well. Formal Web
generation always evaluates the sealed selection and labels in process with
certification required. Formal mode is certification-only.

A perfect sample needs at least 59 trials for its one-sided 95% lower bound to
exceed 0.95. Recall certification needs at least 59 independently labeled actual
positive trials, so the recall sample often needs to be much larger than 59.
Sample sizes are fixed in the pre-label selection and cannot be expanded after
seeing outcomes without creating and precommitting a new study.

The report preserves separate denominators for selected trials, conclusive
precision trials, actual-positive recall trials, infrastructure errors,
unresolved results, and cross-lane overlap. Its legacy `inconclusive` stratum is
always zero for valid schema-3 formal evidence. Exit status 0 means the requested
point/certified gate passed, 1 means valid evidence missed the target, and 2 means
the evidence contract failed closed.

## 5. Formal release evidence and activation

The schema-5 release-evidence validator runs the same strict schema-3 dual-review validator
and recomputes the held-out metrics from every archived `resolved_label`. A
correlated rewrite of review or resolution fields therefore requires resealing
all bound artifacts and still cannot bypass the dual-review invariants. The
validator independently enforces the 95% target floor, complete incremental
campaign proof, the `gpt-5.6-luna` / `max` contract, and campaign agreement
between selection and report. The evidence bundle streams every raw campaign
result into a bounded `campaign-results/` directory and archives the exact alias
classes plus protected-input bytes used by selection. Validation rebuilds every
alias unit and prediction from those raw results, re-extracts and alias-expands
the protected IDs, and reruns the domain-separated top-k selector. The archived
selection must match that full-population replay byte-for-byte. Changing only a
campaign manifest hash, population count, alias class, protected input, selected
row, or raw result therefore fails closed. The validator also recomputes the
canonical label blob hash recorded by the artifact-order proof.

Formal generation also requires `--recall-selection`, `--recall-labels`, and
`--recall-report`. It rebuilds the authoritative protected inventory, replays
the sealed recall selection from the exact published detector `inventory_id`,
reruns independent-label resolution with Git artifact ordering, and requires the
supplied report to match the recomputation byte-for-byte. A schema-4 release
receipt binds all three artifact hashes, the inventory ID, selection digest,
protected-census digest and overlap count, `complete_end_to_end` status, recall
point, and interval. The schema-5 archive
stores `recall-selection.json`, `recall-labels.json`, and `recall-report.json` as
required artifacts. Missing, `UNKNOWN`, unresolved, coverage-failure,
incomplete-census, null-recall, tampered, or correlated-resealed evidence
blocks receipt creation and publication.

Formal release additionally requires both the end-to-end recall point estimate
and the lower endpoint of its family-wise 95% interval to meet the receipt's
recall target. A point estimate alone cannot certify publication.

Detector inventory `generated_at` comes from the canonical UTC
`source_remote_cutoff.checked_at_utc`, so its content identity can be built and
sealed before recall labels exist. Publication `generated_at` remains the actual
release generation time.

The current authoritative protected roots contain prior held-out study IDs from
the same formal campaign. A new schema-4 selection places those overlaps only in
the separately sealed census and keeps them out of random sampling. Publication
remains blocked until schema-3 labels resolve every census packet conclusively;
then their exact finite-population contribution is combined with the unprotected
Horvitz-Thompson estimate. The covered-unprotected diagnostic remains
non-publishable on its own.

Reviewer and resolver IDs plus the blinding attestations are exact signed audit
claims. This repository mechanically enforces their presence, normalized
distinctness, exact `true` attestations, blind packet structure, and artifact
binding. Authenticating that those IDs correspond to independent people and
that the reviewers' evidence environment withheld predictions, lanes, peer
reviews, and aggregate scores remains inside the CI identity, code-review, and
signed-audit boundary.

Artifact ordering is proven against the safe, non-shallow Git object store when
the held-out report is generated. The evidence archive binds that proof and the
exact selection/label bytes; it does not embed the commit/tree ancestry objects.
Replaying ancestry after moving the archive therefore requires the bound
repository object store. The verifier supplies the trusted repository root from
its installed code location (or an explicit isolated-test authority); bundle
bytes cannot redirect verification to an alternate Git repository. The labels
commit must also equal that repository's current `HEAD`.
`scripts/verify_formal_release.py --require-active --require-inventory`
performs that replay and rejects missing commit objects, broken ancestry,
pre-existing labels, or committed selection/label byte drift. A coordinated
rewrite of repository history and all release artifacts remains inside the
Git/CI signing boundary.

Publication uses an exchange transaction under the publication-parent lock. The
prior generation stays at the candidate recovery path while post-promotion
inputs, live index/entries/stats/receipt, bundle hash, and manifest hash are
rechecked and the activation record becomes durable. A failed postcheck or
activation exchanges the prior generation back before releasing the lock. A
pending activation binds canonical output/recovery paths, candidate and previous
directory inodes, generation ID, evidence bundle, receipt, publication bundle,
and publication manifest. Crash reconciliation reacquires the same exclusive
lock, rereads and rehashes the live generation, and activates only when the
bound candidate inode is truly live; a pre-exchange or substituted candidate
remains pending.
