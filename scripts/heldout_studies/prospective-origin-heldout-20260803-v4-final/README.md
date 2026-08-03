# Prospective origin held-out v4 — final package

## Result

The old observed-AI-only admission rule failed the recall-first objective: it
kept 550 of 45,133 local pre-fix ancestor pairs and silently removed the other
44,583 before candidate conservation was measured.

The repaired workflow retains all 45,133 local ancestor pairs, recursively adds
5,729 recoverable squash-member edges, and freezes a finite schedule of 26,057
candidate units carrying 50,862 exact fix edges. This is a construction-level
guarantee inside the frozen local-history boundary, not a zero-population-miss
claim.

The association-only held-out resolved 3 of 12 selected cases. Independent
causal review found no confirmed observed-AI causal case in those three, so
conditional AI-origin recall and precision are not estimable from this split.
The 14 consensus causal-history edges used in the repair replay are post-hoc
mechanism controls, not AI-causality ground truth.

Canonical result: [`result.json`](result.json).

## Frozen evidence

- `causal_reconciliation.json`: independent review reconciliation and the
  zero-positive denominator.
- `top10_edge_ledger.json`: all 34 old top-10 exact edges, each adjudicated
  noncausal.
- `consensus_causal_history_controls.json`: post-review repair controls.
- `repair_consensus_edge_ledger.json`: exact-edge ledger for the repair replay.
- `result.json`: claim boundaries, workload, cost projection, statistics, and
  source hashes.

The full pre-repair and repair scorecards are generated artifacts (25.7 MB
combined), so they are deliberately omitted from Git. `result.json` retains
their aggregate values and hashes; the commands below regenerate the final
scorecard for byte-level comparison.

## Reproduce the repaired replay

The commands below start from the already frozen fix manifest, structural
inventory, AI scan, and local repository clones. Set the cache path to the clone
root on the replay machine.

```bash
export RECALL_REPO_CACHE=/home/hanqing/.cache/cve-analyzer/repos

cve-analyzer/.venv/bin/python scripts/cohort_origin_candidate_reduce.py generate \
  --fix-manifest scripts/heldout_studies/prospective-origin-heldout-20260803-v4-root-result/fix_manifest.json \
  --structural-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-structural-20260803-final-v1 \
  --ai-scan-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-ai-scan-all-history-20260803-v1 \
  --repository-path github.com/azure/azure-sdk-for-python="$RECALL_REPO_CACHE/azure_azure-sdk-for-python" \
  --repository-path github.com/benbjohnson/litestream="$RECALL_REPO_CACHE/benbjohnson_litestream" \
  --repository-path github.com/eigent-ai/eigent="$RECALL_REPO_CACHE/eigent-ai_eigent" \
  --output-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-reduction-replay

cve-analyzer/.venv/bin/python scripts/cohort_origin_squash_expand.py \
  --generated-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-reduction-replay \
  --max-squash-depth 7 \
  --output-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-squash-replay

cve-analyzer/.venv/bin/python scripts/cohort_origin_packetize.py \
  --generated-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-squash-replay \
  --max-candidates 8 \
  --output-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-packets-replay

cve-analyzer/.venv/bin/python scripts/cohort_candidate_unit_scorecard.py generate \
  --packets-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-packets-replay \
  --output-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-schedule-replay \
  --budget 1 --budget 5 --budget 10 --budget 25 --budget 50 \
  --budget 100 --budget 200 --budget 500 --budget 1000 \
  --budget 5000 --budget 25000 --budget 50000

cve-analyzer/.venv/bin/python scripts/cohort_candidate_unit_scorecard.py evaluate \
  --generated-dir .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-all-ancestry-schedule-replay \
  --ledger scripts/heldout_studies/prospective-origin-heldout-20260803-v4-final/repair_consensus_edge_ledger.json \
  --output .ai-slop/state/cohort-v1/prospective-origin-heldout-v4-repair-scorecard-replay.json
```

Expected content digests:

```text
reduction candidate_rows_sha256  fca0c6bd4a664d766899c18c29015db6594c96a51c0804e240e610d5d40556c9
squash candidate_rows_sha256     243d4b9f0f8be4aa03355d675dfc163f32c19da34903a678a43123c83b1c4d39
schedule rows sha256              a6f55167c05000942b9f94458bb196c9278e54807de7608c49a0e4dec584c890
schedule file sha256              709c24b870d9c34387e985d7d3bf25c9f3c4c2c1b66964cc0fdd3e0f46400f2c
```

Public pull refs are a live external dependency. If a ref becomes unavailable,
the expansion must retain its landed squash as `BLOCKED`; it must not delete the
carrier or silently reproduce a smaller scope.

## Claim-grade next gate

Precommit a fresh split seeded from observable AI commits or pull requests,
follow it forward to later fixes or advisories, and independently adjudicate
causality before opening ranks. With zero misses, 59 independent positive cases
are required for a one-sided 95% lower recall bound of at least 0.95; 299 are
required for at least 0.99.
