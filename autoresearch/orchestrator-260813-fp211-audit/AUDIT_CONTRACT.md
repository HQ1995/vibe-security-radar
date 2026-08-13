# Canonical 211 false-positive audit contract

Pinned input:

- repository commit: `cd97a295956a8d3d46330bf9b0300ddded21f737`
- canonical ledger: `autoresearch/orchestrator-260812-posthold-canonical/ledger.jsonl`
- audit manifest: `autoresearch/orchestrator-260813-fp211-audit/manifest.jsonl`
- population: exactly 211 canonical `COMPONENT_ROW` records

## Objective

Independently falsify every current case. The current row state, prior reports, OSV `introduced`, commit references, ancestry intersections, and model votes are hypotheses or routing evidence, never proof.

## Required gates per row

1. **Identity:** verify the first-party GHSA/CVE object and whether all public IDs belong to this exact mechanism. Preserve missing/404 and polluted alias evidence.
2. **Relevant-hunk AI provenance:** prove that the candidate hunk which creates or incompletely remediates the boundary is AI-authored. A PR-level label, carrier trailer, author email, or unrelated AI hunk is insufficient.
3. **Topology:** distinguish atomic commit, merge/squash carrier, PR member, backport, and later refactor. A carrier is not automatically the origin member.
4. **But-for causality:** inspect parent, candidate, and vulnerable release. Removing the candidate must remove the mechanism or a distinct new surface/contribution. Old-bug-preserving refactors and risk-reducing incomplete hardening are false positives. For `AI_INCOMPLETE_REMEDIATION`, the AI change must explicitly attempt the same security boundary and leave the advisory residual; merely preceding the vulnerability is insufficient.
5. **Minimum fix reversal:** prove that the selected fix or minimum fix set closes the same source/sink/invariant. A remediation-only, sibling, multi-purpose, or insufficient fix edge fails.
6. **Release containment:** for released claims, prove candidate/carrier present in a vulnerable artifact and minimum fix absent, then fix present in a fixed artifact. Commit-only rows must remain separate.
7. **Uniqueness:** check formal aliases and same-mechanism duplicates against all 211 rows. Same repository or same fix alone does not merge distinct mechanisms; cross-repository copies may still be duplicates if source/sink/invariant are materially identical.

## Verdicts

- `CONFIRM`: all required gates for the row's claimed scope close.
- `NARROW`: a real AI-causal mechanism closes, but identity, scope, topology, fix-set, or release wording must be narrowed.
- `FALSE_POSITIVE`: a decisive causal, attribution, fix-reversal, release, or duplicate counterexample defeats the counted row.
- `UNKNOWN`: evidence is missing or contradictory; do not infer PASS from absence of a counterexample.
- `BLOCKED`: a named external/local prerequisite is unavailable and no safe alternative closes it.

Confidence is `HIGH`, `MEDIUM`, or `LOW`. Only `CONFIRM/HIGH` may become a final confirmed case without another review.

## JSONL row schema

Each assigned ordinal produces exactly one compact JSON object with these fields:

```json
{
  "schema_version": 1,
  "ordinal": 1,
  "row_key": "...",
  "baseline_state": "PASS",
  "verdict": "CONFIRM",
  "confidence": "HIGH",
  "causal_class": "AI_DIRECT_ROOT",
  "false_positive_class": null,
  "identity_gate": "PASS",
  "ai_hunk_gate": "PASS",
  "topology_gate": "PASS",
  "but_for_gate": "PASS",
  "fix_reversal_gate": "PASS",
  "release_gate": "PASS",
  "uniqueness_gate": "PASS",
  "candidate_set": ["40-char sha"],
  "carrier_set": [],
  "minimum_fix_set": ["40-char sha"],
  "public_ids_keep": ["GHSA-...."],
  "public_ids_remove": [],
  "duplicate_of": null,
  "decisive_evidence": ["primary-source path/URL plus exact locator or replay command"],
  "counterevidence": [],
  "replay_commands": ["read-only command"],
  "experience_tags": ["old_bug_preserving_refactor"],
  "lesson": "short reusable adjudication lesson"
}
```

Gate values are `PASS`, `FAIL`, `NARROW`, `UNKNOWN`, `BLOCKED`, or `NA`. Use full 40-character lowercase SHAs. Do not copy secrets, tokens, entire advisory bodies, or large raw responses into outputs.

## Worker deliverables and ownership

Each worker owns only its assigned files:

- `shards/shard-NN.jsonl`
- `reports/shard-NN.md`

The report must state exact ordinal coverage, verdict counts, every false-positive/narrow counterexample, primary-source citations, replay commands, limitations, and a reusable-experience section. Workers are not alone in the checkout: do not edit canonical files, other shards, code, manifests, caches, or unrelated dirty files; do not commit. Put temporary clones and raw API pages under `/tmp/fp211-shard-NN/`.

## Stop/claim boundary

Mechanical 211/211 coverage is not proof that all rows are correct. Final acceptance also requires schema/conservation verification, conflict adjudication, independent review of every non-`CONFIRM/HIGH` row, and a rebuilt canonical HOLD ledger. Never turn routing or a green parser into causality.
