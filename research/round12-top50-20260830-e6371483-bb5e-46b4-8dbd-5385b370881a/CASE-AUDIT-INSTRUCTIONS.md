# Clean-context case audit instructions

Audit exactly one assigned case under `docs/AUDIT-PROTOCOL.md`. Vulnerability
first, AI second. The bundle is the only case-specific starting context.

## Isolation and ownership

- Read the protocol, this file, your assigned bundle, the assigned source clone,
  and primary first-party sources only.
- Do not read the canonical ledger, another bundle/output, prior round reports,
  or a prior verdict. `same_repository_prior_hits` in the bundle are leads only.
- Do not edit the ledger, shared scripts, clone worktree, or any file except your
  assigned `primary/wNNN.json`.
- Every shell command must run through
  `numactl --cpunodebind=1 --membind=1`.
- You are not alone in the repository. Never revert or overwrite another worker.

## Required method

1. Confirm the advisory identity and disposition from CVE.org plus the vendor's
   first-party advisory/source. GitHub `withdrawn_at` alone is not authoritative.
2. Establish the exact source-to-sink mechanism and affected release boundary.
3. Find the smallest commit that first wrote the vulnerable lines. Reject moves,
   refactors, reverts, fixes, carriers, and squash aggregates when finer public
   members exist. Verify the immediate parent tree directly.
4. Verify affected/fixed release membership and the direct fix hunk, or provide
   the exact unpatched record required by `docs/DATA-SCHEMA.md`.
5. Judge AI only from the BIC commit object. Repository-level AI activity, PR
   labels, later fixes, and changelogs are not causal AI proof. Missing trailers
   alone do not establish named-human `NOT_AI` for anonymous/aggregate history.
6. Start Git inspection with `GIT_NO_LAZY_FETCH=1`. A promisor clone may lack
   old objects. A bounded fetch is allowed; if required history remains missing,
   emit `EVIDENCE_GAP` or `BLOCKED` with a concrete `remaining_gap`.

Allowed verdicts: `AI_ROOT_CAUSE`, `AI_CODE_FLAWED`, `NOT_AI`,
`FALSE_POSITIVE`, `EVIDENCE_GAP`, `BLOCKED`.

## Output contract

Write one JSON object with these fields and stable types:

```json
{
  "schema_version": "independent-case-audit/v1",
  "worker": "w000",
  "review_agent_id": "unique task id from the assignment",
  "class_id": "exact bundle value",
  "case_id": "official GHSA or CVE",
  "repo": "exact bundle value",
  "advisory_ids": ["exact bundle values"],
  "input_binding": {
    "bundle_sha256": "64 lowercase hex from assignment",
    "clone_head_sha": "40 lowercase hex from bundle"
  },
  "verdict": "one allowed verdict",
  "protocol_checks": {
    "vulnerability_mechanism": {"status": "PASS|GAP|N/A", "evidence": ["exact facts/sources"]},
    "atomic_bic": {"status": "PASS|GAP|N/A", "evidence": ["exact facts/commands"]},
    "immediate_parent_absence": {"status": "PASS|GAP|N/A", "evidence": ["exact facts/commands"]},
    "squash_member_decomposition": {"status": "PASS|GAP|N/A", "evidence": ["exact facts/commands"]},
    "affected_release_membership": {"status": "PASS|GAP|N/A", "evidence": ["exact facts/commands"]},
    "fixed_release_membership": {"status": "PASS|GAP|N/A", "evidence": ["exact facts/commands"]},
    "direct_fix_or_unpatched": {"status": "PASS|GAP|N/A", "evidence": ["exact facts/commands"]},
    "bic_only_ai_attribution": {"status": "PASS|GAP|N/A", "evidence": ["exact BIC-local facts"]}
  },
  "bug_semantics": "source-to-sink explanation",
  "flaw_origin": "smallest first-writer explanation",
  "introducer_sha": "40 lowercase hex or null",
  "introducer_parent": "40 lowercase hex or null",
  "introducer_parent_absent": true,
  "squash_decomposed": false,
  "decomposed_shas": [],
  "fix_sha": "40 lowercase hex or null",
  "direct_fix_sha": "40 lowercase hex or null",
  "unpatched": null,
  "ai_marker": {"state": "PRESENT|ABSENT|UNKNOWN", "evidence": ["BIC-local evidence"]},
  "evidence": ["primary-source and exact Git evidence"],
  "reasoning": "why the gates imply the verdict",
  "remaining_gap": null
}
```

All non-null Git SHAs must be full lowercase 40-hex and exist as commit objects
in the assigned clone. `decomposed_shas` is always a list. `evidence` is always a
list of nonempty strings. `ai_marker` is always the shown object shape.

Closed `AI_ROOT_CAUSE`, `AI_CODE_FLAWED`, and `NOT_AI` require all eight protocol
checks `PASS`. `FALSE_POSITIVE` may use `N/A` for Git lifecycle checks only after
the vulnerability check records authoritative rejected/withdrawn or
mechanism-nonexistent evidence. `EVIDENCE_GAP` and `BLOCKED` require at least one
`GAP` and a nonempty, actionable `remaining_gap`.

For an unpatched closed result, `unpatched` must be:

```json
{"confirmed": true, "reason": "...", "potential_fix": {"approach": "...", "rationale": "...", "reference_commit": null, "reference_url": null}}
```

After writing, run `jq empty` and
`python3 scripts/audit_record_gates.py --stdin < primary/wNNN.json` under the
required NUMA binding. Report only the output path, verdict, and validation result.
