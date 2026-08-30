# Round11 completion-audit contract

Scope is the 111 rows in `../manifest.jsonl` whose `primary_out` did not exist
when this lane was opened. The frozen manifest is authoritative; do not
re-freeze or substitute cases.

Each worker is assigned to one fresh, clean-context subagent. That subagent may
read only `docs/AUDIT-PROTOCOL.md`, its exact manifest row, its exact bundle,
its advisory sources, and its clone. It must not read another case, the frozen
report, roster verdicts, or independent-review results.

The subagent independently establishes vulnerability semantics, the atomic
introducer and its parent, squash/member history, affected and fixed release
boundaries, the direct fix or an explicit unpatched state, and AI evidence on
the BIC only. Missing evidence is recorded as a gap; it is never inferred.

Output is the manifest row's exact `primary_out` path. Top-level keys, in order:

`class_id`, `case_id`, `repo`, `advisory_ids`, `bug_semantics`, `flaw_origin`,
`introducer_sha`, `introducer_parent`, `introducer_parent_absent`,
`squash_decomposed`, `decomposed_shas`, `ai_marker`, `verdict`, `fix_sha`,
`direct_fix_sha`, `evidence`, `reasoning`, `remaining_gap`.

Only `unpatched` may be added. Full commit fields are 40-hex SHA or `null`.
Before completion, parse the file with `json.loads` and run the repository's
record gate for that single record. Do not edit the ledger, report, roster,
manifest, bundles, clone, or any other case output.
