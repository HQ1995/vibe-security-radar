# Independent 389-case review

Scope is every row in `../manifest.jsonl` whose `primary_out` exists in the
frozen 389-record snapshot. Each `wXXX.json` is written by one fresh subagent
that reviews only that worker's bundle, primary record, advisory, and clone.

Required result keys, in order:

`worker`, `review_agent_id`, `class_id`, `case_id`, `repo`, `primary_verdict`,
`review_verdict`, `protocol_checks`, `findings`, `corrected_fields`,
`remaining_gap`.

`review_verdict` is one of `CONFIRMED`, `CORRECTION_REQUIRED`,
`EVIDENCE_GAP`, or `BLOCKED`. `protocol_checks` must explicitly cover the
vulnerability mechanism, atomic BIC, immediate-parent absence, squash/member
decomposition, affected and fixed release membership, direct fix or verified
unpatched state, and BIC-only AI attribution. A result is not complete merely
because `scripts/audit_record_gates.py` passes.

Workers may write only their assigned result file. They must not read another
case bundle, primary record, or review result, and must not modify the ledger,
report, clone, manifest, website, or existing primary records.
