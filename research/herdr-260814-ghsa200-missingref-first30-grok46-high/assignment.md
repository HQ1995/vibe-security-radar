Assignment for missing-ref first30 mining packet

Input: origin20 scan-miss.jsonl in original file order. Keep unique rows whose notes contain missing_ref and contain neither diff_fail nor no_source_deleted.
Snapshot: canonical84 (strict 84, commit ca034f064fd696201c81baae7392c14f0d501d2b) plus explicit terminal/current selected.jsonl and cases.jsonl adjudications.
Assign the first 30 genuinely unassigned rows. No padding. No backfill after freeze.
The missing_ref note prefix is routing only. Resolve the exact full first-party fix SHA from advisory references and PRs.
Conservation: raw pool 141; excluded/already-covered 98; eligible 43; assigned 30; eligible leftover 13; raw outside assignment 111. Equations: 141=98+43; 43=30+13; 141=30+111. This packet does not exhaust the leftover 13 or the 111 outside assignment.
If source lines are deleted or replaced, blame them. If the fix is additive, trace the protected parent sink, route, or context. Absence of deleted lines is not a negative.
This is a mining/selection packet. A bounded-heuristic miss is not a causal REJECT. Fetch, history, or evidence failure is BLOCKED, not causal REJECT.
