Assignment for additive-guard next30 mining packet

Input: origin20 scan-miss.jsonl in original file order. Keep rows whose notes contain no_source_deleted and contain no diff_fail. Identities unique.
Snapshot: canonical84 (strict 84, commit ca034f064fd696201c81baae7392c14f0d501d2b) plus explicit terminal/current selected.jsonl and cases.jsonl adjudications, and explicitly exclude all 30 additiveguard-first30 mining IDs even though NOT_SELECTED.
Assign the next 30 genuinely unassigned rows from the leftover 66. No padding. No backfill after freeze.
Conservation: raw pool 381; excluded/already-covered 315; eligible 66; assigned 30; eligible leftover 36; raw outside assignment 351. Equations: 381=315+66; 66=30+36; 381=30+351. This packet does not exhaust the leftover 36 or the 351 outside assignment.
These fixes are additive guards. Absence of deleted lines is not a negative.
This is a mining/selection packet. A bounded-heuristic miss is not a causal REJECT. Fetch/history failure is BLOCKED, never causal REJECT.
