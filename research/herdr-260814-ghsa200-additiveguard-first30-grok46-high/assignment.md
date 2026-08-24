Assignment for additive-guard first30 mining packet

Input: origin20 scan-miss.jsonl in original file order. Keep rows whose notes contain no_source_deleted and contain no diff_fail. Identities unique.
Snapshot: canonical84 (strict 84, commit ca034f064fd696201c81baae7392c14f0d501d2b) plus explicit terminal/current selected.jsonl and cases.jsonl adjudications.
Assign the first 30 genuinely unassigned rows. No padding. No backfill after freeze.
Conservation: raw pool 381; excluded/already-covered 285; eligible 96; assigned 30; eligible leftover 66; raw outside assignment 351. Equations: 381=285+96; 96=30+66; 381=30+351. This packet does not exhaust the leftover 66 or the 351 outside assignment.
These fixes are additive guards. Absence of deleted lines is not a negative.
This is a mining/selection packet. A bounded-heuristic miss is not a causal REJECT.
