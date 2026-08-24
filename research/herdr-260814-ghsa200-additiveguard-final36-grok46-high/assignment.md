Assignment for additive-guard final36 mining packet

Input: origin20 scan-miss.jsonl in original file order. Keep rows whose notes contain no_source_deleted and contain no diff_fail. Identities unique.
Snapshot: canonical84 (strict 84, commit ca034f064fd696201c81baae7392c14f0d501d2b) plus explicit terminal/current selected.jsonl and cases.jsonl adjudications, and explicitly exclude all 60 additiveguard-first30 and additiveguard-next30 mining IDs regardless of NOT_SELECTED or BLOCKED.
Assign all 36 remaining genuinely unassigned rows. No padding. No backfill after freeze.
Conservation: raw pool 381; excluded/already-covered 345; eligible 36; assigned 36; eligible leftover 0 (exhausted); raw outside assignment 345. Accepted prior accounting: 381=315+66 before next30; 66=30+36 next30 leaving final36. This packet: 381=345+36; 36=36+0; 381=36+345. Eligible is exhausted after 36. No further additive slice.
These fixes are additive guards. Absence of deleted lines is not a negative.
This is a mining/selection packet. A bounded-heuristic miss is not a causal REJECT. Fetch/history failure is BLOCKED, never causal REJECT.
