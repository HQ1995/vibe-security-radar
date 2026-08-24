# Fix-blame diff_fail20: 20 REJECT, 0 PASS proposals

Verdict first: 0 PASS proposals, 20 REJECT. Assigned 20, reviewed 20, unreviewed 0. Conservation 20=20+0. Worker PASS is proposal only; this packet emits none. Start count is not rebuilt. Current leader-accepted count 82 (canonical82, commit 6800d212, ledger hash 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23). Packet delta 0. Publication and greater-than-200 stay HOLD. This packet does not rebuild canonical82.

## Method

This is not another direct-root rank-queue pass. Frozen selection used origin20 scan-miss.jsonl (the task named scan.jsonl; that path does not exist). Original scan order is miss-file as_completed order. A row qualifies when notes are prefixed diff_fail:. First 20 unique GHSA IDs after excluding canonical82 strict IDs, origin20 selected14, residual-security20 selected20, leftover4, route-surface selected IDs, and pending GHSA-425G plus GHSA-HC8V. Cap 20. No padding. selected.jsonl sha256 1116efd21db9461f60d0aac1831f55b3ad75f33f1c81834ba75e85cf6bacacfa was frozen before deep review.

Repair used existing read-only clones. Promisor blob:none clones lack blobs. Object stores were unioned through GIT_ALTERNATE_OBJECT_DIRECTORIES, including cve-analyzer checkouts that already held blobs. No remotes were fetched. Rename-following blame of deleted source hunks was then rerun with the origin20 method. OSV introduced, routing, AI fix authorship, commit-message similarity, shared SHA, and carrier trailers are not causality.

## Repair result

All 20 diffs repaired. Hits 0. no_ai_blame_on_deleted_hunks 20. Still-fail 0.

## REJECT (20)

| Order | ID | Class | Why |
| --- | --- | --- | --- |
| 1 | GHSA-JJ2R-455P-5GVF | no AI blame | PermFile 0644 to 0640; squash member, not two-parent carrier |
| 2 | GHSA-3Q2W-42MV-CPH4 | no AI blame | command spawn allowlist; shared SHA with W7QC stays distinct |
| 3 | GHSA-CM2R-RG7R-P7GG | no AI blame | password handling |
| 4 | GHSA-WJ44-9VCG-WJQ7 | no source deleted | additive isRepositoryGitPath guards only |
| 5 | GHSA-4WX8-5GM2-2J97 | no AI blame | markdown preview XSS; single-parent squash |
| 6 | GHSA-RMWH-G367-MJ4X | no AI blame | auth token removed from /api/command |
| 7 | GHSA-W7QC-6GRJ-W7R8 | no AI blame | same closer as 3Q2W; distinct identity |
| 8 | GHSA-PF4H-VRV6-CMVR | merge carrier | two parents; no AI member hunk |
| 9 | GHSA-57JG-M997-CX3Q | no source deleted | docs/admin/optionals.rst only |
| 10 | GHSA-WCWH-7GFW-5WRR | no AI blame | trailer parser; empty AI index |
| 11 | GHSA-4QQF-9M5C-W2C5 | no AI blame | IP in notification mail |
| 12 | GHSA-M49C-G9WR-HV6V | merge carrier | two parents; first-parent no deleted source |
| 13 | GHSA-377J-WJ38-4728 | no AI blame | 2FA session expiry |
| 14 | GHSA-WQ2J-W9PM-7X2P | no AI blame | theme query override |
| 15 | GHSA-867C-P784-5Q6G | no AI blame | attached filename hint |
| 16 | GHSA-2374-6CVW-QMX6 | no source deleted | CKEditor .dnn manifest only |
| 17 | GHSA-WPP4-VQFQ-V4HP | no AI blame | CLAHE underflow |
| 18 | GHSA-2CJV-6WG9-F4F3 | no AI blame | 72-byte password max |
| 19 | GHSA-2V5M-CQ9W-FC33 | merge carrier | two parents; no AI member hunk |
| 20 | GHSA-495J-H493-42Q2 | no AI blame | parms.lookup removal |

Three rows are two-parent merge carriers (PF4H, M49C, 2V5M). Authorship is not transferred from member to carrier. Four rows have no deleted source hunks (WJ44, 57JG, M49C, 2374). No row has a live AI marker on the closer. Incomplete-remediation patch-delta is N/A: no AI-authored security boundary was amended.

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 82. Only leader-reviewed rows with all seven gates PASS enter that bound after independent hostile red-team. This packet does not rebuild canonical82 and does not support a greater-than-200 claim.
