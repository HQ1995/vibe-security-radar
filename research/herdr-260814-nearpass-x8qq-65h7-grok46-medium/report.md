# Hostile review: GHSA-X8QQ-M4QC-RPJ5 and GHSA-65H7-C7C4-MGHX

**NARROW + NARROW.** Countable PASS remains 0. Packet delta 0. Canonical94 stays **94 HOLD**.

Independent hostile seven-gate replay of two near-pass mechanisms. nearpass-next10 is routing only. Prior NARROW labels are not proof. Worker PASS is proposal only; this packet emits none. Exact seven PASS is required for PASS_PROPOSAL. Did not pad.

Conservation: assigned=2, reviewed=2, unreviewed=0. Equation `2=2+0`.

Network evidence used anonymous public git, GitHub HTML, advisory-database raw JSON, and PyPI only. Credential-bearing environment variables are unset before network commands and are never printed. Anonymous failure is BLOCKED; credentials are not used as a fallback.

## A. GHSA-X8QQ-M4QC-RPJ5 NARROW

Alias CVE-2026-59237. Repository Roskus/prospero-flow-crm. Candidate set `56ea64c8` and `86f40651`. Empty carrier. Closer `9a859c4d`.

identity_gate: NARROW. Unreviewed advisory-database JSON sha256 `309f08e3ff27f20eb12e2fc378fe8a34ab89041cedaee91b842ae565e1c85624` has `github_reviewed=false` and `affected=[]`. Global GitHub advisory page is labeled Unreviewed. Repository advisory HTTP 404. github-reviewed path HTTP 404. Details name Roskus Prospero Flow CRM and `Order::find($id)` / `Item::find($id)`, but that is not a reviewed first-party repo GHSA.

topology_gate: PASS. Both candidates are single-parent. `56ea64c8` is an ancestor of `86f40651` and of closer `9a859c4d`. No carrier. No authorship transfer.

ai_hunk_gate: PASS. Both commits carry `Co-Authored-By: Claude Haiku 4.5`. `56ea64c8` first-parent-creates OrderRead blob `c3082407` and OrderUpdate blob `0da633ba` with unscoped `Order::find($id)`. `86f40651` first-parent-creates OrderItem read/update/delete with `Item::find($id)`. Parent `260a0fe3` has no those API Order read/update files.

but_for_gate: PASS. Removing the two candidates removes the advisory-named unscoped GET/PUT order and GET/PUT/DELETE order-item paths. Pre-existing `OrderDeleteController` already scopes `company_id`.

fix_reversal_gate: PASS. Atomic closer `9a859c4d` parent `66646511` still has `Order::with('items')->find($id)` and `Item::find($id)`. The closer adds `where('company_id', Auth::user()->company_id)` and `whereHas('order', ...)`. No AI trailer on the closer.

release_gate: NARROW. GitHub Release and tag `v4.6.0` (`4c15d20a`) exist and lack the API OrderRead/Item files. First containing tag of both candidates and of the closer is `v5.5.3` (`584f3158`). At `v5.5.3`, OrderRead blob `d2e097de` and OrderItemRead blob `f3b308b3` equal the closer. Same-first-tag. Packagist HTTP 404. No vulnerable released artifact contains the AI members without the closer.

uniqueness_gate: PASS. Absent from canonical94 strict 94. Distinct from GHSA-4FXP. Alias is not a second case.

seven_gates_exact_pass is false. Verdict NARROW.

## B. GHSA-65H7-C7C4-MGHX NARROW

Alias CVE-2026-2393. Repository mlflow/mlflow. Candidate/carrier `3094ab60`. Closer `64aa0ab7`.

identity_gate: PASS. github-reviewed advisory-database JSON sha256 `82b1200e2e8ee1a93629751cbdd9c6a32cae0852129df149b55b06519d10cc85` names PyPI `mlflow`, CWE-918, alias CVE-2026-2393, withdrawn null. Global GitHub advisory page is Reviewed. Repository advisory HTTP 404 is not required once the reviewed GHSA object names the package.

topology_gate: PASS. Squash `3094ab60` is single-parent onto `4a724add`. It is the assigned candidate and the assigned carrier. PR #16583 members are not authorship. Closer `64aa0ab7` is single-parent onto `24dcf3f8`. Backport `fec1670e` on the v3.10.0 line is the same PR #20747 subject with equal delivery blob `2d7c7c88` and is not origin.

ai_hunk_gate: NARROW. The squash has an explicit Claude co-author trailer and creates `delivery.py` with `session.post(webhook.url)` plus scheme-only `_validate_webhook_url`. A 41-file human-authored GitHub squash does not bind that hunk to Claude. Prefer no PASS. Do not transfer later Claude-marked PR members onto the squash. File-add of `delivery.py` on the PR head (`195461a3`) has no Claude trailer.

but_for_gate: PASS. Parent `4a724add` has no `delivery.py` and no `_validate_webhook_url`. Removing `3094ab60` removes the webhook POST surface.

fix_reversal_gate: PASS. Closer `64aa0ab7` (no AI trailer) amends `_validate_webhook_url` with hostname resolution and `ip.is_global`, and calls it from `_send_webhook_request`. That reverses private-IP / metadata SSRF on the same POST. Scheme filtering already existed in the origin squash; GHSA prose about missing scheme checks is not the residual and is not used as proof.

release_gate: PASS. GitHub Release/tag `v3.3.0` (`f2266fa9`) contains `3094ab60` and not `64aa0ab7`. PyPI wheel `mlflow-3.3.0-py3-none-any.whl` sha256 `f05786d5fcb45cf6fa21ea3c59116b58e47c2d3566e79651de229c29db70819c` has `session.post(webhook.url)` without delivery-time validate and without `ip.is_global`. GitHub Release/tag `v3.11.1` (`09179c65`) contains closer `64aa0ab7`. PyPI wheel `mlflow-3.11.1-py3-none-any.whl` sha256 `8f6bf1238ac04f97664c229dd480380c5c254a78bdb3c0e433e3a0397508b1af` has `ip.is_global` and `_validate_webhook_url(webhook.url)` in delivery.py. Advisory range introduced 0 / fixed 3.9.0 is false: `v3.2.0` lacks `delivery.py`; PyPI 3.9.0 still lacks `ip.is_global`. That range is unused.

uniqueness_gate: PASS. Absent from canonical94 strict 94.

seven_gates_exact_pass is false because ai_hunk_gate is NARROW. Verdict NARROW.

## Claim boundary

No PASS_PROPOSAL. Canonical94 is untouched. Publication and more-than-200 stay HOLD.
