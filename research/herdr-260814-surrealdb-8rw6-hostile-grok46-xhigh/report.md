# Hostile red-team: GHSA-8RW6-P7M8-63JP

KEEP proposal 1. Packet delta 0. Current leader-accepted count remains 85.

This is an independent hostile review of the net-new proposal that GHSA-8RW6 in surrealdb/surrealdb is AI_NEW_SURFACE_CONTRIBUTOR at candidate `15579bd2`, parent `ce74c027`, fix `8f89b260`, crates/GitHub 3.1.3 / 3.1.4. No worker verdict was inherited. This packet does not admit the row, does not rebuild canonical85, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0.

Leader may admit this KEEP proposal only after an independent leader replay. This packet does not admit it.

## Hostile questions

1. Does 15579 only refactor or move an already vulnerable scan path? No for the counted surface. Parent already has `surrealdb/core/src/exec/operators/scan/pipeline.rs` (blob `84440278`, first-add `c896f841` with no AI trailer). Parent `filter_fields_by_permission` keys a `HashMap<String, PhysicalPermission>` by top-level field name and uses `obj.remove`. It does not call `Value::each` or `value.cut`. Candidate blob `87613265` stores `(Idiom, PhysicalPermission)` pairs, expands wildcards with `original.each(&idiom.0)`, and cuts with `value.cut` in forward order. That is a new streaming permission surface, not a move of the parent loop.

2. Does the advisory exploit never traverse `pipeline.rs`, leaving only human `doc/output.rs` and `doc/reduce.rs`? Those two files do not exist at 15579. They are added later by unmarked `25d16748`. At candidate time the document executor already had the same each+forward-cut pattern in unchanged `pluck.rs` (`Document::pluck_select`). The GHSA names all three later sites. Language tests that omit `planner_strategy` run `compute-only`, `all-ro`, and `best-effort-ro`. `all-ro` requires the new planner for read-only SELECT. Production default is `best-effort` (`SURREAL_PLANNER_STRATEGY`, `NewPlannerStrategy::default`). Point lookups reuse `build_field_state` / `filter_and_process_batch` from the scan pipeline (`record_id.rs`). The GHSA regression `7356_array_element_select_permission_leak.surql` is `SELECT * FROM ONLY doc:1` as a record user and names `filter_fields_by_permission` in its reason. Missing whole-GHSA-only reachability would be NARROW; the streaming path is a distinct advisory-affected execution surface.

3. Does an AI trailer fail to bind the exact hunk? The introducing commit is GitHub-committed, 81 files, associated-pulls empty. `github.com/surrealdb/surrealdb/pull/81` is an unrelated integer-range PR. Internal `(#81)` is not that GitHub pull. No unmarked member was recovered, so this is not member-to-carrier transfer. Parent lacks the each+cut loop; the candidate adds it together with `field_select_permission_wildcard_path` tests that document `Value::each`. Later Claude-marked `02b3eb88` still has the forward loop and does not re-author it.

4. Does removing 15579 leave the same GHSA path reachable? On the streaming path, revert restores HashMap top-level-only filtering, so the odd-index each+cut leak in `pipeline.rs` is gone. The compute/document path still leaks via `pluck` / later `output.rs` / `reduce.rs`. Whole-GHSA but-for fails. Counted class is AI_NEW_SURFACE_CONTRIBUTOR at the streaming surface only. Human sibling origin is acceptable because the AI path itself is a real causal contribution.

5. Does v3.1.3 lack 15579, or v3.1.4 lack 8f89? Owned blob:none fetch of the tags peels `v3.1.3` to `7db9a420` and `v3.1.4` to `c9e03954`. GitHub compare: 15579 is merge-base of both tags (ahead, behind 0). 8f89 diverges from both tags. Byte containment still holds: v3.1.3 `pipeline.rs` blob `0160c213` equals the fix parent (forward `each`, no `.rev()`). v3.1.4 `pipeline.rs` / `output.rs` / `reduce.rs` blobs equal 8f89 (`e0e00f7a`, `8c0392d7`, `fb4e9cd5`). crates.io `surrealdb-core` 3.1.3 / 3.1.4 are not yanked; crate file bytes match those tag blobs. Shared clone was not mutated and still has no `v3.1.3` / `v3.1.4` tags.

6. Is the fix incomplete or not the minimum reversal? 8f89 is the GHSA-named closer. On `pipeline.rs` it is the minimum reversal: `for path in original.each(&idiom.0)` becomes `into_iter().rev()` with an issue #7356 comment. It also reverses the later human document paths. That extra sibling reversal does not void the AI-path reversal.

7. Does the identity overlap canonical85 or foundation? No. GHSA-8RW6 is absent from canonical85 strict 85 and from canvas `foundation.jsonl`. Same-repo SELECT-permission GHSAs (COUNT fast path, JSON Patch, error-message leak) are different fingerprints and are not in the counted 85.

## Gates

1. `identity_gate`: PASS. Live github-reviewed GHSA-8rw6-p7m8-63jp at advisory-database `6253da86`. Repo advisory state published, `withdrawn_at` null. crates.io `surrealdb` last known affected `<= 3.1.3`, fixed 3.1.4. Mechanism named is element-level `field.*` SELECT leak from forward cut.

2. `ai_hunk_gate`: PASS. Atomic `15579bd2` with explicit Claude Opus 4.7 Co-authored-by authors the each+forward-cut hunk versus parent. Not a later AI review. Not a recovered human member.

3. `topology_gate`: PASS. Single parent `ce74c027`. Candidate is an any-parent ancestor of both public tags. Carrier set empty. GitHub squash committer without a mapped unmarked member is not authorship transfer. Closer is not in v3.1.3.

4. `but_for_gate`: PASS at the stated narrow scope. See question 4. Not whole-GHSA direct root.

5. `fix_reversal_gate`: PASS. Official closer `8f89b260` reverses the same streaming loop. Sibling document reversals are extra, not a substitute.

6. `release_gate`: PASS on GitHub tags plus crates.io `surrealdb-core` 3.1.3 / 3.1.4. Moving branch `main` is not used as containment. Fix SHA need not be a tag ancestor when the tag bytes equal the closer blobs.

7. `uniqueness_gate`: PASS. Absent from canonical85 strict 85 and from foundation.jsonl.

`remediation_patch_delta_gate` is NOT_APPLICABLE. The candidate is a planner refactor that adds a nested-permission surface, not an explicit incomplete security guard on an older hole.

## Claim boundary

No red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical85. Publication and more-than-200 stay HOLD.

## Replay

Replay fetches GitHub tags, GitHub compare, the repo advisory, advisory-database bytes, and crates.io surrealdb-core 3.1.3/3.1.4 into `mktemp -d`, then removes that directory on exit. Shared clones stay read-only. This packet does not retain `work/`.
