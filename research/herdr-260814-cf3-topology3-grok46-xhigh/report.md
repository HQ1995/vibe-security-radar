# cf3 topology-3 independent closure

Verdict first: **0 PASS_PROPOSAL**. Assigned **3**. Reviewed **3**. Conservation **3=3+0**. **1 NARROW**. **2 REJECT**. Canonical86 stays **86**. packet_delta **0**. Prior topologyonly/nearpass rows were hypotheses only. Worker PASS is proposal only. Seven gates must be exact PASS after replay; none are.

## Bindings (independent)

PR members, squash carriers, and parents were recovered from local git objects. Carrier authorship is not transferred. Shared SHA is routing only.

### GHSA-5WP8-Q9MX-8JX8 (qhkm/zeptoclaw) NARROW

Identity PASS: github-reviewed first-party repo advisory, not withdrawn. crates.io zeptoclaw introduced 0 fixed 0.6.2.

AI hunk PASS: Claude member `3c4368da` (n_parents=1, parent `182b7c83`) authors `ShellAllowlistMode` first-token allowlist. Claude member `91f6c2bf` authors the earlier substring blocklist. Both are real members, not the squash.

Topology FAIL: `3c4368da` is not an ancestor of squash `1712debb` (#104), `v0.6.1`, or fix `68916c3e`. `shell.rs` blobs: member `a09e6171` != carrier `165b10b5` != `v0.6.1` `87b9d900`. First-parent pickaxe for `allowlist.is_empty` hits the squash. Hypothesis that PR 104 members had n_parents=0 is false; local objects have n_parents=1.

Release FAIL for the allowlist member (not in `v0.6.1` peel `ad14ed8d`). `91f6c2bf` is a first-parent ancestor of `v0.6.1`, but the GHSA also names allowlist residuals that exist only in the squash tree. But-for FAIL: deleting `3c4368da` does not change the released artifact.

Fix reversal PASS on the four GHSA-5WP8 shell.rs vectors in `68916c3e`. That closer also names GHSA-HHJV (Android); shared SHA is routing, not a merge with the negative-control identity. Uniqueness PASS versus canonical86.

### GHSA-CW23-QWR7-C655 (nearai/ironclaw) REJECT

Identity FAIL: GitHub advisory is unreviewed, `github_reviewed_at` null, `vulnerabilities=[]`, repository advisory 404, absent from pinned github-reviewed advisory-database. CVE-2026-18980 is not a counting unit.

AI hunk FAIL: member `b20880c1` (Claude Sonnet 4.6, n_parents=1, parent `f3a0c71b`) relocates High-risk `contains()` into the per-segment loop. Parent already split on `|`, `&`, `;` without newline. That hunk is a false-positive tweak, not the GHSA injection residual closed by `#4869`.

Topology FAIL: member is not an ancestor of squash `b58b4215` (#368), `ironclaw-v0.29.1`, or fix `a1d7c3ba`. Blobs unequal. Carrier is an any-parent ancestor of `ironclaw-v0.29.1` but not a first-parent ancestor. Release FAIL. Fix-reversal UNKNOWN after identity/topology already failed. Uniqueness PASS versus canonical86.

### GHSA-X34R-63HX-W57F (langroid/langroid) REJECT

Identity PASS: github-reviewed first-party advisory. Distinct from counted GHSA-PMCH.

AI hunk FAIL: advisory mechanism is `pandas_utils.py` WAF dunder/`_literal_ok` residual. Copilot member `b1c45e3f` edits only `table_chat_agent.py`. Copilot `556196b8` is a 6-line `try/finally` around `generic_visit`, not `visit_Attribute`. Human `b68a8a79` authored "Mitigation for CVE-2025-46724". Closer `30abbc1a` adds `visit_Attribute` with a Claude trailer; an advisory-listed closer is not an origin.

Topology FAIL: neither Copilot member is an ancestor of squash `0d9e4a7b` (#850) or tag `0.59.31`. pandas_utils blobs: member `50684588` != carrier `4dc82715` != `0.59.31` `d2d156b4` != fix/`0.59.32` `108acf56`. But-for FAIL. Fix reversal FAIL (closer does not reverse an AI member WAF hunk). Release FAIL. Uniqueness PASS versus canonical86/PMCH.

## Conservation

3 assigned = 3 reviewed + 0 unreviewed. PASS_PROPOSAL=0. cve_aliases_counted=false. canonical86_overlap=0.

## Claim boundary

Canonical86 HOLD remains 86. L0 claim source in RESEARCH-TRUTH-LAYERS remains canonical84; this packet uniqueness-checks canonical86 as requested and does not edit either ledger. Publication and greater-than-200 remain HOLD. No commit or push.
