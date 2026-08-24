# fp211 topology-only remainder (exact 3)

Verdict first: **0 PASS**. Seven fp211 NARROW identities have topology_gate as the only non-PASS contract gate. Canonical82 already counts four of them. This packet freezes the remaining **three** first-party GHSA identities in order and independently rechecks all seven gates. All three stay **NARROW**. Worker PASS is a proposal and this packet emits none. packet_delta=0. Canonical strict count remains **82**. Pending 425G/HC8V stay excluded. Publication and more-than-200 claims remain **HOLD**. Causal admission is false.

## Scope

Deterministic input: fp211 topology-only NARROW set (ordinals 1, 92, 93, 107, 113, 126, 156).

Leader mechanical exclusion because canonical82 already counts them:

- ord1 GHSA-FMFG-9G7C-3VQ7
- ord92 GHSA-WV46-V6XC-2QHF
- ord93 GHSA-RG8M-3943-VM6Q
- ord113 GHSA-G3XQ-3GMV-QQ8G

Frozen remainder, no padding or substitution:

1. ord107 GHSA-CW23-QWR7-C655
2. ord126 GHSA-5WP8-Q9MX-8JX8
3. ord156 GHSA-X34R-63HX-W57F

Pending GHSA-425G-FJHQ-5H92 and GHSA-HC8V-WWC9-VGXM are excluded. Inherited fp211 PASS values are not proof. Member authorship is never transferred onto a carrier. An atomic AI member may remain a candidate with an explicit first-parent carrier; that rule does not close topology when the member is missing from first-parent public history or when blobs are unequal.

Conservation: assigned = reviewed + unreviewed = 3 + 0 = 3. Pool equation: 7 = excluded_canonical82_4 + assigned_3.

## Per-case

### GHSA-CW23-QWR7-C655 (107, nearai/ironclaw) - NARROW

Identity NARROW: global GHSA is unreviewed, `vulnerabilities=[]`, `github_reviewed_at` null, repository advisory 404.

Atomic Claude member `b20880c1` first-parent moves High-risk `NEVER_AUTO_APPROVE` from full-string `contains()` into the per-segment loop. Parent `f3a0c71b` already had that split on `|`, `&`, `;` without newline. AI-hunk PASS. But-for PASS for the High-check relocation.

Topology NARROW: member is not an ancestor of squash carrier `b58b4215` (PR 368), `ironclaw-v0.29.1`, or fix `a1d7c3ba`. Carrier is an any-ancestor of `ironclaw-v0.29.1` but not a first-parent ancestor. `shell.rs` blobs: member `4798d0c3`, carrier `fa92cb37`, tag `8f574e90`. Do not transfer.

Release NARROW: vulnerable crate tag does not contain the member and does not first-parent-contain the carrier. Fix blob equals `ironclaw-v1.0.0`. Fix-reversal PASS: closer documents newline among shell separators. Uniqueness PASS versus canonical82.

### GHSA-5WP8-Q9MX-8JX8 (126, qhkm/zeptoclaw) - NARROW

Identity PASS on the reviewed repository advisory. Claude member `3c4368da` is PR 104 member 8 of 11 and first-parent-introduces `ShellAllowlistMode` plus `!self.allowlist.is_empty()`. Claude blocklist member `91f6c2bf` is a first-parent ancestor of `v0.6.1` but is not a PR 104 member. AI-hunk PASS.

Topology NARROW: allowlist member is not a tag ancestor. Squash `1712debb` is Claude-marked, is a first-parent ancestor of `v0.6.1`, and is the first-parent pickaxe hit for `allowlist.is_empty`. That squash is multi-purpose (Landlock/Firejail/Bubblewrap plus allowlist). `shell.rs` blobs: member `a09e6171`, carrier `165b10b5`, `v0.6.1` `87b9d900`. Unmarked human PR 104 members are not transferred.

Incomplete-remediation patch-delta NARROW: the GHSA residual spans allowlist first-token/empty-strict and regex/literal blocklist holes. Closer `68916c3e` also names GHSA-hhjv. Same-boundary-only delta is not proved. Fix-reversal PASS on the 5WP8 vectors. Release NARROW when the counted commit is the allowlist member. Uniqueness PASS; HHJV stays a different GHSA.

### GHSA-X34R-63HX-W57F (156, langroid/langroid) - NARROW

Identity PASS. Advisory mechanism is pandas_eval WAF bypass (`_literal_ok`, dunders) in `pandas_utils.py`.

Copilot member `b1c45e3f` is PR 850 member 7 of 10 and first-parent-rewrites `config.full_eval` to `self.config.full_eval` in `table_chat_agent.py` only. `pandas_utils.py` blob equals the parent. Human PR 850 member `b68a8a79` authored "Mitigation for CVE-2025-46724". AI-hunk NARROW. But-for NARROW.

Topology NARROW: member is not an ancestor of mixed squash `0d9e4a7b` or `0.59.31`. Squash quotes Copilot and Claude. `table_chat_agent.py` blobs: member `ba8bc96c`, carrier `c7b32065`, `0.59.31` already `28c3c288` equal to fix `30abbc1a`. `visit_Attribute` is absent in `0.59.31` and present in the fix. Release NARROW. Fix-reversal PASS. Uniqueness PASS versus GHSA-PMCH.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=82. current_leader_accepted_count=82. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
