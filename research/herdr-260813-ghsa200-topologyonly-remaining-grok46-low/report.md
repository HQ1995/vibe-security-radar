# Remaining topology-only NARROW identities

Verdict first: **0 PASS**. Seven fp211 NARROW identities have topology_gate as the only non-PASS contract gate. After mechanical exclusion of recovered/covered overlap, **three** first-party GHSA identities remain. All three stay **NARROW**. Worker PASS is a proposal and this packet emits none. Publication remains **HOLD**. Causal admission is false. The strict-released lower bound is not rebuilt. This packet does not support a more-than-200 claim.

## Scope

Source pool from `final_mechanisms.jsonl`: ordinals **1, 92, 93, 107, 113, 126, 156** (exactly the NARROW rows whose six other gates are PASS).

Mechanically excluded before review:

- Recovered/covered: ordinal **1** `GHSA-FMFG-9G7C-3VQ7` (final ACCEPT / netred KEEP / canonical72, counting squash carrier `39806871`, not member `aae7acba`).
- Recovered/covered: ordinal **113** `GHSA-G3XQ-3GMV-QQ8G` (canonical72 / B3 pending identity, member/carrier blob mismatch).
- nearclosed already reviewed: ordinal **107** `GHSA-CW23-QWR7-C655` and ordinal **126** `GHSA-5WP8-Q9MX-8JX8`.
- canonical72, final, netred, medium5, B3, Actual-Gogs, and current Q855 (`GHSA-Q855-8RH5-JFGQ`) are not expanded into this slice.

Assigned remaining unique identities: **92, 93, 156**. Conservation: assigned = reviewed + unreviewed = 3 + 0 = 3. Count unit is first-party GHSA once. CVE aliases are not counting units. Scope was not broadened.

Ordinal 156 also appears in the nearclosed reviewed set. This packet still independently re-checks that remaining topology-only identity because the assigned remainder after excluding 107/126 is 92/93/156. The independent check preserves NARROW.

## Conservation

| Verdict | Count |
|---|---|
| PASS | 0 |
| NARROW | 3 |
| UNKNOWN | 0 |
| REJECT | 0 |
| BLOCKED | 0 |

Pool equation: source_pool_7 = recovered_1_and_113 (2) + nearclosed_107_and_126 (2) + assigned_3.

## Why zero PASS

Admission requires the counted commit itself to carry an AI marker and its own first-parent diff to prove the vulnerable hunk, or a squash member that is atomically attributable without transferring authorship onto a different carrier. Preserve NARROW when the case is carrier-only, the member object is missing, member/carrier/tag blobs mismatch, or the squash is mixed. All seven contract gates must be the string `PASS`. Prefer no PASS over weak evidence.

## Per-case

**GHSA-WV46-V6XC-2QHF** (92, openclaw/openclaw). Reviewed first-party GHSA, CVE-2026-35670. Member `ce12b909` is present, Claude-marked, parent_count=1, and first-parent adds `resolveChatUserId` nickname-then-username matching that the parent lacks. Member is not an ancestor of squash `9a3800d8` or tag `v2026.3.2`. `client.ts` and `webhook-handler.ts` member blobs differ from the carrier and from `v2026.3.2`. `channel.ts` member equals carrier `61fbc745` but `v2026.3.2` is `142f39d7`. Fix `7ade3553` is an ancestor of `v2026.3.22` and not of `v2026.3.2`. Do not transfer member authorship onto the Claude squash. Topology NARROW.

**GHSA-RG8M-3943-VM6Q** (93, openclaw/openclaw). Reviewed first-party GHSA, CVE-2026-41376. Member `fbfe2f15` is present, Claude-marked, parent_count=1, and first-parent injects `ThreadStarterBody` absent from the parent. Member is not an ancestor of squash `49c60e90` or tag `v2026.2.12`. `handler.ts` blobs are three-way unequal (member `018f4dc0`, carrier `eef2bed4`, `v2026.2.12` `c63ea3ee`). `channel.ts` member `eb67c49c` differs from carrier/`v2026.2.12` `366f74ad`. Fix `8a563d60` is an ancestor of `v2026.3.31` and not of `v2026.3.28`. Distinct from `GHSA-WV46`. Blob mismatch preserves NARROW.

**GHSA-X34R-63HX-W57F** (156, langroid/langroid). Reviewed first-party GHSA, CVE-2026-25481. Copilot member `b1c45e3f` first-parent only rewrites `config.full_eval` to `self.config.full_eval` in `table_chat_agent.py`. Member is not an ancestor of mixed squash `0d9e4a7b` or tag `0.59.31`. Squash message quotes Copilot and Claude. `table_chat_agent.py` blobs: member `ba8bc96c`, carrier `c7b32065`, `0.59.31` already `28c3c288` equal to fix `30abbc1a` / `0.59.32`. Copilot first-parent did not introduce `_literal_ok`; the member tree still has pandas_utils.py blob `50684588`, unequal to the carrier. Mixed squash plus non-ancestry plus blob mismatch: topology NARROW.

## Uniqueness

92 and 93 are already present in canonical72 as carrier-counted identities. This packet does not emit a second count and does not propose PASS. 156 is absent from canonical72, nearclosed KEEP, netred KEEP, medium5, B3, Actual-Gogs, and Q855. Shared openclaw SHAs with other GHSA identities are different invariants and are not merged. CVE aliases are stored and not counted.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. Integration and publication stay HOLD.

Status is **TERMINAL**. Expansion stopped. No further candidates in the assigned remaining set.
