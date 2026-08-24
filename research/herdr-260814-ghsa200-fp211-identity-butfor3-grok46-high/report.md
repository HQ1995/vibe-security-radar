# fp211 identity+but-for remainder (exact 3)

Verdict first: **0 PASS proposals**, **3 NARROW**, 0 REJECT, 0 UNKNOWN, 0 BLOCKED. Assigned 3, reviewed 3, unreviewed 0. Conservation 3=3+0. Pool equation 9=6+3. packet_delta=0. Canonical strict count remains **84**. Publication and more-than-200 stay **HOLD**. Worker PASS is a proposal only; this packet emits none.

Selection was frozen before research in `selected.jsonl`. The fp211 NARROW pool with only `identity_gate` and `but_for_gate` non-PASS has nine rows. Six earlier rows were already reviewed by `herdr-260814-ghsa200-nearpass-twogate12` and are excluded: GHSA-GC24-PX2R-5QMF, GHSA-HFF7-CCV5-52F8, GHSA-Q447-RJ3R-2CGH, GHSA-C339-W3CQ-2RJR, GHSA-Q6QF-4P5J-R25G, GHSA-Q5PP-GVJG-H7V4. No padding and no substitution.

Frozen remainder, ordinal order:

1. ordinal 125 `post:openclaw-feishu-tool-gate@canonical` / GHSA-2Q7J-2VHX-56G8
2. ordinal 183 `posthold:F02` / GHSA-MFMP-Q643-VJ39
3. ordinal 184 `posthold:F03` / GHSA-M649-24Q9-Q6R4

Baseline is committed canonical84 `ca034f064fd696201c81baae7392c14f0d501d2b`, ledger sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`, strict count 84. Inherited fp211 PASS values are not proof. OSV/CVE alias routing is not identity. An AI squash cannot receive a member hunk by trailer. Incomplete remediation requires an explicit AI security attempt and a same-boundary patch delta.

## NARROW (uncounted)

| ID | Repo | Unresolved gates | Minimal counterexample |
| --- | --- | --- | --- |
| GHSA-2Q7J-2VHX-56G8 | openclaw/openclaw | but_for | Parent already gated perm/drive/wiki from top-level `feishuCfg.tools`. Candidate 5f6e1c19 is a Claude multi-account sync that checks `firstAccount.config.tools` at registration and always builds the client from that first account. `tool-account.ts` is absent there. The closer amends a later execute-time router. |
| GHSA-MFMP-Q643-VJ39 | ChurchCRM/CRM | identity, topology, but_for, release | Repo advisory packs new GroupView pills with an untouched GroupRoles.js option sink whose blob equals the member parent. Member 0ea20d01 is not a tag ancestor. GroupView.js blobs are three-way unequal versus squash 80a3e620 and tag 7.4.2. |
| GHSA-M649-24Q9-Q6R4 | ChurchCRM/CRM | identity, topology, but_for, release | Parent already had quoted `data-name`. Candidate adds `tel:` and `mailto:`. The GHSA names all three. Same member is not in 7.5.1. Fix member 5631bb08 is not in 7.6.0; squash ae2b7355 is. |

## Per-case

### GHSA-2Q7J-2VHX-56G8 (125, openclaw/openclaw) — NARROW

Identity PASS: published repository advisory names `openclaw/openclaw`, npm `@openclaw/feishu`, and Feishu tools per-account disablement. Global `/advisories` is 404. `cve_id` is null. CVE-2026-62187 is CNA routing, not a counting unit. Sibling GHSA-W8WF-3QVJ-6XQF is permission-tools, not an alias.

AI-hunk PASS: atomic Claude Opus 4.5 commit `5f6e1c19` (one parent). Topology PASS: that commit is an ancestor of `v2026.2.6` and `v2026.6.6`. No carrier. `v2026.2.6` `perm.ts` blob `f11fb988` equals the candidate.

But-for NARROW: parent `7e005acd` already imported `resolveToolsConfig` and skipped tool registration when disabled. The candidate only retargets that check at `firstAccount`. Execute-time `requiredTool` lives in `tool-account.ts`, which the candidate does not add. `v2026.6.6` already has that file without `requiredTool`. Closer `d4f11d30` (`fix(feishu): enforce account tool family gates`) is first in `v2026.6.9`. Fix-reversal PASS. npm `2026.6.6` / `2026.6.9` `gitHead` equals the git peels. GitHub releases exist and are not drafts. Release PASS. Uniqueness PASS versus canonical84.

Not incomplete remediation: the candidate is a feature sync, not an explicit security attempt.

### GHSA-MFMP-Q643-VJ39 (183, ChurchCRM/CRM) — NARROW

Identity NARROW: published repo advisory, global 404, Packagist `churchcrm/crm` 404. The GHSA names four OptionName HTML sinks including GroupRoles.js, which the AI member does not edit.

AI-hunk PASS on member `0ea20d01` (Claude Opus 4.6, one parent). Topology NARROW: the member is not an ancestor of squash `80a3e620` (PR 8316, also Claude-marked, plus DawoudIO) or of tags 7.4.2 through 7.6.0. GroupView.js blobs: member `6d1eae10`, carrier `23fb4f55`, 7.4.2 `1cb473c5`. GroupRoles.js blob `62dfbce1` is identical on parent and member.

But-for NARROW: parent GroupView.js has no `buildRolePills` and no `tel:`/`mailto:`. The member adds unescaped OptionName pills. Parent GroupRoles.js already concatenates `i18next.t(value.OptionName)` into option HTML. A GHSA that still names that old sink is not a clean origin of every listed line.

Fix members `3b8b4745` and `367dd18e` are not tag ancestors. Squash `330d0d6a` equals 7.4.3 GroupView.js `116f1bff` and adds `escapeHtml` on the three pill sinks. Fix-reversal PASS on that released closer. Release NARROW when the counted commit is the member. GitHub 7.4.2 / 7.4.3 exist and are not drafts. Uniqueness PASS; shared origin with ordinal 184 does not merge cases.

### GHSA-M649-24Q9-Q6R4 (184, ChurchCRM/CRM) — NARROW

Identity NARROW: published repo advisory packs new `tel:`/`mailto:` concatenations with a parent `data-name` attribute sink. Global 404.

Same origin member and squash as ordinal 183. Topology NARROW on the same three-way blob split. But-for NARROW: parent already has `data-name`; member adds `tel:` and `mailto:` using `.text().html()`. The GHSA names all three.

7.5.1 still renders `tel:`/`mailto:`/`data-name` without `escapeAttribute`. 7.6.0 uses `escapeAttribute`. Fix member `5631bb08` is an omnibus XSS/SQLi patch, is not a tag ancestor, and GroupView.js blob `9a48ea50` is not 7.6.0 `041a9794`. Squash `ae2b7355` (PR 9428) equals 7.6.0. Do not transfer. Fix-reversal PASS on the released squash. Release NARROW for the member. Uniqueness PASS.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=84. current_leader_accepted_count=84. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
