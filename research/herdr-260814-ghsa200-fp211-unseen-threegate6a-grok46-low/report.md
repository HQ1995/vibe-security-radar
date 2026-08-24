# fp211 unseen three-gate remainder (exact 6)

Verdict first: **0 PASS**. All six rows stay **NARROW**. Worker PASS is a proposal and this packet emits none. packet_delta=0. Canonical strict count remains **84**. Publication and more-than-200 claims remain **HOLD**. Causal admission is false.

## Scope

Leader freeze, no padding or substitution, ordinal order:

1. ord28 GHSA-QJ77-C3C8-9C3Q (topology+but_for+release)
2. ord33 GHSA-3CVX-236H-M9FJ (but_for+fix_reversal+release)
3. ord62 GHSA-JFV4-H8MC-JCP8 (identity+topology+but_for)
4. ord71 GHSA-HHFF-FJ5F-QG48 (identity+topology+but_for)
5. ord77 GHSA-W4H3-GPV2-82QC (identity+but_for+fix_reversal)
6. ord79 GHSA-VMW2-QWM8-X84C (topology+but_for+fix_reversal)

Active two-gate lanes are out of scope. Inherited fp211 PASS values are routing only. Atomic AI members are never transferred onto merge/squash/rebase carriers. Trailer transfer is forbidden. Incomplete remediation is not used: none of these six is an explicit same-boundary security-attempt residual.

Conservation: assigned = reviewed + unreviewed = 6 + 0 = 6.

## Per-case

### GHSA-QJ77-C3C8-9C3Q (28, openclaw/openclaw) - NARROW

Identity PASS on the reviewed first-party advisory for Windows cmd.exe exec allowlist bypass. Atomic Claude 78d08fc5 adds node-host allowlist-before-prompt. AI-hunk PASS. Topology NARROW: member is absent from v2026.2.1 and npm gitHead ed4529e2; squash 4b3e9c0f is first-parent; bash-tools.exec.ts blobs are pairwise unequal. But-for NARROW: the GHSA invariant is cmd.exe metacharacters, not the AI node-host prompt. Parent blob 91b38dc3 is missing under GIT_NO_LAZY_FETCH; fail closed. Fix a7f4a53c first-parent of v2026.2.2 / npm 539a15e6 hardens Windows analysis of the carrier tree. Release NARROW for the counted member. Uniqueness PASS versus canonical84; shared repository is not dedupe.

### GHSA-3CVX-236H-M9FJ (33, openclaw/openclaw) - NARROW

Identity PASS on the reviewed allowInsecureAuth Control UI advisory. Atomic Claude 079af0d0 adds hasTokenAuth device skip. AI-hunk PASS. Topology NARROW: any-ancestor of tags and npm gitHeads, not first-parent in 8000-commit walks; released message-handler.ts blob unequal to the member. But-for NARROW: deleting the token skip does not remove allowInsecureAuth. Fix 40a29261 is a /merge-pr closer, first-parent of npm 2026.2.21, not an atomic reversal of the AI hunk. git tag v2026.2.21 peel 5e34eb98 != npm gitHead d9844c6a. Shared SHA with GHSA-RQPP is not dedupe. Uniqueness PASS.

### GHSA-JFV4-H8MC-JCP8 (62, openclaw/openclaw) - NARROW

Identity NARROW: reviewed repo advisory names unvalidated PID kill; the AI member blob is not the released helpers.ts blob. Atomic Claude bb6d608d. Topology NARROW: member is not an ancestor of squash 8befe7f8 or v2026.1.15. But-for NARROW: parent already had pkill -f resume cleanup. Fixes 6084d13b/eb60e2e1 first-parent of v2026.2.14 close the carrier, not the member. Release NARROW. Uniqueness PASS.

### GHSA-HHFF-FJ5F-QG48 (71, openclaw/openclaw) - NARROW

Identity PASS on the reviewed Discord preflight advisory. Atomic Claude b9b47f50 is first-parent of v2026.3.28 and npm gitHead f9b10792. Topology PASS for that membership. But-for NARROW: parent already transcribed first audio before member auth. Member path is absent from the tag tree after the extensions/discord move. Fix ee52f642 first-parent of v2026.3.31. Release NARROW for member-path blob containment. Uniqueness PASS.

### GHSA-W4H3-GPV2-82QC (77, openclaw/openclaw) - NARROW

Identity NARROW: unreviewed GHSA, repository advisory 404. Atomic Claude 8d74578c equals its listed carrier. Member is first-parent of v2026.1.20. media.ts blob equals parent. But-for NARROW: preexisting file:// loader. Closers 4fd7feb0 and 93880717 first-parent of v2026.3.22. npm 2026.3.22 has integrity and no gitHead. Uniqueness PASS versus sibling image-tool identities.

### GHSA-VMW2-QWM8-X84C (79, jasperfx/marten) - NARROW

Identity PASS on the reviewed Marten regConfig advisory. Atomic Claude 3408b01e adds PrefixSearch. Member is not an ancestor of V8.36.0; carrier 18c8d9b4 is first-parent. PrefixSearch blobs are equal; FullTextWhereFragment is unchanged on the member. But-for NARROW: new API on a preexisting sink. Fix 62624965 first-parent of V8.37.0 validates all fragment paths. Do not transfer. Uniqueness PASS.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=84. current_leader_accepted_count=84. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
