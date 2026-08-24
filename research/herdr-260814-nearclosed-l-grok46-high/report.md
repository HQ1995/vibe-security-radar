# Near-closed released wave L (fp211 ordinals 124, 183, 184)

Verdict first: **3 PASS proposals**. 0 NARROW. 0 REJECT. 0 UNKNOWN. 0 BLOCKED.

Assigned 3, reviewed 3, unreviewed 0. Conservation 3=3+0. Worker PASS is a proposal only. Canonical90 remains 90 HOLD. Packet delta 0. Publication and greater-than-200 stay HOLD. This packet does not rebuild the strict-released ledger.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical90 summary SHA-256 `5222879219a975fa4388f3f07f5c62cd6687a642b6509afe48a4250fb4be81ef`. Ledger SHA-256 `daf706e14d514ad62d197e61aa8ec7f52eefd958bc19a4a7c58591a0be8654ec`. fp211 public_cases.jsonl SHA-256 `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`. Shared tracked files and canonical ledgers were not edited. No commit, push, or credential output.

## Assignment

Exactly three first-party identities, fp211 ordinals 124, 183, 184: GHSA-G353-MGV3-8PCJ, GHSA-MFMP-Q643-VJ39, GHSA-M649-24Q9-Q6R4. Overlay routing (NARROW identity/topology/but_for, packed XH72, shared ChurchCRM origin SHA) is not truth. All seven contract gates were rebuilt from Git objects, first-party advisories, tags, and public artifacts.

PASS_PROPOSAL required all seven gates exact PASS for the counted scope. Scoped-contributor rule: PASS only if removing the exact atomic AI change eliminates or materially shrinks a precisely named advisory mechanism, even when an older sibling path remains, and the later minimum fix reverses that exact new surface. Preservation, refactor, sibling caller of a preexisting helper, packed second identities, and member-to-squash transfer are rejected.

Ordinals 183 and 184 share hypothesized member `0ea20d01` and squash `80a3e620`. Shared SHA never proves duplication or uniqueness. First-party GHSA objects, semantic fingerprints, and distinct closers were compared before counting.

Clones used read-only: `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`, `/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm`. No clone writes. No durable pages.

## Per case

1. GHSA-G353-MGV3-8PCJ ordinal 124 PASS_PROPOSAL. Identity PASS: reviewed first-party GHSA-g353 aliases CVE-2026-32974 only, Feishu webhook mode accepted verificationToken without encryptKey, patched 2026.3.12 by 7844bc89. Distinct from GHSA-XH72-V6V9-MWHC / CVE-2026-44109 (residual fail-closed plus blank card-action tokens, fix c8003f1b, patched 2026.4.15) and from GHSA-Q447 unbounded-body DoS. Count squash 5c2cb6c5 on its own Claude Opus 4.6 marker, n_parents=1. Member b0c67ea0 is not a tag ancestor; monitor.ts blob equals squash and v2026.2.12; no authorship transfer. Parent 49c60e90 logs webhook mode not implemented. Squash adds Lark.adaptDefault. First-parent pickaxe for adaptDefault on v2026.2.12 hits the squash. Closer 7844bc89 requires encryptKey for webhook and is first-parent of v2026.3.12, not of v2026.3.11. Contained in v2026.3.11 / fixed v2026.3.12. Uniqueness PASS versus canonical90, XH72, and Q447.

2. GHSA-MFMP-Q643-VJ39 ordinal 183 PASS_PROPOSAL. Identity PASS: published repo advisory, not withdrawn; global /advisories 404 is not a missing identity. Names GroupView OptionName HTML pills/dropdowns and GroupRoles option labels; affected < 7.4.3, patched 7.4.3. Count squash 80a3e620 on its own Claude Sonnet 4.6 marker, n_parents=1. Member 0ea20d01 is not a tag ancestor; GroupView.js blobs are three-way unequal; no authorship transfer. Scoped contributor applied to AI-added buildRolePills without transferring the preexisting GroupRoles.js option sink (blob 62dfbce1 identical on parent and squash). First-parent pickaxe for buildRolePills on 7.4.2 hits the squash. Closer 330d0d6a adds escapeHtml on those GroupView sites and is first-parent of 7.4.3; members 3b8b4745/367dd18e are not transferred. Contained in 7.4.2 / fixed 7.4.3. Distinct from GHSA-M649. Uniqueness PASS versus canonical90.

3. GHSA-M649-24Q9-Q6R4 ordinal 184 PASS_PROPOSAL. Identity PASS: published repo advisory, not withdrawn. Names tel:/mailto:/data-name attribute XSS in GroupView.js; affected 7.5.1, patched 7.6.0. First-party text distinguishes GHSA-mfmp (HTML text, escapeHtml, 7.4.3) and states that MFMP's encoder would not close these sinks. Same counted squash 80a3e620; shared SHA is not duplication. Scoped contributor applied to AI-added tel: and mailto: concatenations. Parent already had quoted data-name. First-parent pickaxe for tel: and mailto: on 7.5.1 hits the squash; data-name pickaxe hits earlier human ede1bfb0. Closer ae2b7355 switches tel/mailto/data-name to escapeAttribute and is first-parent of 7.6.0; member 5631bb08 is not transferred. Contained in 7.5.1 / fixed 7.6.0. Uniqueness PASS versus canonical90 and versus MFMP.

## Uniqueness

None of the three IDs is in canonical90 strict_released_case_ids (90). None is GHSA-8RW6-P7M8-63JP. CVE aliases are stored and not counted. GHSA-G353 is not GHSA-XH72 and is not GHSA-Q447. GHSA-MFMP is not GHSA-M649: different first-party identities, different DOM contexts (HTML text versus URL/attribute), different closers (330d0d6a versus ae2b7355), different tags (7.4.3 versus 7.6.0). Replay uniqueness reads only the pinned canonical90 summary plus the pinned advisory objects.

## Claim boundary

Countable PASS requires all seven gates PASS plus leader admission. Proposed PASS: 3. Publication remains HOLD. Greater-than-200 remains HOLD. This packet does not support a greater-than-200 claim. Canonical90 was not rebuilt. Expansion stopped. Did not pad.
