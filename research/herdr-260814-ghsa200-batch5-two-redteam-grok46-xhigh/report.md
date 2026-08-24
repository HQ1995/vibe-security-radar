# Red-team: batch-5 PASS pair

**Status: `REDTEAM_COMPLETE`.** Hostile hypothesis: neither source-worker PASS is countable until independently proved. Assigned exactly `GHSA-F229-3862-4942` and `GHSA-33RQ-M5X2-FVGF` from `autoresearch/herdr-260814-ghsa200-directroot-batch5-grok46-medium/cases.jsonl`. Source verdicts and prose were not trusted.

**KEEP proposal: 0. NARROW: 2. REJECT/UNKNOWN/BLOCKED: 0.**

Worker PASS remains proposal only. Causal admission is false. Publication and more-than-200 remain HOLD. Canonical73 still holds 73 strict released first-party GHSA identities. Neither assigned ID is in that set.

Leader contract frozen at SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.

## Attacks

| Case | Attack | Result |
|------|--------|--------|
| F229 | Original pre-AI sandbox escape is an old bug | Sticks |
| F229 | Claude attempt creates or preserves the exact residual array/object coercion | Sticks: Claude did not author the attempt; human array helper already covers the GHSA PoC; closer is object-coercion sibling |
| F229 | 2.11.0 shipped the attempt without 09afbebe despite advisory ranges | Sticks as a counting failure: the cut exists, first-party ranges treat it as the fix |
| F229 | 09afbebe closes that same residual | Sticks as a failure: object toString/valueOf sibling, not the named array PoC |
| 33RQ | f5c90f0e itself authors the allowFrom fallthrough rather than inheriting a human PR member | Sticks: Claude blob is the human hard deny |
| 33RQ | 2026.1.29 contains the fallthrough | Does not stick |
| 33RQ | 8c7901c9 is the minimal exact reversal | Does not stick |
| 33RQ | 2026.2.1 contains the fix | Does not stick |

## GHSA-F229-3862-4942 — NARROW (ai_hunk, topology, but-for, fix-reversal, release)

Identity PASS. Frozen advisory-database `GHSA-f229-3862-4942` is github-reviewed, not withdrawn, package `@enclave-vm/core`, repository `agentfront/enclave`, alias CVE-2026-27597. PoC is `{}[['__proto__']]` then constructor / `getOwnPropertyDescriptors`.

AI hunk FAIL. Squash `9e1a930cd8efa1c4b6fb699f79bba6b4889d1910` is single-parent `164bee43` and carries `Co-Authored-By: Claude Opus 4.6`. Cached PR #52 members show that trailer comes from `b4bd9b8e`, whose first-parent diff is only `libs/core/package.json` and `yarn.lock`. Human `4e2de7be` (no Claude) rewrites `disallowed-identifier.rule.ts` to blob `368fa4fe`, adds `tryGetArrayCoercedString`, and injects intrinsic Object neutralization in `vm-adapter.ts`. The squash rule blob equals `4e2de7be`. PR branding / squash-carrier transfer is not an atomic AI hunk.

Topology FAIL. Same member-to-squash transfer. Claude is a later co-author on an unrelated version align, not the security boundary.

But-for FAIL, including incomplete-remediation patch-delta. Parent / tag `v2.10.1` rule blob `bcbdd443` already walks Identifier and string Literal keys and the agentscript preset already lists `constructor`, `__proto__`, and `prototype`. Advisory `introduced:0` and `last_known_affected_version_range: <= 2.10.1` name that old hole. Human `4e2de7be` is an explicit security attempt that adds the exact array-coercion helper for `obj[['__proto__']]`. Removing Claude's package.json align does not shrink the GHSA PoC. `09afbebe` adds `coercion-utils.ts` `tryGetObjectCoercedString` for `{toString: () => 'x'}` / `valueOf`. That is an untouched sibling path, not an omitted case of the array helper. Rollback reopening the broader parent hole is not, by itself, incomplete-remediation causality.

Fix-reversal FAIL. `09afbebe` is a single-parent child of `1dd877c` and is the first-parent of `chore(release): v2.11.1`. It amends the identifier rule, but the named PoC is the array path already handled by `4e2de7be`. Advisory remediation says the issue has been fixed in **v2.11.0**.

Release FAIL as a countable vulnerable/fixed pair for incomplete rem. Annotated tags in `/home/hanqing/.cache/cve-analyzer/repos/agentfront_enclave`:

| Tag | Peel | `@enclave-vm/core` | 9e1a930 | 09afbebe | coercion-utils |
|-----|------|--------------------|---------|----------|----------------|
| v2.10.1 | `7a9b981e` | 2.10.1 | no | no | no |
| v2.11.0 | `1dd877c` | 2.11.0 | yes | no | no |
| v2.11.1 | `0ec916f` | 2.11.1 | yes | yes | yes |

`v2.11.0` did ship the attempt without `09afbebe`. First-party `last_known_affected <= 2.10.1` and “fixed in v2.11.0” still refuse that cut as the incomplete-rem vulnerable artifact.

Uniqueness PASS. Absent from canonical73, fp211 public cases, and live `scripts/publication_adjudications.json`. Prior commit-first row is UNKNOWN, not a counted KEEP.

## GHSA-33RQ-M5X2-FVGF — NARROW (ai_hunk, topology, but-for)

Identity PASS. Frozen advisory-database `GHSA-33rq-m5x2-fvgf` is github-reviewed, package `openclaw`, range `>= 2026.1.29, < 2026.2.1`, named closer `8c7901c9`, optional Twitch plugin `extensions/twitch/src/access-control.ts`.

AI hunk FAIL. Squash `f5c90f0e5c7a12285ceea6c3102666a7b904b16f` is single-parent `c5ffc11d` and carries Claude Sonnet 4.5 from member `0a99064a`. That member’s GitHub files list omits `access-control.ts`. Independent blobs:

| Spec | `access-control.ts` blob | Behavior |
|------|--------------------------|----------|
| ebf7dcc0 copy plugin files (human) | `cb0bed15` | `return { allowed: false, reason: "sender not in allowlist" }` |
| 9693933b wip type changes (human, Claude parent) | `cb0bed15` | same hard deny |
| 0a99064a Claude refactor | `cb0bed15` | Claude did not touch the file |
| f5c90f0e squash | `0ce86d78` | membership returns true; non-members fall through to default allow |
| 62e4ad23 2026.1.29 | `0ce86d78` | same fallthrough |
| 8c7901c9 fix | deny return inserted | `sender is not in allowFrom allowlist` |

Cached PR #1612 later human member `cf311730` is titled “adjust access control logic”. Original tests blob `77105d52` (unchanged through Claude) expect “blocks users not in the allowlist”. Squash tests blob `1200f72d` expect “allows users not in allowlist via fallback (open access)”. Mainline blame of the fallthrough onto the squash is carrier attribution.

Topology FAIL. Counting the squash as Claude origin of the fallthrough transfers authorship from human members.

But-for FAIL. Removing the Claude refactor leaves the human hard deny. The GHSA mechanism is the later human fallthrough, not the Claude refactor of other Twitch files.

Fix-reversal PASS. `8c7901c9` is single-parent `aa2eb48b`. First reverse `-S 'sender is not in allowFrom allowlist'` hit. First-parent inserts the deny immediately after the membership true-return and flips the fallback tests. That is the GHSA-named closer. A later inbound-allowlist commit `a47722de` is not first.

Release PASS as reconstructed containment, not as AI origin. `chore: release 2026.1.29` (`62e4ad23`) has `package.json` `openclaw` / `2026.1.29`, contains `f5c90f0e`, does not contain `8c7901c9`, and has the fallthrough blob. `chore: bump to 2026.2.1` (`85cd55e2`) has version `2026.2.1`, contains `8c7901c9`, and the deny lines blame `8c7901c9`. Clone has no tags; advisory names that range and `https://github.com/openclaw/openclaw/releases/tag/v2026.2.1`.

Uniqueness PASS. Absent from canonical73 and publication adjudications. Distinct from other OpenClaw allowlist identities. Prior commit-first row is UNKNOWN.

## Claim boundary

No worker or red-team proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical73 and does not support a more-than-200 claim. Shared tracked files, canonical snapshots, and the source worker directory were not edited. No commit or push. No credentials printed.
