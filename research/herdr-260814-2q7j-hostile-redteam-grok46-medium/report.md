# Hostile red-team: GHSA-2Q7J-2VHX-56G8

**REJECT.** Countable PASS remains 0. Packet delta 0. Canonical91 stays **91 HOLD**.

This is an independent hostile review of the hypothesis that atomic Claude commit `5f6e1c19bd18ea45addd3afedf2f88cc3064f3f6` created the per-account Feishu tools merge/first-account gate named by GHSA-2q7j, and that closer `d4f11d3005a56abc709ebc8e715972593ebed96e` reversed that same invariant in `v2026.6.9`. nearclosed-m is routing only and is not evidence. Worker PASS is proposal only; this packet emits none. This packet does not admit the row, does not rebuild canonical91, and does not support a greater-than-200 claim.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

## Identity (first-party)

Repo advisory GHSA-2q7j-2vhx-56g8 on openclaw/openclaw is published, not withdrawn, severity high, `cve_id` null. Summary: Feishu tools could ignore per-account disablement. npm `@openclaw/feishu` vulnerable `<= 2026.6.6`, patched `2026.6.9`. Global catalog 404 for this GHSA id. CVE-2026-62187 is a stored CNA object GHSA-mm88-h44m-w2gp and is not a formal alias of 2q7j. Sibling repo advisory GHSA-w8wf-3qvj-6xqf names permission tools, not this identity.

identity_gate: PASS.

## Topology and AI marker

`5f6e1c19` is single-parent onto `7e005acd`. Trailer: Co-Authored-By Claude Opus 4.5. It first adds `mergeFeishuAccountConfig` on `extensions/feishu/src/accounts.ts` after the community-plugin tree, and it switches docx/drive/wiki/perm registration to `resolveToolsConfig(firstAccount.config.tools)`. Execute still calls `createFeishuClient(firstAccount)`.

Human `0223416c` already had `{ ...base, ...account }` merge in `src/feishu/accounts.ts` with no AI marker. Claude `2267d58a` (counted elsewhere for sendMedia/allowFrom, not transferred here) removed that merge. Human `125dc322` (Peter Steinberger, no AI trailer) adds `tool-account.ts` and is an ancestor of `v2026.6.6` and of the closer. Closer `d4f11d30` is unmarked GitHub squash `#93363`.

topology_gate: PASS for this graph. No member is transferred onto `5f6e1c19`.

## Why the hypothesized pairing fails

Parent `7e005acd` already called `resolveToolsConfig(feishuCfg.tools)` on the same four families. That is an older global sibling, not per-account disablement.

At `5f6e1c19`, tools always execute as the first account. That is not ignore-disablement of a later resolved account.

At `v2026.6.6` peel `8c802aa6` / npm 2026.6.6 sha256 `73a2c688...`, docx/drive/wiki/perm no longer use `firstAccount.config.tools`. Registration uses `resolveAnyEnabledFeishuToolsConfig` (OR across accounts). Execute uses `createFeishuToolClient` without `requiredTool`. `tool-account.ts` blob `e6d35aff` equals the closer parent `62563c2c`, not the AI commit. Human `125dc322` introduced that file (blob `72b5db9b` then later evolved).

Closer `d4f11d30` adds `requiredTool` on the resolved account. Fixed tag `v2026.6.9` peel `c645ec45` / npm 2026.6.9 sha256 `05610347...` contains that throw. `chat.ts` still uses `firstAccount.config.tools` after the closer. Merge is not reversed.

ai_hunk_gate: FAIL (relevant released hunk is human `tool-account.ts`).
but_for_gate: FAIL (advisory-named surface is the later human execute path; parent global tools and 0223416 merge remain as older siblings).
fix_reversal_gate: FAIL (closer does not reverse the AI first-account gate).
release_gate: FAIL (named vulnerable artifact does not contain the AI first-account docx/drive/wiki/perm gate).

## Uniqueness

GHSA-2Q7J is absent from canonical91 strict 91. Counted Feishu rows GHSA-8JPQ and GHSA-J4XF are different mechanisms on `2267d58a`. GHSA-W8WF is a distinct unpublished-to-canonical sibling. Shared closer SHA is not duplication.

uniqueness_gate: PASS.

## Claim boundary

No red-team REJECT or proposal changes the count. Only leader-reviewed rows with all seven gates PASS enter the strict released lower bound. This packet does not rebuild canonical91. Publication and more-than-200 stay HOLD.
