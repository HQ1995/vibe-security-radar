# Unrecognized AI marker audit (729 no-pre-fix identities)

Routing only. This packet does not call a PASS and does not infer causality.
Canonical94 stays 94 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none. Matcher policy is not edited.

## Freeze

Pinned source nextqueue-v2 result SHA256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` report `36cfe74f595b57b6ff3cf891658e36554aa0b07a4160aea1e30af3ddc55f2380` replay `6da01d386cd5d42ee5f3e807902c6627a3bf6df5060592e5fba0be8f323ecbed`.
CONTRACT.md SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger SHA256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096` summary `c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b` strict 94.
The 13 exhausted no-pre-fix packets are the inventory prefix plus ranks 61-729. Their assignment union is 729 unique identities. Sorted-ID SHA256 `ffeceb62c6fa243e5865020390ba5de297d01ce3fc0ac1c9754f46d2739c63b1`. Packet counts 60x12+9=729. Overlap across packets 0. Duplicate IDs 0.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` committer 2026-08-14T03:33:36+00:00 tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No clone was retained. Anonymous public git only. Credential-like environment variables were stripped.

## Method

Starting population is exactly the 729 `no_pre_fix_ai_marker` identities already exhausted by the 13 packets. This packet does not substitute, pad, or add later identities.
For each identity, pre-fix history is the no-merge ancestors of the listed same-repo fix on fix-touched paths (cap 80), excluding the closer itself. Production `matches_for_commit` v3 is the miss oracle: a form is unrecognized only when that call returns empty.
Admitted evidence classes are complete attribution lines, exact vendor bot identities, and exact coauthor trailers. Filenames, prose mentions, PR branding, branch names, model guesses, and carrier trailer transfer are out.
A new pattern is proposed only when a first-party vendor source owns the exact form and a plausible earliest date exists. Commits are re-evaluated only under those admitted forms.

## Conservation

13-packet union unique IDs = 729. Expected hash holds.
729 = 3 defensible-form hits reviewed + 726 no defensible unmatched form.
3 = ROUTE 1 + REJECT_ROUTING 2 + UNREVIEWED 0 on the hit set.
Bucket equation 729=1+2+726. Assigned hits 3=3+0. Holds. Did not pad.
PASS=0. PASS_PROPOSAL=0. countable_pass=0. packet_delta=0.
CVE aliases are not counting units. Shared SHA is not identity dedupe.

## Defensible new forms (matcher v3 miss; first-party owned)

1. Complete attribution trailer `Made-with: Cursor`. Cursor Help documents Agent attribution as a `Made with Cursor` trailer (https://cursor.com/help/integrations/git). Cursor staff (deanrie, 2026-04-16) states IDE and CLI agents emit `Made-with: Cursor` (https://forum.cursor.com/t/fix-auto-commit-ammend-of-cursor-to-match-linux-kernel-recommendations/158177). Production verbs are Generated/Created/Written/Assisted only, so this complete line misses. Plausible earliest date 2026-03-01 (first hit in this freeze is 2026-03-02; help and staff notes are 2026). Help-page spacing `Made with Cursor` is the same vendor form and also misses; this freeze has 0 hits of that spelling.

2. OpenCode complete footer and coauthor as documented on first-party issues: generated-with markdown line pointing at https://opencode.ai plus `Co-Authored-By: opencode <noreply@opencode.ai>` (https://github.com/anomalyco/opencode/issues/558 created 2025-06-30; https://github.com/anomalyco/opencode/issues/786). Policy already has alias OpenCode and email `opencode@sst.dev`, but not this markdown footer and not `noreply@opencode.ai`. Plausible earliest date 2025-06-01 (policy OpenCode date; issue 558 is 2025-06-30). This freeze has 0 hits of those exact first-party strings.

## Rejected near-misses (not proposed)

- `Co-Authored-By: OpenCode <opencode@local>` on GHSA-387M-935M-C4VW `822d150d79c58a48b759aee73438d71a82431e01`. OpenCode is named, but `opencode@local` is not a vendor-owned address in first-party docs. Exact trailer without vendor email is not admitted.
- `Co-authored-by: coderabbitai[bot] <136622811+coderabbitai[bot]@users.noreply.github.com>` (GHSA-4GV9-MP8M-592R). The GitHub App exists and first-party review commands can commit autofix (https://docs.coderabbit.ai/reference/review-commands), but every hit here has a human author plus a review-bot trailer. That is carrier/suggestion transfer, not bot authorship of the GHSA hunk. No same-mechanism code overlap with CLI superuser privilege escalation.
- `Co-authored-by: codeflash-ai[bot] <148906541+codeflash-ai[bot]@users.noreply.github.com>` (same Langflow advisory). Marketplace app is a performance optimizer (https://github.com/marketplace/codeflash-ai). Human author, job-queue perf PR, not the GHSA mechanism.
- `dane-ai-mastra[bot]` author on GHSA-XH92-RQRQ-227V `9e4abde7cef33e3f5cb1e71bee70c6556ef394cd`. First-party GitHub App is Mastra platform deploy/PR automation (https://github.com/apps/dane-ai-mastra, https://mastra.ai/docs/mastra-platform/github). The commit is `chore(deps): update mastra` with zero overlap on `packages/mcp-docs-server/src/tools/docs.ts`.
- dependabot, renovate, github-actions, pre-commit-ci, allcontributors, and other non-coding-agent bots.
- Prose, docs, CHANGELOG-only overlap, and `windsurf` mentions in documentation.

Already-matched v3 forms that appeared in the same windows (Claude `noreply@anthropic.com`, Copilot / github-advanced-security trailers, gemini-code-assist login) are not unrecognized.

## Re-evaluation of defensible-form commits

Exact candidate SHAs with `Made-with: Cursor` on pre-fix history:

- `c4711a9b694938fbcc32b30ffd6b72576f0901fc` GHSA-CFVJ-7RX7-FC7C rank 330 repo=openclaw/openclaw. Single-parent. Ancestor of fix `17ede52a4be3034f6ec4b883ac6b81ad0101558a`. Overlap is CHANGELOG.md only. Advisory is sandbox media symlink traversal. Commit is Control UI POST routing. ai_hunk FAIL. but_for FAIL. REJECT_ROUTING.

- `2def22c85ea7a13cf5e9f682fef412774a184e8e` GHSA-4RC3-7J7W-M548 rank 549 repo=harttle/liquidjs. Single-parent. Ancestor of layout DoS fix `e2311dfd6e82f73509308aa8a3a1fafc92e226f0`. Files: README.md only. REJECT_ROUTING.

- `529dd67eeb6b125637623d6a723601f0938d3613` shared by GHSA-V273-448J-V4QJ rank 451 and GHSA-4RC3-7J7W-M548 rank 549. Shared SHA is not uniqueness. Subject: `fix: use realpath for fs.contains (#867)`. Single-parent. v3 matches empty.

GHSA-4RC3 mechanism is circular layout/block DoS (`src/tags/layout.ts`). Code overlap with this SHA is only `test/e2e/parse-and-render.spec.ts`. ai_hunk FAIL. REJECT_ROUTING.

GHSA-V273-448J-V4QJ advisory (CVE-2026-39859, CWE-22) names `src/fs/loader.ts` LookupType.Root skipping `contains()`, so `renderFile()` / `parseFile()` bypass configured `root`. Fix `f41c1fc02fe901598f3328118b42b13bc6bc9b04` (#870) removes that skip. Candidate `529dd67eeb6b` is an ancestor, overlaps `src/fs/loader.ts` and `src/fs/loader.spec.ts`, and is topology-atomic (one parent, not a merge carrier). Parent of `529dd67eeb6b` already passed `type !== LookupType.Root` into `candidates()`, so this SHA preserved the named skip while moving containment next to a realpath `contains()` change. It did not introduce the hole and did not close it. The GHSA closer #870 also carries `Made-with: Cursor`; closer attribution is not a pre-fix candidate. identity on the new form is exact. ai_hunk is same-file and same containment API, not but-for origin of the Root skip. but_for FAIL (revert would leave the skip). fix_reversal does not treat #867 as the introduced hole. Local tags containing the SHA: 0, so release stays UNKNOWN. uniqueness vs canonical94: PASS (absent). Seven-gate KEEP is not closed. ROUTE for matcher-form recall and leader review. Not a PASS.

## ROUTE IDs

GHSA-V273-448J-V4QJ

## Count boundary

No worker proposal changes the count (packet_delta=0). Current leader-accepted strict count is 94. This packet did not edit the matcher, canonical ledger, or any directory outside this packet. No commit or push. No PASS.

Stop.
