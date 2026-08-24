# CF3 reversal5 independent but-for / fix-reversal closure

Verdict-first: **0 PASS_PROPOSAL**. All five remaining foundation identities are **REJECT**. Conservation **5=5+0**. Canonical88 strict count remains **88**. Publication **HOLD**. Worker PASS is proposal-only; this packet emits none.

Nextqueue/nearpass rows were routing hypotheses only. Canonical88 and current cf3 (confirm5/release6/singlegate5/topology3) are exclusion/authority. A case is PASS_PROPOSAL only with all seven exact PASS, an exact AI-authored hunk or distinct new released surface, a scoped but-for, and an official closer that reverses that same mechanism rather than a sibling. Fatal fail is REJECT.

| Order | ID | Repo | Fatal fail |
|---|---|---|---|
| 1 | GHSA-42M6-XH7C-6XM4 | steipete/codexbar | AI providers are not ProviderHTTPClient; closer hardens the human transport |
| 2 | GHSA-HFF7-CCV5-52F8 | openclaw/openclaw | /v1/responses is a new caller of parent Tailscale HTTP; closer scopes the helper |
| 3 | GHSA-HHFF-FJ5F-QG48 | openclaw/openclaw | content_type rename is not the member-before-preflight order; closer reorders a parent check |
| 4 | GHSA-Q6QF-4P5J-R25G | openclaw/openclaw | assigned SHA does not add workspaceOnly; closer adds the parent guard |
| 5 | GHSA-W4H3-GPV2-82QC | openclaw/openclaw | assigned images.ts has no file://; closers harden a later/sibling seam |

## GHSA-42M6-XH7C-6XM4

Identity NARROW: unreviewed GHSA, empty affected.

AI hunk / but-for / fix-reversal FAIL: Claude OpenRouter/DeepSeek/Kimi commits never add `ProviderHTTPClient.swift`. Human `f62bb8c8` added that transport. Closer `08c171b6` guards credentialed redirects on that file. Removing the AI providers leaves the named sink. Topology PASS (atomic ancestors). Release PASS: v0.32.0 contains candidates without the closer; v0.33.0 contains the closer. Uniqueness PASS: not in canonical88 strict 88.

## GHSA-HFF7-CCV5-52F8

Identity PASS: github-reviewed first-party GHSA.

AI hunk / but-for / fix-reversal FAIL: `f4b03599` adds `/v1/responses` calling parent `authorizeGatewayConnect`. Parent `openai-http.ts` already had that call. Closer `356d61aa` defaults Tailscale header auth off in `auth.ts`; it does not amend `openresponses-http.ts`. Deleting the AI route leaves Chat Completions HTTP on the helper. Topology PASS. Release PASS: v2026.2.19 vs v2026.2.21. Uniqueness PASS.

## GHSA-HHFF-FJ5F-QG48

Identity PASS: github-reviewed first-party GHSA.

AI hunk / but-for / fix-reversal FAIL: parent already transcribes audio before `resolveDiscordMemberAccessState`. `b9b47f50` only renames `contentType` to `content_type`. Closer `ee52f642` moves the member allowlist before transcription. That reverses parent ordering, not the AI property hunk. Topology PASS (atomic ancestor). Release PASS: v2026.3.28 vs v2026.3.31. Uniqueness PASS.

## GHSA-Q6QF-4P5J-R25G

Identity PASS: github-reviewed first-party GHSA.

AI hunk / but-for / fix-reversal FAIL: `8d74578c` keeps the image tool available for vision primaries and adds native injection. Parent and candidate `image-tool.ts` both lack `workspaceOnly`. Closer `dd9d9c1c` adds that guard. The GHSA-named sandbox bypass is pre-AI. Topology PASS. Release PASS: v2026.2.22 vs v2026.2.23. Uniqueness PASS: distinct from GHSA-W4H3 despite the shared SHA.

## GHSA-W4H3-GPV2-82QC

Identity NARROW: unreviewed GHSA; first reference is GHSA-h3x4-hc5v-v2gm (cross-bound).

AI hunk / but-for / fix-reversal FAIL: assigned `8d74578c` adds `images.ts` with zero `fileURLToPath` / `file://` hits. Later `8c0e290` adds file URL detection. Closers `4fd7feb0` / `93880717` add `safeFileURLToPath` and sibling media-loader guards. Those reverse a later/sibling seam, not the assigned hunk. Topology PASS. Release PASS: v2026.3.13-1 vs v2026.3.22. Uniqueness PASS: distinct from GHSA-Q6QF.

## Hygiene

No durable pages, clones, packages, or caches in this directory. Existing clones were read-only. Replay is fail-closed and drops only the known harmless `error: unable to normalize alternate object path:` line if a clone emits it; any other git stderr fails. No credentials. No GitHub REST/GraphQL. No edits outside the owned directory. No commit or push. ASCII English only.
