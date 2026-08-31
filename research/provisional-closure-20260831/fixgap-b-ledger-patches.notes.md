# Canonical fix-data closure: GH4H and WXHM

This packet restores direct-fix code evidence for two published cases. It does not change their causal verdicts or case count.

## GHSA-GH4H-34GR-87R7

- Canonical class: `alias-226bc664b77d22042b6f4336`; expected live revision: 2.
- Local primary clone: `.ai-slop/state/repos/budibase_budibase`.
- Candidate `700ff33db7470d4d2dd9674e9e29dc5e6392daa4` adds SSO `accessToken` and `refreshToken` to `getUserContextBindings`; its message contains both the Claude Code generation marker and Claude co-author trailer.
- Direct fix `bca426de7dc36d680285295655dc640dea2aab21` adds `sanitizeAutomationTestResult`, applies it before return/cache/WebSocket broadcast, and isolates cached test progress by user ID. `git merge-base --is-ancestor ... 3.39.25` exits 0.
- Primary URLs: https://github.com/budibase/budibase/commit/700ff33db7470d4d2dd9674e9e29dc5e6392daa4 and https://github.com/budibase/budibase/commit/bca426de7dc36d680285295655dc640dea2aab21.

## GHSA-WXHM-2MQ7-7697

- Canonical class: `alias-0ae0a984e1b1218e180ef355`; expected live revision: 2.
- Local primary clone: `.ai-slop/state/repos/microsoft_prompty`.
- Candidate `a0e6108842a3bfc840a33db819a4415fbdac333d` adds the TypeScript `${file:...}` loader and reads `resolve(agentDir, val)` without a root boundary; its commit has the Copilot co-author trailer.
- Direct fix `88ac9948d7d37995edbb2f6d36913436626c39e1` establishes canonical allowed roots, rejects lexical escape, then rechecks `realpathSync` to stop symlink escape. It is an ancestor of `typescript/2.0.0-beta.2`.
- Primary URLs: https://github.com/microsoft/prompty/commit/a0e6108842a3bfc840a33db819a4415fbdac333d and https://github.com/microsoft/prompty/commit/88ac9948d7d37995edbb2f6d36913436626c39e1.

## Validation

- Both JSONL lines parse with `json.loads`.
- Each row is the complete live row plus canonical candidate/fix/release/code-evidence fields.
- `scripts.ledger_store.validate_update` accepts both rows against the current live revisions.
- Every displayed hunk has public prose, a valid unified-diff count, role-specific anchors, source URLs, and deterministic SHA-256 over the newline-joined hunk text.
