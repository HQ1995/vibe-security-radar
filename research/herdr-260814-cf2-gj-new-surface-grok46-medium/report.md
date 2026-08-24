# CF2 G-J new-surface packet (proposal only)

Verdict: **0 PASS_PROPOSAL / 40 REJECT / TERMINAL**. Canonical85 stays 85. Greater-than-200 remains unsupported.

This worker inspected 40 net-new first-party G-J identities from the unreviewed remainder of `herdr-260813-ghsa200-commitfirst-gj-grok46-medium`. Selection was the remaining origin-rank slice after excluding the source shard's 30 terminal rows, canonical85 identities, and canvas foundation identities. Origin-rank leftover rows are file-history routing only (zero blamed lines). Mining looked for atomic AI commits that add a GHSA-specific entrypoint or a new caller to an older unsafe helper. None closed all seven gates.

## Counterevidence classes

Highest-signal unique-repo rows failed as sibling same-file rewrites, not new-surface causality:

- GHSA-GJQQ-6R35-W3R8 (Arcane): Copilot `75fc5f06` adds updater notifications. Lifecycle command-injection hooks are human `24b03c4f`; closer `5a9c2f92` deletes those hooks.
- GHSA-M3C2-496V-CW3V (Fiber static Windows): routing intro is a Gemini-review-bot trailer on a net/http adapter feat that never touches `sanitizePath`. Advisory closer is 2026-02-08. Later Copilot static-traversal work is after the closer.
- GHSA-F45Q / GHSA-QQC3 (Hubuum): Claude identity/remote-target feat is not the reqwest redirect/transport policy the two advisories close. Shared SHA is routing only.
- GHSA-M77W (OpenClaude): Claude null-shell-output security-review is not `dangerouslyDisableSandbox`.
- GHSA-JPCW (kin-openapi): Claude `encoding.contentType` helper is not the `mt.Schema == nil` panic.
- GHSA-QGQ7 (go-git): Claude-assisted `Module()` submodule containment is a sibling of `validReferenceName` disguised-`..` (same file, different boundary). Incomplete-remediation patch-delta fails.
- GHSA-VXGM (Hugo): Claude `@` userinfo deny rewrite is not redirect re-check against `security.http.urls`.
- GHSA-Q5PR (h3): Claude `getValidatedCookies` never calls `getChunkedCookieCount`. Unbounded parse is human `61b395e3`.
- GHSA-7CFQ (Inspektor Gadget): Copilot USDT size-cap commit is not an ancestor of advisory merge `ec69da2e`.
- GHSA-94PJ (Guzzle): QUERY redirect middleware is not Curl `Proxy-Authorization` origin leakage; `codexofc` is not an AI co-author class.

Gogs changelog hits and Gitea shared `DEFAULT_TITLE_SOURCE` / merge-tree intros are repeated file-history routing across unrelated identities. An advisory-listed closer is not an origin. An AI-marked squash or review-bot trailer does not transfer authorship.

## Conservation

- Origin-rank rows 94; source-shard already reviewed 30; remaining eligible 64; this packet froze 40; reviewed 40; PASS_PROPOSAL 0.
- Equation: 40 = 40 + 0. No padding. No GitHub REST/GraphQL. No full clones. No edits outside this owned directory.

Worker PASS would have been proposal only. This packet emits none.
