# Independent hostile review of GHSA-H2V8-4C3F-VQGV and GHSA-G8MR-85JM-7XHM

Verdict first: **2 causal PASS_PROPOSAL**. Countable seven-gate PASS=0. Canonical88 stays 88.
Assigned 2. Reviewed 2. Unreviewed 0. Equation 2=2+0.
Publication and more-than-200 stay HOLD.

Inherited CF4-b2, h2v8-release-closure, and confirm11-closure verdicts were not copied. Both rows were rebuilt from first-party advisory objects and local git. Release remains a separate gate. A causal-only PASS proposal requires all six causal gates exact PASS.

## GHSA-H2V8-4C3F-VQGV

Repository brentmid/evernote-mcp-server. Class AI_DIRECT_ROOT. Causal six PASS. release_gate UNKNOWN. Causal PASS_PROPOSAL. Not countable.

1. identity_gate PASS. Unreviewed GHSA-h2v8-4c3f-vqgv aliases CVE-2025-12489, names evernote-mcp-server openBrowser command injection, and references first-party commit 1e66c78c. No github-reviewed collision at advisory-database HEAD 39d888. Empty affected[] is the unreviewed import shape, not a second repo.

2. ai_hunk_gate PASS. Candidate e08547bcdb42aaa86190c6e2dfc64159fcd3a146 is atomic (parent 9f7c1b36d698845ea8bd968ad7446550995a2a3d). Parent has no auth.js. Candidate adds `exec(\`${command} "${url}"\`)`. Marker: Generated with Claude Code and Co-Authored-By: Claude <noreply@anthropic.com>.

3. topology_gate PASS. n_parents=1. No carrier. Blame at the fix parent still attributes the exec interpolation to e08547bc. Intermediate auth.js commits keep that interpolation. Closer 1e66c78c is Claude-marked and is the reversal.

4. but_for_gate PASS. Removing the candidate removes auth.js. Path: authenticate -> getRequestToken oauth_token -> redirectToAuthorization concatenates `?oauth_token=` with no encoding -> openBrowser -> exec shell text. The closer documents oauth_token="; touch /tmp/pwned #.

5. fix_reversal_gate PASS. 1e66c78c4ce6ea294ac6b0eb289a9eae9c5e9579 rewrites openBrowser from exec interpolation to spawn(command, args). Tests follow. Exact reverse.

6. uniqueness_gate PASS. Absent from canonical88 strict 88. Distinct from GHSA-G8MR-85JM-7XHM.

7. release_gate UNKNOWN (separate). brentmid shipped no discoverable artifact. Local and origin git tags are empty. GitHub tags and releases APIs return []. npm evernote-mcp-server is yasuhiroki 0.0.2/0.0.3 (tarball sha256 f3caba45... / 098f5a1d...; src/*.mjs; no auth.js). Scoped npm, PyPI, and Docker Hub 404. GHCR unauthenticated list is UNAUTHORIZED, not a public image. package.json versions and Dockerfile git clones are not registry artifacts.

## GHSA-G8MR-85JM-7XHM

Repository vitest-dev/vitest. Class AI_INCOMPLETE_REMEDIATION. Causal six PASS. release_gate NARROW. Causal PASS_PROPOSAL. Not countable.

Two mechanisms must not be mixed. The older ungated CDP hole is sendCdpEvent with no allowWrite flags (parent blob 7619c5f0, shipped as v3.2.4). The AI residual is Codex backport af88b1f5 adding allowWrite/allowExec/canWrite while leaving sendCdpEvent ungated, then closer 385a1aef adding isCdpAllowed/assertCdpAllowed. Independent `git log v3.2.4..v3.2.5 -- packages/browser/src/node/rpc.ts` yields exactly those two commits.

1. identity_gate PASS. github-reviewed GHSA-g8mr-85jm-7xhm aliases CVE-2026-53633, names Browser Mode CDP not gated by allowWrite/allowExec, and binds @vitest/browser 3.x last-known-affected <=3.2.4 patched 3.2.5.

2. ai_hunk_gate PASS. Atomic af88b1f5d82844a4761ea9a977156c98e2b14ca8, parent 5a7d56e2235d63441a23c54dc85ecffcbfe7cf44, Co-authored-by: Codex <noreply@openai.com>. Parent has sendCdpEvent and zero allowWrite. Candidate adds canWrite and leaves CDP ungated.

3. topology_gate PASS. n_parents=1. No carrier. Fix 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7 parent is the candidate. Mainline closer 63e3b2ee and v4 closer e4067b3b are other-line, not this row's minimum_fix_set.

4. but_for_gate PASS under incomplete-remediation patch-delta. The AI commit authors the allowWrite/allowExec boundary and omits CDP. The GHSA names that residual. Reverting only 385a1aef reopens ungated sendCdpEvent while canWrite remains. v3.2.4 is not this residual.

5. fix_reversal_gate PASS. 385a1aef wraps sendCdpEvent and trackCdpEvent with assertCdpAllowed using the same flags.

6. uniqueness_gate PASS. Absent from canonical88 strict 88. Ledger rows for this id are counted=false PRESERVE. Distinct from the pre-AI CDP hole.

7. release_gate NARROW (separate). Every v3.2.4/v3.2.5 artifact tested. Tag v3.2.4 peel c666d149: candidate not ancestor; rpc.ts blob equals parent; npm @vitest/browser@3.2.4 sha256 a24c6ade... has sendCdpEvent and no allowWrite/isCdpAllowed. Tag v3.2.5 peel 2cbad0a9: contains candidate and closer; rpc.ts blob equals the fix; npm @vitest/browser@3.2.5 sha256 0f4e1678... has allowWrite, canWrite, isCdpAllowed, and assertCdpAllowed. npm vitest@3.2.4/@3.2.5 are not the CDP RPC package. Same-first-tag: no published v3 artifact contains the Codex backport without the CDP closer.

## Claim boundary

Worker PASS is proposal only. This packet emits two causal-only PASS proposals and zero countable PASS. Prefer no seven-gate PASS over treating yasuhiroki npm, version strings, the older ungated CDP hole, or v3.2.5 (already the closer) as AI residual containment. Canonical88 was read, hashed, and not edited.

Status TERMINAL. No canonical edit. No commit. No push. No padding.
