# Hostile review: GHSA-Q9J6-XCVX-PX63

**NARROW.** Countable PASS remains 0. Packet delta 0. Canonical94 stays **94 HOLD**.

This is an independent hostile review of hypothesized pairing candidate `bbb2aa9ad4e0c14517d32272b5e6d83318fde493`, carrier merge `4d4254b591ede243b38df7b678cf36619cb25825`, and purported minimum fix set [`48ba4ece3c1b43cb4b9627438c0ff4e4251e3511`, `f267a28cb2badc7e712c4592af4d79d090fe5063`] for coollabsio/coolify GetLogs command injection, alias CVE-2026-34599. nearpass-next10 and nearclosed-g are routing only. Inherited PASS labels are not proof. Worker PASS is proposal only; this packet emits none. Exact seven PASS is required for PASS_PROPOSAL.

Conservation: assigned=1, reviewed=1, unreviewed=0. Equation `1=1+0`.

Network evidence used anonymous public git, GitHub HTML, and tag tarballs only after a clean process environment. Credential-bearing variables are unset and never printed. Anonymous failure is BLOCKED; credentials are not used as a fallback.

## Identity (first-party)

Published repository advisory GHSA-q9j6-xcvx-px63 names coollabsio/coolify, CWE-78 OS command injection in the GetLogs Livewire component, and formal alias CVE-2026-34599. Title: Authenticated Remote Code Execution in GetLogs Livewire Component. State published; withdrawn_at absent. Package ecosystem composer / name coollabsio/coolify, range `<= 4.0.0-beta.470`, patched `4.0.0-beta.471`. PoC posts Livewire method `getLogs` and returns output in `$outputs`. Recommended fix is `#[Locked]` on `$container`, container-name validation, and server ownership. The advisory lists interpolation line numbers 136, 143, 152, 159, 203, 205, 209, 211 against the v4.0.0-beta.470 GetLogs.php blob; it does not name `downloadAllLogs`. github/advisories/GHSA-q9j6-xcvx-px63 is HTTP 404. github-reviewed advisory-database JSON is HTTP 404. OSV API is HTTP 404. Identity uses the repository advisory. Normalized identity SHA256 `8212cc1cca6f67e2218d9763ce844265baea6aead463c212d040b20e3c9c4c8e`.

identity_gate: PASS.

## Topology and AI marker

`bbb2aa9a` is single-parent onto `b484c0cc`. Author and committer are Claude `<noreply@anthropic.com>`. Subject: feat(logs): Add dropdown to download displayed or all logs. Tree `c1d07534`. GetLogs.php 44 insertions; the only new method is `downloadAllLogs`. `getLogs()` is byte-identical to the parent. No Co-Authored-By trailer; the AI marker is the author identity.

Carrier `4d4254b5` is merge `8be1a9b5` + `bbb2aa9a`, subject `claude fix test (#7825)`, author Andras Bacsai, no Claude trailer. Authorship stays on the member.

Follow-up `a980fd46` (Co-Authored-By Claude Haiku 4.5) is a direct child of the candidate and rewrites downloadAllLogs accumulation/size limits. Its GetLogs.php blob `22605e1b` equals v4.0.0-beta.468/469/470. Do not transfer candidate authorship onto `a980fd46`.

Fix member `48ba4ece` is Co-Authored-By Claude Opus 4.6. AI-on-fix is not origin. Merge `f267a28c` (PR #9229) parents `7b3b6fa6` + `b3256d4d`; `48ba4ece` is an ancestor of the second parent, not of the first. Second parent subject is `fix(security): harden model assignment and sensitive data handling`. Diff versus first parent is 27 paths, including GetLogs.php plus unrelated models/API controllers/tests.

topology_gate: PASS. ai_hunk_gate: PASS for the downloadAllLogs hunk only. That hunk is not the advisory PoC method.

## But-for (hostile)

The exact advisory mechanism is unlocked `$container` interpolated into `docker logs` / `docker service logs` inside `getLogs()`, with no authorization and output in `$outputs`. Parent `b484c0cc` already has `public ?string $container = null` without `#[Locked]`, already interpolates that property in `getLogs()`, and already lacks `ownedByCurrentTeam`. Parent of that parent `b7e0f557` already interpolates. Blame of the getLogs interpolation at the candidate parent is human Andras Bacsai (`fe22dfc5`, 2024-05-02). The `$container` property itself is human (`97027875`, 2023-10-02). Parent Claude commit `b484c0cc` only removed a display-line cap; it did not introduce interpolation.

Candidate vs parent: `getLogs`, `copyLogs`, `mount`, and the unlocked `$container` property are unchanged. Removing `downloadAllLogs` leaves the advisory PoC (`method: getLogs`) intact. `downloadAllLogs` copies the same interpolation into a second Livewire method. The 470 line numbers 203/205/209/211 are those copied sites after `a980fd46`; the advisory still names `getLogs` as the PoC and does not name `downloadAllLogs`. Copying an old bug into a sibling sink does not materially shrink the scoped mechanism. This is not incomplete remediation: the candidate is a download-all feature, not a security boundary rewrite.

but_for_gate: NARROW.

## Fix reversal (hostile)

Closer member `48ba4ece` adds `#[Locked]` on resource/servicesubtype/server/container, validates names, and authorizes both `getLogs` and `downloadAllLogs`. GetLogs.php blob `d0121bdc` equals merge `f267a28c` and equals v4.0.0-beta.471. That blob still interpolates `$this->container` in both methods; the lock is on the shared property, which is the parent getLogs invariant. Blade at 471 still calls `$wire.downloadAllLogs()`. Tests cover both methods, but the test blob is not stable: `48ba4ece` `34824b48`, `f267a28c` `3e5a33b6`, v4.0.0-beta.471 `c0b17c3b`. Merge `f267a28c` also lands unrelated model/API hardening from `b3256d4d`. The GetLogs reversal is `48ba4ece` alone; the purported two-SHA minimum set is not minimum and is not a candidate-only reversal. Parent getLogs remains the primary closer target.

fix_reversal_gate: NARROW.

## Release

GitHub Releases `v4.0.0-beta.470` and `v4.0.0-beta.471` exist (`released this`). Lightweight tags peel to `575b0766d12bad2a78febff72ab59c017772bcf7` and `914d7e0b50505bc1fd56c34974fca09ad354e92a`. Anonymous `git ls-remote` matches those peels. Codeload tag tarballs: 470 GetLogs.php git blob `22605e1b` has `downloadAllLogs`, no `#[Locked]`, no `ownedByCurrentTeam`; 471 GetLogs.php git blob `d0121bdc` has `#[Locked]` and `ownedByCurrentTeam`. Candidate and carrier are ancestors of 470; neither closer is. Both closers are ancestors of 471 via 471 second parent `ffb5045c`.

release_gate: PASS. Release pairing does not make the candidate causal.

## Uniqueness

GHSA-Q9J6 is absent from canonical94 strict 94. The only counted coolify case is GHSA-X9QH-W4C4-54F9 (`coolify.buildHelperImage.dev_helper_version.unescaped_docker_build_shell`), a different mechanism. CVE-2026-34599 is a formal alias, not a second case.

uniqueness_gate: PASS.

## Claim boundary

Five gates close on independent git/advisory/release evidence. but_for_gate and fix_reversal_gate stay NARROW. seven_gates_exact_pass is false. Verdict NARROW, not PASS_PROPOSAL. Canonical94 is untouched. Publication and more-than-200 stay HOLD.
