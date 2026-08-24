# GHSA-4C96-W8V2-P28J REJECT

**Verdict: REJECT.** Not AI_INCOMPLETE_REMEDIATION. Canonical84 stays 84. Packet delta 0. Worker PASS is not issued.

Identity uses the denoland/deno repository advisory, not the global advisory-database object. Title: command injection via incomplete shell metacharacter blocklist in node:child_process, bypass of CVE-2026-27190. Named affected versions v2.7.0 and v2.7.1, patched 2.7.2. Alias CVE-2026-32260. Not withdrawn. Prior first-party advisory is GHSA-HMH4-3XVX-Q5HR / CVE-2026-27190, official fix commit 9132ad95, release v2.6.8. Shared CVE/GHSA alias is one public case; the prior CVE is not counted separately.

## Gates

| Gate | Value | Proof |
|------|-------|-------|
| identity_gate | PASS | Unauthenticated repo advisory JSON sha256 1dbe8b84e85c417318ce4a26edabccae0729a8cb44853f55d221e393f8e3b184. |
| ai_hunk_gate | FAIL | Landed rem, residual, and closer are human Felipe Cardozo with no AI trailer in git messages. |
| topology_gate | PASS | 9132ad95, a29b955a, and b4d4a5bc are single-parent first-parent ancestors of the cited tags. Member 0393fdcd is not in the local clone and is not attributed. gh lists discarded. |
| but_for_gate | FAIL | Claude-marked 43deeb2c is spawnSync timeout/pid, not the $VAR quoting residual, and is not an ancestor of v2.7.0-v2.7.2. |
| fix_reversal_gate | FAIL | Closer b4d4a5bc amends human quoting, not an AI hunk. It does not reverse 43deeb2c. |
| release_gate | PASS | Git commit tags v2.7.0=fb4db333 and v2.7.1=1df618d9 share file blob 3c7661a8 with the residual. v2.7.2=83e37468 file blob b3bda553 equals closer b4d4a5bc. GitHub Releases API was not used. |
| uniqueness_gate | PASS | Absent from canonical84 strict 84. Distinct from GHSA-HMH4. |

## Human attribution (git objects)

- Prior 27190 rem: 9132ad95 Felipe Cardozo, subject `fix(ext/node): escape more shell args (#31999)`, parent b51441cc, first-parent of v2.6.8, absent from v2.6.7.
- Residual quoting: a29b955a Felipe Cardozo, subject `fix(ext/node): enable test-stdio-closed tests (#32237)`, first-parent of v2.7.0. Introduces POSIX `$VAR` double quotes at the GHSA-named site.
- Closer: b4d4a5bc Felipe Cardozo, subject `fix:(ext/node): escape simple quotes in node:child_process (#32336)`, first-parent of v2.7.2, not an ancestor of v2.7.1. Adds `unsafeInDoubleQuotes` so backticks are not double-quoted.

## AI routing SHA (not causal)

43deeb2c author email biwanczuk@gmail.com, trailer `Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`, subject timeout/killSignal/pid for spawnSync (#32810). Not an ancestor of v2.7.0, v2.7.1, or v2.7.2. File overlap is routing only.

## Credential boundary

gh was invoked for PR commit lists. Those lists are routing only. Replay does not call gh and does not require credentials. Unauthenticated HTML Copilot strings are Primer chrome, not authorship.

selected.jsonl is omitted because all seven gates are not PASS.
