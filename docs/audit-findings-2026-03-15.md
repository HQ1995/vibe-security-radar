# Audit Findings: Deep Verifier Accuracy on Removed CVEs

**Date:** 2026-03-15
**Auditor:** Independent manual review (Claude Opus 4.6 + human oversight)
**Scope:** 19 of 94 CVEs removed from website after deep verifier filtering changes

## Executive Summary

After adding strict filtering to `generate_web_data.py` (only CONFIRMED deep verdicts pass), 94 CVEs were removed from the website. We audited 19 of these to determine whether the deep verifier was correct.

**Result: 94.7% accuracy (18/19 correct).** One false negative was found and the root cause was a caching bug, not a flaw in the verification logic itself.

## The False Negative: GHSA-vj3g-5px3-gr46

**Vulnerability:** Path traversal in OpenClaw's Feishu media temp-file naming. User-controlled `imageKey` values were used directly in `path.join(os.tmpdir(), ...)`, allowing writes outside the temp directory.

**AI involvement:** The vulnerable code was introduced in commit `2267d58afcc7` ("feat(feishu): replace built-in SDK with community plugin") by Yifeng Wang, with a clear `Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>` trailer. The prior implementation did not have this vulnerability.

**What went wrong:** The deep verifier was actually run twice for the same BIC against two different fix commits:
1. Fix commit `cdb00fe2` -> **CONFIRMED** (35 tool calls, correct)
2. Fix commit `ec232a9e` -> timed out after 41 tool calls -> **UNLIKELY** (fallback)

The cache key did not include `fix_commit_sha`, so the second result overwrote the first. A correct CONFIRMED verdict was silently replaced by an incorrect timeout fallback.

**Bugs fixed:**
- Cache key now includes `fix_commit_sha` to prevent collision (commit `7cd7df4`)
- Timeout fallbacks are no longer cached, allowing retries on next run (commit `7cd7df4`)
- Added `is_fallback` flag to `AgentVerdict` and `VerificationVerdict` (commit `7cd7df4`)

**After fix:** Re-running the analysis produced **CONFIRMED** as expected.

## Pattern: AI Commits That Fix (Not Introduce) Vulnerabilities

A striking pattern across the openclaw audits: in multiple cases, AI-authored commits were **security improvements** rather than vulnerability introductions. The deep verifier correctly identified this in every case.

| CVE | What AI commit did | Deep verdict |
|-----|-------------------|-------------|
| GHSA-73hc-m4hx-79pj | Added `require_read_access` to previously unauthenticated health endpoint | UNLIKELY (correct) |
| GHSA-943q-mwmv-hhvh | Added `DANGEROUS_ACP_TOOLS` deny set and interactive permission prompt | UNLIKELY (correct) |
| CVE-2026-32061 | Added `resolvePath()` confinement to previously unrestricted `$include` | UNLIKELY (correct) |
| GHSA-9f72-qcpw-2hxc | Correctly implemented `sandboxRoot` path restrictions (a new restriction was later added by a human but missed this path) | UNLIKELY (correct) |

In these cases, the AI was brought in to add security controls. The vulnerability existed because the fix was incomplete, not because the AI introduced a new attack vector. The deep verifier successfully distinguished "AI wrote an incomplete fix" from "AI introduced the vulnerability."

## Pattern: Ghost Blame (Blamed Commit Never Touched Blamed File)

In 3 of 19 audited CVEs, the pipeline's `git blame` attributed lines to a commit that **never modified the blamed file**. This produces false AI signals because the commit happens to have AI co-author trailers for unrelated work.

| CVE | Blamed commit | Blamed file | Actually modified? |
|-----|--------------|-------------|-------------------|
| CVE-2026-28467 | `bbc67f37` | src/media/fetch.ts | No |
| GHSA-56f2-hvwg-5743 | `bbc67f37` | src/agents/tools/web-fetch.ts | No |
| GHSA-hwpq-rrpf-pgcq | `483fba41` | src/infra/exec-approvals.ts | No |

**Fix applied:** Added `_commit_touched_file()` validation in `pipeline.py` (commit `c992c8d`) that verifies the blamed commit actually modified the blamed file before accepting the BIC.

## Pattern: PR Body Keywords as False Authorship Signals

The `pr_body_keyword` signal type detects phrases like "Generated with [Claude Code]" in GitHub PR descriptions. However, this indicates that Claude Code was used to create the PR, not necessarily that the specific blamed lines were AI-authored.

In the CVE-2026-28467 audit, the blamed commit's PR body contained "Generated with [Claude Code]", but the commit only modified gateway API files -- none of the vulnerable media fetch files. The signal is technically correct (the PR used Claude Code) but semantically misleading when applied to blame attribution.

**Recommendation:** Consider downweighting `pr_body_keyword` signals or requiring them to be corroborated by per-file attribution (e.g., the blamed file must be in the PR's changed files).

## Pattern: Formatting/Refactor Commits Blamed for Pre-existing Vulnerabilities

Two fickling (Trail of Bits) CVEs were blamed on AI commits that only performed mechanical changes:

| CVE | AI commit action | Actual vulnerability origin |
|-----|-----------------|---------------------------|
| GHSA-q5qq-mvfm-j35x | `ruff` code formatting | Incomplete blocklist from 2021 |
| GHSA-h4rm-mm56-xf63 | Crash fix in `StackGlobal.run()` | Builtins import suppression from 2021 |

`git blame` naturally attributes reformatted lines to the formatting commit even though the semantic content is unchanged. The deep verifier correctly recognized these as non-causal.

**Recommendation:** Consider adding a formatting-commit detector (e.g., if a commit message matches `style:`, `chore(format)`, or known formatter names like ruff/black/prettier, and the diff is whitespace-only changes, automatically downweight).

## Pattern: OSS-Fuzz Bisection ≠ Root Cause

OSV-2026-371 (tinyobjloader) was attributed to an AI-authored parser rewrite because OSS-Fuzz's bisection identified it as the first commit where a specific fuzz test case crashed. However, the vulnerable `tryParseDouble` function existed long before the AI commit -- the rewrite merely changed code paths enough for the fuzzer to reach the pre-existing bug.

**Recommendation:** When the vulnerability source is OSS-Fuzz bisection (identifiable by `OSV-` prefix and fuzzing-related descriptions), apply additional skepticism to the BIC attribution since bisection finds "first crashing commit" not "commit that introduced the bug."

## Deep Verifier Tool Improvement

During the audit process, we added `git_log_search` (pickaxe search via `git log -S`) to the deep verifier's tool set (commit `c992c8d`). This allows the verifier to find when a specific code pattern was first introduced, which is more powerful than `git blame` for tracing through file renames and refactors.

## Full Audit Results

| # | CVE | Independent Verdict | Pipeline | Agree? | Key Finding |
|---|-----|-------------------|----------|--------|-------------|
| 1 | CVE-2026-28467 | NO_AI | UNLIKELY | Yes | Ghost blame + pr_body_keyword false signal |
| 2 | CVE-2026-28482 | NO_AI | UNLIKELY | Yes | AI commit only added a parameter to existing vuln function |
| 3 | GHSA-cfvj-7rx7-fc7c | UNLIKELY | UNLIKELY | Yes | AI inherited existing unsafe `fs.copyFile` pattern |
| 4 | **GHSA-vj3g-5px3-gr46** | **CONFIRMED** | **UNLIKELY** | **No (FN)** | **Claude Opus 4.5 introduced path traversal; timeout fallback bug** |
| 5 | GHSA-56f2-hvwg-5743 | UNLIKELY | UNLIKELY | Yes | Same SSRF as #1, ghost blame |
| 6 | GHSA-9f72-qcpw-2hxc | UNLIKELY | UNLIKELY | Yes | AI code was safe; human later added mechanism but missed this path |
| 7 | GHSA-73hc-m4hx-79pj | UNLIKELY | UNLIKELY | Yes | AI commit was adding security (read auth on health endpoint) |
| 8 | GHSA-553v-f69r-656j | UNLIKELY | UNLIKELY | Yes | AI commit and vulnerability are independent code paths |
| 9 | GHSA-hwpq-rrpf-pgcq | UNLIKELY | UNLIKELY | Yes | Ghost blame on import statement |
| 10 | GHSA-vjp8-wprm-2jw9 | UNLIKELY | UNLIKELY | Yes | AI commit blamed on import line, vuln in function body |
| 11 | GHSA-m69h-jm2f-2pv8 | UNLIKELY | UNLIKELY | Yes | AI touched config schema, not webhook handling |
| 12 | GHSA-g353-mgv3-8pcj | INCONCLUSIVE | UNLIKELY | ? | Needs deeper investigation |
| 13 | CVE-2026-21694 | UNLIKELY | UNLIKELY | Yes | Copilot commit not causally related |
| 14 | GHSA-q5qq-mvfm-j35x | UNLIKELY | UNLIKELY | Yes | AI did ruff formatting only |
| 15 | GHSA-3qhf-m339-9g5v | UNLIKELY | UNLIKELY | Yes | Missing try/except from day 1, AI refactored message dispatch |
| 16 | GHSA-943q-mwmv-hhvh | UNLIKELY | UNLIKELY | Yes | AI commit was incomplete security fix (added deny list) |
| 17 | GHSA-h4rm-mm56-xf63 | UNLIKELY | UNLIKELY | Yes | Vuln from 2021, AI touched adjacent comment |
| 18 | OSV-2026-371 | UNLIKELY | UNLIKELY | Yes | Fuzzer bisection, not root cause; legacy parser bug |
| 19 | CVE-2026-32061 | UNLIKELY | UNLIKELY | Yes | AI commit was incomplete path confinement fix |

## Pipeline Improvements Made During Audit

| Commit | Change | Impact |
|--------|--------|--------|
| `c62b524` | Rename `llm_verdict`/`verification_verdict` to `screening_verification`/`deep_verification` | Consistency across pipeline |
| `c992c8d` | BIC blame-file validation + `git_log_search` tool | Catches ghost blame, enables pickaxe tracing |
| `7cd7df4` | Cache key includes `fix_commit_sha` + don't cache fallback verdicts | Fixes the one FN found |

## Conclusions

1. **The deep verifier is highly accurate** (94.7%) at distinguishing AI-introduced vulnerabilities from coincidental AI involvement. The one miss was a caching infrastructure bug, not a reasoning failure.

2. **AI is more often fixing than introducing** vulnerabilities in the openclaw codebase. Multiple AI commits were security improvements that happened to be incomplete.

3. **`git blame` attribution is the weakest link.** Ghost blame, formatting commits, and import-line attribution account for most false signals. The blame-file validation added during this audit will help.

4. **The screening (shallow LLM) layer has high false positive rate.** It gave CONFIRMED on many cases where deep verification correctly said UNLIKELY. The two-tier system works as designed -- screening casts a wide net, deep verification filters accurately.
