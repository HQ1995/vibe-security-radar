# Audit Findings: Deep Verifier Accuracy on Removed CVEs

**Date:** 2026-03-15
**Auditor:** Independent manual review (Claude Opus 4.6 + human oversight)
**Scope:** 94 of 94 CVEs removed from website after deep verifier filtering changes (complete audit)

## Executive Summary

After adding strict filtering to `generate_web_data.py` (only CONFIRMED deep verdicts pass), 94 CVEs were removed from the website. We audited all 94 to determine whether the deep verifier was correct.

**Result: 95.7% accuracy (90/94 correct).** Four false negatives were found across three distinct root causes: caching bugs (2), verifier reasoning error (1), and pipeline fix-commit resolution failure (1).

### The 4 False Negatives

| # | CVE | Vulnerability | AI Tool | Root Cause | Status |
|---|-----|--------------|---------|-----------|--------|
| 1 | GHSA-vj3g-5px3-gr46 | Path traversal in Feishu temp files | Claude Opus 4.5 | Cache key collision + timeout fallback cached | **Fixed** (7cd7df4) |
| 2 | CVE-2025-59163 | CORS `Access-Control-Allow-Origin: *` | GitHub Copilot | Per-BIC verifier missed CORS as independent issue | **Fixed** (v10 investigation) |
| 3 | GHSA-5wp8-q9mx-8jx8 | Shell allowlist bypass (wrong regex, missing metachar detection) | Claude Opus/Sonnet 4.6 | Verifier misclassified as "incomplete fix" | **Fixed** (v10 investigation) |
| 4 | CVE-2025-66689 | Path traversal (`is_dangerous_path` exact match vs prefix) | Claude | Fix commit pointed to version bump, pipeline never analyzed code | **Needs pipeline fix** |

## FN 1: GHSA-vj3g-5px3-gr46 (Cache Collision)

**Vulnerability:** Path traversal in OpenClaw's Feishu media temp-file naming. User-controlled `imageKey` values were used directly in `path.join(os.tmpdir(), ...)`, allowing writes outside the temp directory.

**AI involvement:** Commit `2267d58afcc7` by Yifeng Wang, `Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>`. The prior implementation did not have this vulnerability.

**What went wrong:** The deep verifier ran twice for the same BIC against two different fix commits:
1. Fix commit `cdb00fe2` -> **CONFIRMED** (35 tool calls, correct)
2. Fix commit `ec232a9e` -> timed out after 41 tool calls -> **UNLIKELY** (fallback)

Cache key didn't include `fix_commit_sha`, so the second result overwrote the first.

**Bugs fixed:**
- Cache key now includes `fix_commit_sha` (commit `7cd7df4`)
- Timeout fallbacks are no longer cached (commit `7cd7df4`)
- Added `is_fallback` flag to verdict models (commit `7cd7df4`)

## FN 2: CVE-2025-59163 (CORS Wildcard as Independent Vulnerability)

**Vulnerability:** DNS rebinding in vet MCP Server's SSE transport.

**AI involvement:** Copilot commit `cd7caff` added `Access-Control-Allow-Origin: *` to the HEAD handler and replaced `s.Start()` with a custom `http.Server`.

**What the verifier missed:** The original code (human-authored) was already vulnerable to DNS rebinding (no Host validation). But the Copilot commit introduced a **separate, easier attack vector**: with `CORS: *`, an attacker doesn't need DNS rebinding at all — a simple cross-origin `fetch()` from any website can read SSE data. The fix explicitly removes the wildcard CORS and adds origin-specific validation.

**Attack feasibility comparison:**

| | Before Copilot | After Copilot |
|---|---|---|
| Attack method | DNS rebinding (complex) | Direct cross-origin fetch (trivial) |
| CORS headers | None (browser blocks) | `*` (browser allows) |
| Difficulty | Needs DNS infrastructure | One line of JS |

The old per-BIC verifier saw only "DNS rebinding was pre-existing → UNLIKELY" without recognizing CORS `*` as an independent vulnerability. The new v10 per-vulnerability investigation correctly identified both BICs as CONFIRMED.

## FN 3: GHSA-5wp8-q9mx-8jx8 (Buggy Security Features)

**Vulnerability:** Shell allowlist/blocklist bypass in zeptoclaw with 4 distinct vectors.

**AI involvement:** 3 of 4 bypass vectors were written by Claude:

| Vector | Description | Author |
|--------|-------------|--------|
| Weak regex `python[23]?\s+-c\s+` bypassed by `python -Bc` | Claude Opus 4.6 |
| `contains()` bypassed by shell globs `/etc/pass[w]d` | Human |
| Allowlist only checks first token, `;`/`|` chaining bypasses | Claude Sonnet 4.6 |
| Empty allowlist in Strict mode silently allows everything | Claude Sonnet 4.6 |

**Why the verifier got it wrong:** It applied the "incomplete security fix" template — treating these as "AI added some security but didn't cover everything." But this is fundamentally different: the AI **created the security mechanism itself** with implementation bugs (wrong regex patterns, missing metacharacter detection, broken empty-list guard). The bypass IS the vulnerability, not a missing feature.

**Key distinction:** "AI didn't add a security mechanism" (UNLIKELY) vs "AI added a security mechanism that's broken" (CONFIRMED). The verifier needs to distinguish these.

## FN 4: CVE-2025-66689 (Fix Commit Resolution Failure)

**Vulnerability:** Path traversal in Zen/Pal MCP Server. `is_dangerous_path()` used exact string match (`str(resolved) in DANGEROUS_PATHS`) instead of prefix match, so `/etc/passwd` bypassed the `/etc` block.

**AI involvement:** Commit `4151c3c3` ("Migration from Docker to Standalone Python Server"), `Co-authored-by: Claude <noreply@anthropic.com>`.

**What went wrong:** This is not a verifier error — the pipeline never analyzed the code at all. The OSV fix commit (`fa78edca`) pointed to a semantic-release version bump. The pipeline detected it as "locale/translation only" and skipped it, but didn't fallback to find the actual code fix (`9ed15f4`).

**Needs pipeline fix:** When a fix commit only touches non-code files, search nearby commits in the same release for the actual security fix.

## Patterns Discovered Across 94 Audits

### Pattern 1: AI Fixes Vulnerabilities More Often Than Introducing Them

In 8+ cases, AI-authored commits were **security improvements** that happened to be incomplete:

| CVE | AI action | What was left unfixed |
|-----|-----------|----------------------|
| GHSA-73hc-m4hx-79pj | Added `require_read_access` to unauthenticated endpoint | Fix upgraded to `require_write_access` |
| GHSA-943q-mwmv-hhvh | Added `DANGEROUS_ACP_TOOLS` deny set | Fail-open on unknown tool names |
| CVE-2026-32061 | Added `resolvePath()` confinement | Nested `$include` path reset escape |
| GHSA-9f72-qcpw-2hxc | Added `sandboxRoot` restrictions | Later `workspaceOnly` mechanism missed this path |
| CVE-2025-5277 | Replaced `shell=True` in one file | Left `tools.py` with shell execution |
| GHSA-vh5j-5fhq-9xwg | Added non-atomic replay protection | TOCTOU race in check-then-act |
| GHSA-83pf-v6qq-pwmr | Added 8 network modules to denylist | Missed 6 more (smtplib, ftplib, etc.) |
| GHSA-wccx-j62j-r448 | Added Unpickler hooks | Missed `pickle.loads`/`_pickle` hooks |

The deep verifier correctly classified all of these as UNLIKELY.

### Pattern 2: Ghost Blame (Blamed Commit Never Touched Blamed File)

In 5+ cases, `git blame` attributed lines to commits that never modified the blamed file:

| CVE | Blamed commit | Blamed file | Actually modified? |
|-----|--------------|-------------|-------------------|
| CVE-2026-28467 | `bbc67f37` | src/media/fetch.ts | No |
| GHSA-56f2-hvwg-5743 | `bbc67f37` | src/agents/tools/web-fetch.ts | No |
| GHSA-hwpq-rrpf-pgcq | `483fba41` | src/infra/exec-approvals.ts | No |
| GHSA-wr6m-jg37-68xh | `03586e3d` | extensions/zalo/... | No |
| CVE-2025-53857 | `c9b5070` | server/atlassian_connect.go | No |

**Fix applied:** `_commit_touched_file()` validation in `pipeline.py` (commit `c992c8d`).

### Pattern 3: Squash Merge Trailer Flattening

AI co-author trailers from cosmetic sub-commits get applied to the entire squash, including vulnerable lines by human sub-commits:

| CVE | What happened |
|-----|--------------|
| CVE-2026-25481 | Claude/Copilot trailers for type annotations applied to entire squash with human-authored vulnerability |
| CVE-2025-57806 | Copilot Autofix trailer from exception-message fix applied to plaintext credential storage commit |
| CVE-2026-22804 | 138 sub-commit squash; `dangerouslySetInnerHTML` written by human, AI trailers from SSH/theming sub-commits |
| CVE-2025-53108 | Copilot sub-commit changed log message wording; human sub-commit removed auth check |

### Pattern 4: Fix Commit Misidentification

In 12+ cases, the pipeline selected the wrong fix commit (version bumps, CHANGELOGs, locale updates):

| Project | Wrong fix commit | Why wrong |
|---------|-----------------|-----------|
| Mattermost Confluence (8 CVEs) | `c32e004` "Improved error messages" | Error message changes, not auth fixes |
| Roo Code (2 CVEs) | `840fe2a` CHANGELOG | Release notes, not code |
| grist-core (2 CVEs) | Version bumps | package.json only |
| PX4-Autopilot | Unmerged Copilot PR | PR was closed, never merged |
| Grav | `0f879bd` CHANGELOG date change | Not the SSTI fix |
| Zen MCP Server | `fa78edca` semantic-release | Version bump, not path traversal fix |

**Recommendation:** Validate fix commits contain actual security-relevant code changes. When they don't, search nearby commits in the same release.

### Pattern 5: AI Creating Buggy Security Features

GHSA-5wp8-q9mx-8jx8 represents a distinct pattern from "incomplete fix": the AI actively created security mechanisms (regex patterns, allowlist logic) that contained implementation bugs. This is different from omitting a check — the AI wrote the check, but wrote it wrong.

### Pattern 6: AI Worsening Existing Vulnerabilities

CVE-2025-59163 shows AI making an existing vulnerability easier to exploit by adding `Access-Control-Allow-Origin: *`, removing the need for DNS rebinding. The AI didn't create the vulnerability but significantly lowered the attack barrier.

OSV-2026-371 shows a similar pattern: AI changed buffer semantics (null-terminated → raw vector) that exposed a latent parser bug.

### Pattern 7: Repeated Projects

Some projects appeared many times in the audit:

| Project | CVEs | All correct? |
|---------|------|-------------|
| Mattermost Confluence Plugin | 8 | Yes (all human-authored, same wrong fix commit) |
| MCP Python SDK | 4 | Yes (all day-1 missing exception handlers) |
| Fickling (Trail of Bits) | 4 | Yes (all 2021-era blocklist gaps) |
| git-mcp-server | 3 | Yes (all exec injection from initial rewrite) |
| OpenClaw | 15+ | 2 FN (GHSA-vj3g-5px3-gr46, GHSA-5wp8-q9mx-8jx8 was zeptoclaw not openclaw) |
| Roo Code | 3 | Yes (all human design decisions) |

## Pipeline Improvements Made During Audit

| Commit | Change | Impact |
|--------|--------|--------|
| `c62b524` | Rename verification fields for consistency | All layers use same field names |
| `c992c8d` | BIC blame-file validation + `git_log_search` tool | Catches ghost blame, enables pickaxe tracing |
| `7cd7df4` | Cache key includes `fix_commit_sha` + don't cache fallbacks | Fixes FN #1 |
| v10 | Per-vulnerability investigation (replaces per-BIC) | Fixes FN #2 and #3 |

**Still needed:** Fix commit resolution fallback when OSV points to version bumps/CHANGELOGs (would fix FN #4).

## Conclusions

1. **Deep verifier accuracy: 95.7%** (90/94). Four FN found across three root causes — caching (2, fixed), verifier reasoning (1, fixed by v10), fix-commit resolution (1, needs pipeline fix).

2. **AI is more often fixing than introducing vulnerabilities.** In 8+ cases AI commits were security improvements. Only 4 of 94 removed CVEs had genuine AI-introduced vulnerabilities.

3. **`git blame` attribution remains the weakest link.** Ghost blame, formatting commits, import-line attribution, and squash-merge trailer flattening account for most false signals.

4. **Fix commit misidentification is a systemic pipeline issue.** 12+ cases used wrong fix commits (version bumps, CHANGELOGs). This doesn't affect verifier accuracy (the verifier works on whatever it's given) but means some CVEs are never properly analyzed.

5. **The screening layer has a high false positive rate** but serves its purpose. It gave CONFIRMED on many cases where deep verification correctly said UNLIKELY. The two-tier system works as designed.

6. **New vulnerability patterns identified:** AI creating buggy security features (GHSA-5wp8-q9mx-8jx8) and AI worsening existing vulnerabilities (CVE-2025-59163) are distinct from the common "coincidental blame" pattern and warrant special attention.
