# False Positive Analysis Report

**Date:** 2026-03-04
**Context:** Two-phase LLM verification upgrade (commit `c50e2e4`)
**Model:** `gemini-3.1-flash-lite-preview`

## Executive Summary

After implementing two-phase LLM vulnerability analysis, the confirmed AI-introduced CVE count changed from **68 to 56** (net -12). This resulted from **24 CVEs being reclassified** as false positives and **12 new CVEs being added** due to improved verdict completeness.

All 24 removed CVEs transitioned from `CONFIRMED` to `UNRELATED` (22) or `UNLIKELY` (2).

## Root Cause of False Positives

**Before (single-phase):** The LLM only saw the fix commit diff and the BIC diff side by side. Without understanding the actual vulnerability, it frequently concluded that an AI commit was causal simply because it modified the same file as the fix commit.

**After (two-phase):**
- **Phase 1** (per-CVE): Analyze the vulnerability itself — type, root cause, vulnerable code pattern, security-relevant files.
- **Phase 2** (per-BIC): Verify causality with Phase 1 context — does this specific commit actually introduce the identified vulnerability?

This eliminates the "same file = same bug" false correlation pattern.

## False Positive Categories

### Pattern 1: Same Repo/File, Different Functional Module (14 CVEs)

The most common false positive pattern. The AI commit modified code in the same file or repository as the vulnerability, but in a completely unrelated functional area. Git blame attributed the AI commit because the fix touched the same file.

| CVE | Vulnerability | AI Tool | Why It Was a False Positive |
|-----|--------------|---------|---------------------------|
| **CVE-2025-46817** | Redis use-after-free in `defragStreamConsumerGroup` | Copilot | AI commit added hash field defrag logic in `src/defrag.c`; vulnerability was in stream consumer group pointer invalidation — completely separate defrag path |
| **CVE-2025-46818** | Redis use-after-free (related to 46817) | Copilot | Same AI commit (`5d0d64b062c1`) blamed for same-file coincidence; different defrag subsystem |
| **CVE-2025-46819** | Redis use-after-free (related to 46817) | Copilot | Same AI commit, same false blame pattern across multiple Redis CVEs |
| **CVE-2025-49844** | Redis Lua sandbox RCE | Copilot | Same Copilot commit in `src/defrag.c` blamed again; Lua sandbox escape is entirely unrelated to memory defragmentation |
| **CVE-2025-59159** | SillyTavern DNS rebinding | Copilot/Claude | 60 AI BICs identified, all UNRELATED — AI commits added TypeScript type definitions and client-side thumbnail caching; vulnerability was missing Host header validation on the server side |
| **CVE-2025-64419** | Coolify command injection | Claude Code | 11 AI commits were all frontend Blade template and UI changes; vulnerability was in backend docker-compose command execution |
| **CVE-2025-69202** | axios-cache-interceptor cache poisoning | Copilot | 10 AI BICs all UNRELATED — AI commits modified Cache-Control header strings; vulnerability was in cache key generation ignoring the HTTP `Vary` header |
| **CVE-2026-26192** | Open WebUI stored XSS | Claude Code/Jules | 7 AI commits modified SCIM integration, permissions, and logging; vulnerability was in citation iframe rendering with unsanitized HTML |
| **CVE-2026-26075** | FastGPT CSRF | Copilot | 5 AI commits modified `.gitignore`, TypeScript type definitions, and Redis cache logic; vulnerability was missing CSRF token validation on API endpoints |
| **GHSA-rcfx-77hg-w2wv** | FastMCP authorization bypass | Claude Code/Copilot | AI commits modified parameter serialization and JSON schema; vulnerability was missing security hints in tool definitions |

*Note: CVE-2025-46817/18/19 and CVE-2025-49844 all stem from the same Copilot-authored commit being blamed across 4 separate Redis CVEs — a single false blame amplified across related vulnerabilities.*

### Pattern 2: AI Commit Made Unrelated Modifications in Same File (6 CVEs)

The AI commit touched the same file as the vulnerability but performed a functionally distinct change that has no causal relationship.

| CVE | Vulnerability | AI Tool | Why It Was a False Positive |
|-----|--------------|---------|---------------------------|
| **CVE-2025-32393** | AutoGPT DoS via RSS feed | Claude Code | AI wrote an "activity status generator" utility; vulnerability was in the RSS feed parser's resource consumption |
| **CVE-2025-53108** | HomeBox unauthorized access | Copilot | AI modified Go backend API function signatures; vulnerability was in GitHub Actions CI/CD configuration allowing unauthorized workflow dispatch |
| **CVE-2025-66479** | Anthropic sandbox escape | Claude Code | AI wrote seccomp filter generation code; vulnerability was in network restriction bypass via `if (!httpSocketPath)` logic |
| **CVE-2026-21452** | msgpack DoS (memory allocation) | Claude Code | AI wrote test files; vulnerability was in the core memory allocation handling for malformed msgpack payloads |
| **CVE-2026-21528** | Azure IoT information disclosure | Copilot | AI modified file path sanitization logic; vulnerability was in network binding to `0.0.0.0` exposing services to all interfaces |
| **CVE-2026-2439** | Session ID insufficient entropy | Claude Code | AI wrote POD documentation; vulnerability was in the `generate_session_id` implementation using weak randomness |

### Pattern 3: AI Commit Was a Fix Attempt, Not an Introduction (1 CVE)

The AI commit was actually trying to remediate the vulnerability, but was incorrectly blamed as the introducer.

| CVE | Vulnerability | AI Tool | Why It Was a False Positive |
|-----|--------------|---------|---------------------------|
| **CVE-2025-53903** | Cross-site scripting (XSS) | Copilot | AI commit message was literally "Potential fix for XSS" — this was a remediation attempt, not a vulnerability introduction. The underlying XSS predated this commit. Verdict: **UNLIKELY** (confidence: 0.09) |

### Pattern 4: Vulnerability Pre-existed the AI Commit (3 CVEs)

The vulnerable code pattern already existed in the codebase before the AI commit. The AI commit made tangential changes (refactoring, type updates, test additions) that git blame attributed to the AI tool.

| CVE | Vulnerability | AI Tool | Why It Was a False Positive |
|-----|--------------|---------|---------------------------|
| **CVE-2026-21694** | Titra mass assignment | Copilot | AI modified route handler parameter destructuring (refactoring); the mass assignment pattern accepting arbitrary user fields existed before the AI commit |
| **CVE-2026-21695** | Titra mass assignment (related) | Copilot | Same AI commit blamed for a related mass assignment in a different route handler; same pre-existing pattern |
| **CVE-2026-21862** | RustFS IP spoofing | Copilot | AI commit was an import refactoring and credential type rename; the IP validation bypass logic predated this commit. Verdict: **UNLIKELY** (confidence: 0.009) |
| **CVE-2026-22612** | Fickling unsafe deserialization | Claude Code | AI modified AST utility functions; the logic that skipped builtins during pickle analysis was already present |
| **CVE-2026-26319** | OpenClaw path traversal | Claude Code | AI wrote test configuration files; vulnerability was in the `sendMediaFeishu` function's file path handling |
| **CVE-2026-27822** | Stored XSS | Copilot | AI modified backend observability example code; vulnerability was in the frontend preview modal's HTML rendering |
| **GHSA-8g98-m4j9-qww5** | Weak password hashing (PBKDF2) | Jules | AI wrote purchase polling logic; vulnerability was in PBKDF2 iteration count configuration being too low |

## Verdict Transition Summary

| Old Verdict | New Verdict | Count | Description |
|-------------|-------------|-------|-------------|
| CONFIRMED | UNRELATED | 22 | AI commit definitively unrelated to the vulnerability |
| CONFIRMED | UNLIKELY | 2 | AI commit tangentially related but not causal (CVE-2025-53903, CVE-2026-21862) |

## Newly Added CVEs (12)

These 12 CVEs were added to the database. They were previously excluded because their `ai_confidence` score was below the threshold or they lacked sufficient verdict data. The two-phase analysis produced more complete verdicts, pushing them above the inclusion threshold.

| CVE | Notes |
|-----|-------|
| CVE-2025-13321 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-53107 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-53355 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-58747 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-66209 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-66210 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-66211 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-66212 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-66213 | Newly confirmed with enriched Phase 1+2 data |
| CVE-2025-67732 | Newly confirmed with enriched Phase 1+2 data |
| GHSA-33rq-m5x2-fvgf | Newly confirmed with enriched Phase 1+2 data |
| GHSA-mhc9-48gj-9gp3 | Newly confirmed with enriched Phase 1+2 data |

## Impact

- **Before:** 68 CVEs attributed to AI-generated code (contained ~35% false positives)
- **After:** 56 CVEs with significantly higher confidence
- **Net effect:** Removed 24 false positives, added 12 previously-missed true positives
- **Quality improvement:** The remaining 56 CVEs each have structured causality data (vulnerability type, root cause, vulnerable pattern, causal chain) visible on the website

## Lessons Learned

1. **"Same file" != "same bug"** — The biggest source of false positives was git blame attributing AI commits to vulnerability-related files when the AI code was in a completely different functional area.

2. **Context is critical for LLM verification** — Without understanding what the vulnerability actually is, the LLM defaults to surface-level correlations (same file, same function names) that produce false confirmations.

3. **Large repos amplify false positives** — Projects like Redis, Next.js, and SillyTavern have many AI-assisted commits across shared files, making "same file" false positives especially prevalent.

4. **Fix commit diffs are noisy** — Fix commits often touch multiple files for unrelated reasons (refactoring, formatting, test additions). Phase 1 analysis helps identify which parts of the fix are security-relevant.

5. **A single false blame can cascade** — One incorrectly blamed AI commit (e.g., the Redis defrag commit) can generate false positives across multiple related CVEs.
