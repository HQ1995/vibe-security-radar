# Independent CVE Audit Skill (`/audit`)

**Date:** 2026-03-12
**Status:** Approved

## Problem

The CVE analyzer pipeline is a mechanical system: git blame → pattern match → LLM verify → tribunal vote. Each phase has known blind spots:

1. **Blame errors**: git blame points to the last commit that touched a line, not necessarily the commit that introduced the vulnerability (e.g., a refactor commit gets blamed instead of the original vulnerable commit)
2. **Squash decomposition false positives**: When blame points to a squash merge, the pipeline checks individual PR commits for AI signals. But it can't tell which specific commit within the squash introduced the vulnerable code — it only knows "some commit in this PR was AI-assisted"
3. **Signal inheritance**: AI signals from merge/squash/cherry-pick can be attributed to the wrong commit
4. **Tribunal only checks BIC causality**: The tribunal verifies "did this BIC introduce the vulnerability?" but doesn't verify fix commit correctness or blame accuracy independently

**No existing component reasons about code semantics** — whether the blamed code actually contains the vulnerable pattern, whether the AI-authored commit specifically introduced it, or whether the pipeline's mechanical analysis missed the real root cause.

## Solution

A Claude Code slash command (`/audit`) that independently verifies cached analysis results by reading actual code, diffs, and advisories. It reasons about correctness at each pipeline stage and accumulates findings to identify systemic issues.

### Key Design Principle: Independence

The audit must NOT reuse pipeline code. It reads raw git data and cached results, then reasons independently. This ensures pipeline bugs don't propagate into the audit.

## Architecture

### Input

- A CVE ID (reads fix commit info from cached result in `~/.cache/cve-analyzer/results/`)
- Or no argument: auto-selects an unaudited CVE (priority: tribunal CONFIRMED > tribunal UNLIKELY but LLM CONFIRMED > unverified)

### Phase 1: Independent Verification (per CVE)

Six stages executed sequentially:

#### Stage 1: Fix Commit Validation

**Question**: Is this commit actually fixing the described CVE?

- Read fix diff from local repo (`~/.cache/cve-analyzer/repos/`)
- Web search for CVE details (NVD, GHSA, security blogs)
- Compare: does the fix diff address the vulnerability described in the CVE?
- Verdict: `CORRECT` / `PARTIAL` / `WRONG`
- If `WRONG` → flag fix commit discovery issue, skip remaining stages

#### Stage 2: Vulnerability Pattern Extraction

**Question**: What specific code pattern was vulnerable?

- From fix diff: what was removed (vulnerable pattern) and what was added (secure pattern)
- Identify the security-critical characteristics (e.g., missing input validation, unsafe deserialization, improper access control)
- Output: `vulnerable_pattern` + `secure_pattern` — this is the ground truth for causality analysis

#### Stage 3: Independent Blame

**Question**: Which commits introduced the vulnerable code?

- For deleted/modified lines in fix diff: run `git blame` directly
- For add-only fixes: use `git log -L` (function history) or context analysis
- Compare against pipeline's BIC list
- Classify each BIC: `SAME` / `DIFFERENT` / `EXTRA` (audit found, pipeline missed) / `MISSING` (pipeline found, audit can't confirm)

#### Stage 4: AI Signal Forensics

**Question**: Are the AI tool attributions real?

- Run `git show --format=full <sha>` to read raw commit metadata
- Verify co-author trailers: original commit vs squash/merge inheritance
- Check author email patterns: AI tool noreply vs user's own email
- For squash commits: read each individual PR commit's diff to determine which specific commit introduced the vulnerable code (not just "some commit in PR had AI signal")
- Verdict per signal: `REAL_SIGNAL` / `INHERITED` / `FALSE_SIGNAL`

#### Stage 5: Causality Analysis (Core)

**Question**: Did the AI-authored code actually introduce the vulnerability?

Decision matrix:

|                           | BIC contains vuln pattern | BIC doesn't contain vuln pattern |
|---------------------------|---------------------------|----------------------------------|
| No BIC → no vulnerability | **CONFIRMED**             | UNLIKELY                         |
| No BIC → still vulnerable | UNRELATED                 | UNRELATED                        |

Additional factors:
- Was code newly written vs modifying existing code?
- Is it on a security-critical code path?
- How large is the commit? (large commit = lower confidence)
- Could the vulnerability have existed before this commit?

#### Stage 6: Pipeline Comparison & Diagnosis

Compare audit conclusions vs pipeline conclusions layer by layer:

| Layer | Audit | Pipeline | Diagnosis |
|-------|-------|----------|-----------|
| Fix commit | CORRECT/WRONG | (assumed correct) | Fix discovery issue |
| Blame | BIC list | BIC list | Blame strategy error |
| AI signals | REAL/FALSE | detected signals | Signal detection issue |
| LLM verdict | - | CONFIRMED/UNLIKELY | Verdict accuracy |
| Tribunal verdict | - | CONFIRMED/UNLIKELY | Tribunal accuracy |

For each disagreement: identify root cause and generate improvement suggestion.

### Phase 1 Output (per CVE)

```json
{
  "cve_id": "CVE-2026-XXXXX",
  "timestamp": "2026-03-12T...",
  "independent_verdict": "CONFIRMED|UNLIKELY|UNRELATED",
  "confidence": "HIGH|MEDIUM|LOW",
  "fix_commit_valid": true,
  "stages": {
    "fix_validation": "CORRECT",
    "blame_agreement": "SAME|DIFFERENT",
    "signal_verification": "REAL_SIGNAL|INHERITED|FALSE_SIGNAL",
    "causality": "CONFIRMED|UNLIKELY|UNRELATED"
  },
  "pipeline_comparison": {
    "agreement": true,
    "disagreement_phase": null,
    "root_cause": null
  },
  "improvement_suggestions": [
    {
      "category": "blame_strategy|signal_detection|confidence_scoring|tribunal_logic|squash_handling",
      "description": "...",
      "affected_file": "src/cve_analyzer/...",
      "severity": "HIGH|MEDIUM|LOW"
    }
  ]
}
```

### Phase 2: Pattern Accumulation

Findings saved to `~/.cache/cve-analyzer/audit/findings.json`.

After every 10 findings, auto-analyze:

1. **By disagreement layer**: "blame has 6/10 disagreements"
2. **By blame strategy**: "context_blame accuracy is 40%"
3. **By signal type**: "squash_decomposed FP rate is 73%"
4. **By vulnerability type**: "deserialization CVEs often get blame wrong"

Output: Pipeline Accuracy Report + Top-N Improvement Recommendations with specific file:line references.

### Audit Target Priority

1. **Tribunal CONFIRMED** (63 CVEs on website) — FP directly harms credibility
2. **Tribunal UNLIKELY but LLM CONFIRMED** — potential tribunal false negatives
3. **High confidence, no tribunal** — unverified candidates

### `/loop` Integration

`/loop 30m /audit` — every 30 minutes:
1. Pick next unaudited CVE by priority
2. Run full Phase 1
3. Save finding
4. Every 10 findings: run Phase 2 pattern analysis

## Known High-Value Audit Targets

### Squash Commit Problem

Pipeline decomposes squash merges and checks if ANY individual PR commit has AI signals. But it cannot determine which specific commit introduced the vulnerable code. The audit skill can:
1. Read the squash merge diff (what the overall PR changed)
2. Read each individual commit's diff
3. Map the vulnerable code to the specific individual commit
4. Check if THAT commit (not just "some commit") was AI-assisted

This alone could eliminate a significant portion of false positives from `squash_decomposed_*` signals.

## Non-Goals

- Does not re-run the pipeline or use pipeline code
- Does not modify cached results (read-only audit)
- Does not replace the tribunal (complementary, not competitive)
- Does not verify fix commit discovery (takes fix commits as given input)
