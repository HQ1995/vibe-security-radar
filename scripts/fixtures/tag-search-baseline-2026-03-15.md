---
name: tag_search_baseline_2026-03-15
description: Tag-based fix commit discovery regression baseline — before/after metrics across all optimization rounds (N=2753, seed=42)
type: project
---

# Tag-Based Fix Commit Discovery — Regression Baseline

**Date:** 2026-03-15
**Test set:** N=2753 CVEs, seed=42, from candidate pool of 2753 (5388 validated, filtered by ground truth quality)
**Ground truth source:** backup-2026-03-15 cache, excluding tag-based/PR-based/AI-inferred sources

## Final Results (current code)

| Metric | Without LLM | With LLM rerank |
|--------|-------------|-----------------|
| FOUND | 2283 (82%) | 2283 (82%) |
| CORRECT | 1896 (83% prec) | 1896 (83% prec) |
| CORRECT@1 | — | 1413 (61%) |
| WRONG | 387 | 387 |
| NOT_FOUND | 470 | 470 |
| Recall | 68% | 68% |
| Time | ~95s | ~166s |

## Original Baseline (before optimizations)

| Metric | Value |
|--------|-------|
| FOUND | 2039 (74%) |
| CORRECT | 1460 (71% prec) |
| CORRECT@1 | 947 (46%) |
| WRONG | 571 |
| NOT_FOUND | 714 |
| Recall | 53% |
| Time | ~135s |

## Optimization History (cumulative)

| Round | Changes | CORRECT | Prec | @1 | WRONG | NOT_FOUND | Recall | Time |
|-------|---------|---------|------|----|-------|-----------|--------|------|
| Baseline | Original 3-step search, MAX=8, hard filter | 1460 | 71% | 947 (46%) | 571 | 714 | 53% | ~135s |
| R1 | Full enumeration ≤200, MAX=20, no hard filter, fix prefix +3 | 1611 | 79% | 909 (44%) | 428 | 714 | 58% | ~22s |
| R2 | Full enumeration all ranges (max 2000) | 1642 | 80% | 855 (41%) | 397 | 714 | 59% | ~22s |
| R3 | +LLM rerank (always, top 15, gemini-2.0-flash-lite) | 1642 | 80% | 1101 (53%) | 397 | 714 | 59% | ~59s |
| R4 | +Tag resolution improvements (prefix, suffix, release-) | 1766 | 79% | — | 450 | 537 | 64% | ~34s |
| R5 | +Cherry-pick matching in regression evaluation | 1840 | 83% | 1247 (56%) | 376 | 537 | 66% | ~83s |
| R6 | +Extended range search (prev_prev_tag), range bonus +3/-3 | 1872 | 83% | 1318 (58%) | 366 | 515 | 67% | ~109s |
| R7 | +Commit body CVE/GHSA ID check (top 50) | 1872 | 83% | 1318 (58%) | 366 | 515 | 67% | ~109s |
| R8 | +Multi-version fallback (up to 3 versions) | 1904 | 83% | 1423 (62%) | 379 | 470 | 69% | ~172s |
| R9 | +LLM diff context (top 3, 30 lines), gemini-3.1-flash-lite | 1904 | 83% | 1423 (62%) | 379 | 470 | 69% | ~172s |
| R10 | +Conditional extended range (score<5), dead code cleanup | 1896 | 83% | 1413 (61%) | 387 | 470 | 68% | ~166s |

## Total Improvement

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| FOUND | 2039 → 2283 | | **+244** |
| CORRECT | 1460 → 1896 | | **+436** |
| CORRECT@1 | 947 → 1413 | | **+466** |
| WRONG | 571 → 387 | | **-184** |
| NOT_FOUND | 714 → 470 | | **-244** |
| Recall | 53% → 68% | | **+15pp** |
| Precision | 71% → 83% | | **+12pp** |

## Remaining Failure Breakdown (N=857)

### NOT_FOUND (470, 17% of total)
- ~97% no_tag_range: version→tag resolution fails
  - Major version mismatch (advisory vs git scheme): ~50%
  - Shallow clone missing tags: ~5%
  - No tags at all: ~5%
  - Other: ~40%

### WRONG (387, 14% of total)
- Outscored (~200, 52%): expected in range but ranked >20
  - Score gap median: ~7.0
  - Expected rank median: ~48
- Not in range (~130, 34%): expected commit on different branch
  - different_branch: 47% of not_in_range
  - before_prev_tag: 27% (partially caught by extended range)
  - cherry_pick_in_range: 26% (caught by cherry-pick matching)
- Filtered out (~10, 3%): non-code filter too aggressive

## Key Algorithm Parameters

```python
_ADVISORY_VERSION_MAX_COMMITS = 20  # Top N returned to pipeline
_ENUMERATE_MAX_COMMITS = 2000       # Max commits enumerated per range
_LLM_RERANK_TOP_N = 10              # Candidates shown to LLM
_LLM_DIFF_TOP_N = 3                 # Candidates with diff context
_MAX_DIFF_LINES = 30                # Diff truncation per commit
LLM_MODEL = "gemini-3.1-flash-lite-preview"  # via model_config.FAST_MODEL
```

## Scoring Weights

- CVE/GHSA ID in message/body: +10
- Security keyword (exact match): +2 per keyword
- Fix prefix (fix:/patch:/hotfix:): +3
- Description keyword overlap: +1 per keyword
- Merge commit: -5
- Chore/CI/docs/style prefix: -3
- Dependency bump: -5
- Release/version bump: -5
- Non-code-only files: -3
- Extended range penalty: -3

## Regression Command

```bash
cd cve-analyzer
# Without LLM (fast, ~95s)
uv run python ../scripts/regression_tag_search.py --sample 2753 --workers 64 --seed 42

# With LLM rerank (~166s)
uv run python ../scripts/regression_tag_search.py --sample 2753 --workers 64 --seed 42 --llm-rerank

# With diagnostics
uv run python ../scripts/regression_tag_search.py --sample 2753 --workers 64 --seed 42 --diagnose
```

## Files Modified

- `git_ops.py`: +list_commits_with_files, +_detect_tag_prefix, +_strip_prerelease, expanded resolve_version_to_tag
- `pipeline.py`: rewritten _resolve_fix_from_version_tag (full enum + scoring + LLM + extended range)
- `commit_scoring.py`: +boost_by_commit_body, +llm_rerank_candidates, +_fetch_short_diff, expanded keywords
- `github_advisory.py`: +extract_all_patched_versions
- `regression_tag_search.py`: +diagnose mode, +llm-rerank flag, +multi-version fallback
- `regression_ground_truth.py`: +cherry-pick matching in sha_matches
