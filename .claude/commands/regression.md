# Regression Check

Run intelligent regression analysis that goes beyond cache comparison.

## Context Files

Before starting, read these files for historical context:
- `cve-analyzer/regression/lessons.md` — known patterns, fragile TPs, past mistakes
- `cve-analyzer/regression/history.md` — changelog of past regression checks

## Phase 1: Tests

```
cd cve-analyzer && uv run pytest tests/ -q
```
If tests fail, stop and fix them before proceeding.

## Phase 2: Impact Analysis

**Before comparing cache, analyze what changed.**

1. Run `git diff HEAD~1..HEAD -- cve-analyzer/src/` (or the appropriate range since last baseline commit) to identify pipeline changes.

2. Categorize the change impact:
   - **Tier removal/addition**: Which fix commit sources are affected? (osv, github_advisory, advisory_version, git_log_search, etc.)
   - **Blame/confidence logic**: Could existing blame chains or confidence scores change?
   - **Signal detection**: New/removed AI tool patterns?
   - **Filter changes**: New/removed filters that could reject previously-accepted fix commits?
   - **Pure refactoring**: Logic unchanged, just code reorganization?

3. For each affected tier/source, query the cache to find TPs that depend on it:
   ```python
   python3 -c "
   import json; from pathlib import Path
   cache = Path.home() / '.cache/cve-analyzer/results'
   for f in sorted(cache.glob('*.json')):
       data = json.loads(f.read_text())
       confirmed = [b for b in data.get('bug_introducing_commits', [])
                     if (b.get('llm_verdict') or {}).get('verdict','').upper() == 'CONFIRMED']
       if not confirmed: continue
       sources = {fc['source'] for fc in data.get('fix_commits', [])}
       if 'AFFECTED_SOURCE' in sources:
           print(f'{data[\"cve_id\"]}: sources={sources}, confirmed_bics={len(confirmed)}')
   "
   ```

4. Classify risk:
   - **HIGH**: TP's ONLY fix source is affected → will be lost
   - **MEDIUM**: TP has affected source + other sources → partial loss
   - **LOW**: Pure refactoring of code path used by TP → unlikely loss

## Phase 3: Cache Comparison

```
cd cve-analyzer && uv run python regression/check.py
```

This is necessary but NOT sufficient. It catches data-level regressions but misses code-level regressions (cache still holds stale results from old pipeline).

## Phase 4: Re-analyze At-Risk TPs

For HIGH and MEDIUM risk TPs identified in Phase 2:

```
uv run cve-analyzer --no-cache --verbose analyze <CVE-ID> --llm-verify
```

Run these in parallel (background) for efficiency. Compare results:
- Did the TP survive? (still has confirmed BICs with AI signals)
- Did it find the same fix commits via different sources?
- Did confidence scores change?

## Phase 5: Update Records

### 5a. Update history.md

Append a new entry to `cve-analyzer/regression/history.md`:
```markdown
## YYYY-MM-DD: <brief description of changes>

**Changes**: <what was modified and why>
**Baseline before**: X TPs (date)
**Baseline after**: Y TPs (date)
**At-risk TPs**: <list of TPs that were at risk>
**Re-analysis results**: <what happened when re-analyzed>
**Regressions**: <count and details>
**New TPs**: <count>
```

### 5b. Update lessons.md

Review `cve-analyzer/regression/lessons.md` and update:
- Add new lessons learned from this regression check
- Update the Fragile TPs Watch List
- Remove entries that are no longer relevant
- Add improvement suggestions based on patterns observed

### 5c. Update baseline (if clean)

Only after confirming no real regressions:
```
cd cve-analyzer && uv run python regression/check.py snapshot --cache
```

## Phase 6: Improvement Suggestions

Based on lessons.md patterns and this check's findings, suggest concrete improvements:

1. **Pipeline improvements**: Missing sources, better filters, confidence tuning
2. **Regression infra improvements**: Better automation, smarter cache invalidation
3. **Test coverage gaps**: Untested code paths that could regress silently

## When to Use

- After modifying the analysis pipeline (`pipeline.py`, `git_ops.py`, `llm_verify.py`, `ai_signatures.py`)
- After re-running batch analysis
- Before committing pipeline changes to main
