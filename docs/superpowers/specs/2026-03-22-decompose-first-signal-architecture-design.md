# Decompose-First Signal Architecture

## Problem

The signal pipeline has a structural flaw: signal detection runs on squash merge commits (Phase B) before decomposition identifies the actual culprit sub-commit (Phase B.5). This ordering creates a cascade of bugs where signals are detected on the wrong commit, then patched with propagation/cleanup hacks that themselves introduce new bugs.

In a 2-day debugging session, 7 bugs were found and fixed, all caused by this ordering:

1. `rescan_signals` wiping `pr_body_keyword` signals (can't regenerate without API)
2. `rescan_signals` wiping `squash_decomposed_*` signals
3. Squash decomposition not propagating culprit DC signals when merge pipeline strips trailers
4. Propagation creating 27 false positives by not checking `touched_blamed_file`
5. `Co-Authored-By:.*Bolt` pattern matching human names
6. `@x.ai` email pattern matching human employees
7. Top-level `ai_signals` aggregate not rebuilding when BIC signals are intact but top-level is stale

Plus 13 unfixed bugs and 5 design issues identified in a full pipeline audit.

## Design Principle

**Signals come from the smallest (atomic) commits.** A squash merge is not a signal source — its sub-commits are. Signal detection should happen after decomposition, on the commit that actually touched the vulnerable file.

## Architecture Change

### Current Flow (problematic)

```
Phase B:   Blame → find BIC → detect signals on BIC (may be squash merge)
Phase B.5: Decompose squash → discover signals are on wrong commit → propagate/strip/cleanup
Phase C.5: LLM screening
Phase D:   Deep verification
Phase E:   Confidence scoring (duplicated in pipeline.py and generate_web_data.py)
```

### New Flow

```
Phase B:   Blame → find BIC (no signal detection)
Phase B.1: Decompose squash merges → find culprit sub-commit
Phase B.2: Detect signals on atomic commits + PR body scan
Phase C:   LLM screening (unchanged)
Phase D:   Deep verification (unchanged)
Phase E:   Confidence scoring (unified, single implementation)
```

## Data Model Changes

### AiSignal: add `origin` field

```python
@dataclass
class AiSignal:
    tool: AiTool
    signal_type: str          # no more "squash_decomposed_" prefix
    matched_text: str
    confidence: float
    origin: str = "commit_metadata"  # commit_metadata | pr_body | verifier_discovered
```

**Backward compatibility:** `origin` defaults to `"commit_metadata"`. Old cached results without this field deserialize correctly. The `squash_decomposed_*` prefix is no longer generated for new results but still recognized during deserialization of old data.

### BugIntroducingCommit: add `effective_signals()` and `pr_signals`

```python
@dataclass
class BugIntroducingCommit:
    commit: CommitInfo
    fix_commit_sha: str
    blamed_file: str
    blamed_lines: list[int]
    blame_confidence: float
    blame_strategy: str
    screening_verification: LlmVerdict | None = None
    tribunal_verdict: dict | None = None
    deep_verification: dict | None = None
    decomposed_commits: list[DecomposedCommit] = field(default_factory=list)
    culprit_sha: str = ""
    pr_signals: list[AiSignal] = field(default_factory=list)  # NEW: PR-level signals

    def effective_signals(self) -> list[AiSignal]:
        """Authoritative signals from the atomic commit + PR-level signals.

        The single source of truth for whether AI authored this BIC's vulnerable code.
        - If decomposed: signals from the culprit sub-commit (only if it touched the blamed file)
        - If not decomposed: signals from the BIC commit itself (it IS the atomic commit)
        - PR-level signals are always included as supplementary evidence.
        """
        if self.culprit_sha and self.decomposed_commits:
            culprit = next(
                (dc for dc in self.decomposed_commits if dc.sha == self.culprit_sha),
                None,
            )
            if culprit and culprit.touched_blamed_file:
                return list(culprit.ai_signals) + list(self.pr_signals)
            # Culprit exists but didn't touch blamed file, or not found
            # PR signals alone are weak evidence — include them but commit signals are empty
            return list(self.pr_signals)
        # Not decomposed: commit itself is atomic
        return list(self.commit.ai_signals) + list(self.pr_signals)
```

### CveAnalysisResult: add `rebuild_signals()`

```python
@dataclass
class CveAnalysisResult:
    # ai_signals remains a stored field (backward compat with JSON cache)
    ai_signals: list[AiSignal] = field(default_factory=list)

    def rebuild_signals(self) -> None:
        """Rebuild top-level ai_signals from BIC effective_signals().

        Call this before every save to ensure top-level stays in sync.
        """
        signals: list[AiSignal] = []
        for bic in self.bug_introducing_commits:
            signals.extend(bic.effective_signals())
        self.ai_signals = signals
        self.deduplicate_signals()
```

## Smart Decomposition Triggers

Not every squash merge needs decomposition. API calls are expensive.

### When to decompose

| Condition | Decompose? | Rationale |
|-----------|-----------|-----------|
| BIC has AI signals | Yes | Find which sub-commit is the real author |
| BIC has no signals, repo has `repo_ai_activity` | Yes | Catch repos that strip trailers (OpenClaw pattern) |
| BIC has no signals, repo has no AI activity | No | Nothing to find |
| BIC is not a squash merge (individual commit) | No | Already atomic |

### API-efficient decomposition

Within a decomposition, minimize API calls:

1. Fetch PR commit list (1 API call)
2. Detect signals on each sub-commit via local regex (0 API calls)
3. **Only for sub-commits with AI signals:** fetch changed files (1 API call each)
4. For sub-commits without AI signals that touched the blamed file: no file fetch needed (we only care about AI authorship)

A 20-commit PR with 2 AI sub-commits costs 3 API calls instead of 21.

### Decomposition failure fallback

When decomposition fails (API rate limit, private repo, deleted PR):

- Set `decomposition_attempted = True`, `decomposition_failed = True` on the BIC
- Fall back to detecting signals on the squash merge commit itself
- Downstream knows these signals are unverified (squash-level, not atomic-level)

## Phase B.2: Signal Detection (new unified phase)

After decomposition, detect signals on the correct commits:

```python
def _detect_signals_on_bics(result: CveAnalysisResult) -> None:
    """Phase B.2: Detect AI signals on atomic commits.

    Runs AFTER decomposition (Phase B.1) so signals land on the right commit.
    """
    for bic in result.bug_introducing_commits:
        # 1. Commit-level signals on the atomic commit
        if bic.culprit_sha and bic.decomposed_commits:
            # Decomposed: detect on culprit sub-commit
            culprit = next(
                (dc for dc in bic.decomposed_commits if dc.sha == bic.culprit_sha),
                None,
            )
            if culprit:
                culprit.ai_signals = detect_ai_signals(culprit_as_commit_info)
                for sig in culprit.ai_signals:
                    sig.origin = "commit_metadata"
        else:
            # Not decomposed: detect on BIC commit
            bic.commit.ai_signals = detect_ai_signals(bic.commit)
            for sig in bic.commit.ai_signals:
                sig.origin = "commit_metadata"

        # 2. PR-level signals (supplementary)
        pr_body = fetch_pr_body(bic)  # may be cached from Phase B.1
        if pr_body:
            pr_sigs = detect_ai_signals_in_text(pr_body)
            for sig in pr_sigs:
                sig.origin = "pr_body"
            bic.pr_signals = filter_anachronistic(pr_sigs, bic.commit.authored_date)

    # 3. Rebuild top-level aggregate
    result.rebuild_signals()
```

## rescan_signals Simplification

With the `origin` field, rescan becomes straightforward:

```python
def rescan_signals():
    for result in cache.iter_cached():
        changed = False
        for bic in result.bug_introducing_commits:
            # Get the atomic commit's signals
            old_signals = bic.effective_signals()

            # Re-detect only commit_metadata signals
            new_metadata = detect_ai_signals(atomic_commit_for(bic))

            # Preserve non-metadata signals (pr_body, verifier_discovered)
            preserved = [s for s in old_signals if s.origin != "commit_metadata"]

            new_signals = new_metadata + preserved
            if signals_changed(old_signals, new_signals):
                write_signals_to_atomic(bic, new_signals)
                changed = True

        if changed:
            result.rebuild_signals()
            result.ai_confidence = compute_ai_confidence(result)
            cache.save_cached(result)
```

No more prefix-based hacks. No more API-only preservation lists. The `origin` field tells rescan exactly what it can and can't touch.

## Confidence Scoring Unification

### New module: `scoring.py`

Extract the confidence formula into a shared module:

```python
# cve_analyzer/scoring.py

def compute_ai_confidence(result: CveAnalysisResult) -> float:
    """Single confidence computation used by both pipeline and web data generation."""
    ...
```

Both `pipeline.py` and `generate_web_data.py` import from `scoring.py`. The duplicate `_recompute_ai_confidence` in `generate_web_data.py` is deleted.

## Signal Integrity Checker

### New module: `integrity.py`

```python
def verify_signal_integrity(result: CveAnalysisResult) -> list[str]:
    """Validate signal invariants. Returns list of violations (empty = valid)."""
    issues = []

    # 1. Top-level signals must match effective signals aggregate
    top = {(s.tool, s.signal_type, s.matched_text) for s in result.ai_signals}
    eff = set()
    for bic in result.bug_introducing_commits:
        for s in bic.effective_signals():
            eff.add((s.tool, s.signal_type, s.matched_text))
    if top != eff:
        issues.append("top-level ai_signals out of sync with effective_signals()")

    # 2. Decomposed BIC culprit must have touched_blamed_file if it has signals
    for bic in result.bug_introducing_commits:
        if bic.culprit_sha and bic.decomposed_commits:
            culprit = next((dc for dc in bic.decomposed_commits if dc.sha == bic.culprit_sha), None)
            if culprit and culprit.ai_signals and not culprit.touched_blamed_file:
                issues.append(
                    f"BIC {bic.commit.sha[:8]}: culprit has AI signals but touched_blamed_file=False"
                )

    # 3. ai_involved consistency
    if result.ai_involved is True and not any(
        bic.effective_signals() for bic in result.bug_introducing_commits
    ):
        issues.append("ai_involved=True but no effective signals on any BIC")

    # 4. All signals must have valid origin
    for bic in result.bug_introducing_commits:
        for sig in bic.effective_signals():
            if sig.origin not in ("commit_metadata", "pr_body", "verifier_discovered"):
                issues.append(f"Invalid signal origin: {sig.origin}")

    return issues
```

Called before every `cache.save_cached()`. Violations are logged as warnings (not fatal) to avoid blocking the pipeline during the transition period.

## Remaining Bug Fixes (included in this refactor)

### Already fixed (this session)
1. ~~rescan wipes pr_body_keyword~~ → `origin` field eliminates this
2. ~~rescan wipes squash_decomposed~~  → `origin` field eliminates this
3. ~~Propagation without touched_blamed_file~~ → `effective_signals()` checks this
4. ~~Bolt pattern matching human names~~ → word boundary fix
5. ~~@x.ai matching human employees~~ → narrowed pattern
6. ~~claude@anthropic.com missing~~ → added to patterns
7. ~~Top-level aggregate not rebuilding~~ → `rebuild_signals()` called before save

### To fix in this refactor
8. **UNRELATED deep_verification not excluding CVEs from website** → `_has_no_confirmed_verdict` loop fix
9. **Discovered BICs skip PR enrichment** → Phase B.1 runs on discovered BICs too (re-enter decomposition after Phase D)
10. **Confidence scoring duplication** → unified in `scoring.py`
11. **rescan uses author fields for committer** → `DecomposedCommit` adds `committer_name`, `committer_email` fields
12. **`_has_no_confirmed_verdict` early return on unverified BIC** → loop continues instead of returning

### Not in scope (design limitations, not bugs)
- Cross-file code move tracing (structural limit of git blame)
- OSV split advisory misattribution (data source issue)
- 5,077 CVEs with repo URL in refs but not extracted (coverage gap, separate project)

## Files to Modify

| File | Changes |
|------|---------|
| `models.py` | AiSignal: add `origin`. BIC: add `pr_signals`, `effective_signals()`, `decomposition_attempted`, `decomposition_failed`. CveAnalysisResult: add `rebuild_signals()`. DecomposedCommit: add `committer_name`, `committer_email`. |
| `pipeline.py` | Phase B: remove signal detection from `_collect_blamed()`. New Phase B.1 (decomposition). New Phase B.2 (signal detection). `rescan_signals()`: rewrite with `origin`-based logic. Remove `_apply_confidence_cleanup` signal clearing. Call `rebuild_signals()` before save. Call `verify_signal_integrity()` before save. Re-enter Phase B.1 for verifier-discovered BICs. |
| `pr_enrichment.py` | Split into decomposition (Phase B.1) and PR body scan (Phase B.2). `decompose_squash_signals()`: remove `squash_decomposed_` prefix. Add smart decomposition trigger (repo AI activity check). Add API-efficient file fetch (only for AI sub-commits). |
| `ai_signatures.py` | `detect_ai_signals()`: set `origin="commit_metadata"`. `detect_ai_signals_in_text()`: set `origin="pr_body"`. |
| `scoring.py` (new) | Extract `_compute_ai_confidence_score` from pipeline.py. Single implementation. |
| `integrity.py` (new) | `verify_signal_integrity()` function. |
| `generate_web_data.py` | Delete `_recompute_ai_confidence`, import from `scoring.py`. Fix `_has_no_confirmed_verdict` loop logic. Use `effective_signals()` concept for `ai_tools_set` computation. |
| `cache.py` | `save_cached()`: call `result.rebuild_signals()` and `verify_signal_integrity()` before write. |

## Migration Strategy

**Incremental compatibility (Option A):**

- New fields (`origin`, `pr_signals`, etc.) default to safe values in `from_dict()`
- Old cached results work without migration
- `origin` defaults to `"commit_metadata"` (safe assumption for pre-existing signals)
- `squash_decomposed_*` prefix still recognized during deserialization: mapped to `origin="commit_metadata"` with prefix stripped from `signal_type`
- `rescan_signals` gradually modernizes cache entries as they're touched
- No batch migration script needed

## Verification Plan

1. All 2274 existing tests pass
2. Re-run rescan on full cache — no signal loss, no new false positives
3. Regenerate web data — count should be >= 78 (no regressions)
4. Independent audit of 5 random CVEs from website — all confirmed TP
5. Re-analyze 3 known OpenClaw CVEs — signals correctly detected via smart decomposition
6. `verify_signal_integrity()` reports 0 violations on regenerated web data
