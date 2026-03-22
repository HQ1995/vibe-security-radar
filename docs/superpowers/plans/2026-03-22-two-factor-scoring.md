# Two-Factor Scoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Simplify AI confidence scoring to a principled two-factor formula (`signal_quality × causal_confidence`), removing noise-filtering hacks that are redundant with the decompose-first architecture.

**Architecture:** Replace three ad-hoc penalties (diffuse blame, indirect-only, confidence floor) with a single origin-based signal weight. The scoring formula becomes: `max(signal_confidence × origin_weight × blame_confidence × verdict_factor)` across all BICs. Deep verification handles causal confidence; `effective_signals()` handles signal correctness; origin weight handles evidence strength.

**Tech Stack:** Python 3.13, dataclasses

---

## Rationale

The three removed penalties were compensating for old-architecture problems:

| Penalty | Old problem it solved | Why redundant now |
|---------|----------------------|-------------------|
| Diffuse blame (>50 BICs) | Noisy blame → random AI signals | `effective_signals()` + `touched_blamed_file` filters noise at source |
| Indirect-only (0.25×) | `squash_decomposed_*` signals were unreliable | Decompose-first detects on atomic commits; `origin` field distinguishes evidence strength |
| Confidence floor (<0.05→0) | Squash prefix signals were noisy | Prefix hack eliminated; low scores are legitimate (PR body on large CVE) |

The replacement — `origin_weight` — captures the one real distinction: commit metadata (co-author trailer, author email) is stronger evidence than PR body text ("Generated with Claude").

## Origin Weights

| Origin | Weight | Rationale |
|--------|--------|-----------|
| `commit_metadata` | 1.0 | Direct evidence: the commit itself has AI authorship markers |
| `pr_body` | 0.5 | Indirect: PR description mentions AI, but doesn't prove which commit |
| `verifier_discovered` | 1.0 | Verifier found evidence through investigation — treat as direct |

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/cve_analyzer/scoring.py` | Modify | Remove 3 penalties, add `_ORIGIN_WEIGHTS`, simplify `compute_ai_confidence` |
| `tests/test_scoring.py` | Modify | Rewrite penalty tests → origin weight tests |
| `tests/test_pipeline_confidence.py` | Modify | Update indirect/diffuse/floor tests |
| `tests/test_bic_count_damping.py` | Delete | Diffuse blame penalty no longer exists |
| `tests/test_confidence_floor.py` | Delete | Confidence floor no longer exists |

---

### Task 1: Rewrite `compute_ai_confidence` with two-factor formula

**Files:**
- Modify: `src/cve_analyzer/scoring.py`

- [ ] **Step 1: Write failing test for origin weight**

```python
# Add to tests/test_scoring.py
def test_pr_body_signal_weighted_at_half():
    """PR body signal (origin=pr_body) gets 0.5 weight."""
    sig = AiSignal(tool=AiTool.CLAUDE_CODE, signal_type="pr_body_keyword",
                   matched_text="Generated with Claude", confidence=0.9,
                   origin="pr_body")
    bic = _make_bic(blame_conf=1.0, signals=[sig])
    result = _make_result([bic])
    score = compute_ai_confidence(result)
    assert score == 0.45  # 0.9 * 0.5 * 1.0

def test_commit_metadata_signal_full_weight():
    """Commit metadata signal gets full weight (no penalty)."""
    sig = AiSignal(tool=AiTool.CLAUDE_CODE, signal_type="co_author_trailer",
                   matched_text="Co-Authored-By: Claude", confidence=0.95,
                   origin="commit_metadata")
    bic = _make_bic(blame_conf=0.9, signals=[sig])
    result = _make_result([bic])
    score = compute_ai_confidence(result)
    assert score == 0.855  # 0.95 * 1.0 * 0.9

def test_no_diffuse_blame_penalty():
    """Score is NOT reduced when many BICs exist."""
    sig = AiSignal(tool=AiTool.CLAUDE_CODE, signal_type="co_author_trailer",
                   matched_text="Co-Authored-By: Claude", confidence=0.95,
                   origin="commit_metadata")
    ai_bic = _make_bic(blame_conf=0.9, signals=[sig])
    non_ai_bics = [_make_bic(blame_conf=0.9, signals=[]) for _ in range(100)]
    result = _make_result([ai_bic] + non_ai_bics)
    score = compute_ai_confidence(result)
    assert score == 0.855  # same as single BIC — no diffuse penalty

def test_no_confidence_floor():
    """Low scores are preserved, not floored to zero."""
    sig = AiSignal(tool=AiTool.CLAUDE_CODE, signal_type="pr_body_keyword",
                   matched_text="Claude", confidence=0.04,
                   origin="pr_body")
    bic = _make_bic(blame_conf=1.0, signals=[sig])
    result = _make_result([bic])
    score = compute_ai_confidence(result)
    assert score == 0.02  # 0.04 * 0.5 — NOT floored to 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd cve-analyzer && uv run pytest tests/test_scoring.py::test_pr_body_signal_weighted_at_half -v`
Expected: FAIL

- [ ] **Step 3: Rewrite scoring.py**

Replace `compute_ai_confidence` body:

```python
_ORIGIN_WEIGHTS: dict[str, float] = {
    "commit_metadata": 1.0,
    "pr_body": 0.5,
    "verifier_discovered": 1.0,
}
"""Signal weight by origin. commit_metadata is direct evidence (co-author trailer,
author email). pr_body is indirect (PR description mentions AI tool). verifier_discovered
is treated as direct (verifier found evidence through investigation)."""


def compute_ai_confidence(result: CveAnalysisResult) -> float:
    """Two-factor AI confidence: signal_quality × causal_confidence.

    signal_quality = max(signal.confidence × origin_weight)
    causal_confidence = blame_confidence × verdict_factor

    Returns max score across all non-excluded BICs. 0.0 if no AI signals.
    """
    if not result.bug_introducing_commits:
        return 0.0

    max_score = 0.0
    for bic in result.bug_introducing_commits:
        signals = bic.effective_signals()
        if not signals:
            continue
        if bic_is_excluded(bic):
            continue
        authorship = [s for s in signals if s.signal_type not in WORKFLOW_SIGNAL_TYPES]
        if not authorship:
            continue

        # Signal quality: best weighted signal confidence
        signal_quality = max(
            s.confidence * _ORIGIN_WEIGHTS.get(s.origin, 1.0)
            for s in authorship
        )

        # Causal confidence: blame × verdict
        causal = bic.blame_confidence * _get_unlikely_penalty(bic)

        score = signal_quality * causal
        if score > max_score:
            max_score = score

    return round(max_score, 4)
```

Delete these constants and code blocks:
- `_INDIRECT_ONLY_PENALTY` (line 18)
- Indirect-only penalty block (lines 133-143)
- Diffuse blame penalty block (lines 145-153)
- Confidence floor block (lines 155-158)
- `ai_bic_count` tracking (line 109, 125)
- `best_bic_authorship` tracking (lines 108, 131)

- [ ] **Step 4: Run new tests to verify they pass**

Run: `cd cve-analyzer && uv run pytest tests/test_scoring.py -k "test_pr_body_signal_weighted_at_half or test_commit_metadata_signal_full_weight or test_no_diffuse_blame_penalty or test_no_confidence_floor" -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/cve_analyzer/scoring.py tests/test_scoring.py
git commit -m "refactor: simplify scoring to two-factor formula (signal × causal)"
```

---

### Task 2: Update existing scoring tests

**Files:**
- Modify: `tests/test_scoring.py`
- Modify: `tests/test_pipeline_confidence.py`
- Delete: `tests/test_bic_count_damping.py`
- Delete: `tests/test_confidence_floor.py`

- [ ] **Step 1: Update test_scoring.py**

Tests to update:
- Indirect-only penalty tests → rewrite as origin weight tests (pr_body = 0.5×)
- Diffuse blame tests → delete or convert to "no penalty regardless of BIC count"
- Confidence floor tests → delete or convert to "low scores preserved"
- Tests that assert exact scores with old penalties → recalculate expected values

Specific tests that WILL BREAK with wrong expected values:

| Test | Old assertion | New expected | Formula |
|------|-------------|-------------|---------|
| `test_verifier_discovered_treated_as_indirect` | `0.85*0.9*0.25 = 0.1913` | `0.85*1.0*0.9 = 0.765` | verifier_discovered weight = 1.0, not indirect |
| `test_culprit_not_touching_file_but_has_pr_signals` | `0.7*0.9*0.25 = 0.1575` | `0.7*0.5*0.9 = 0.315` | pr_body weight = 0.5 replaces 0.25 penalty |
| `test_indirect_penalty_stacks_with_unlikely` | `0.8*0.9*0.25*0.25 = 0.045 → 0.0 (floor)` | `0.8*0.5*0.9*0.25 = 0.09` | No floor, pr_body 0.5 instead of indirect 0.25 |
| `test_pr_body_signal_penalized` (pipeline_confidence) | asserts old 0.25× penalty | assert 0.5× weight | |
| `test_unlikely_stacks_with_indirect_penalty` (pipeline_confidence) | `floor → 0.0` | `> 0` | No floor |

- [ ] **Step 2: Update test_pipeline_confidence.py**

Update tests:
- `test_indirect_only_pr_body_signals_penalized` → verify 0.5× weight instead of 0.25× penalty
- `test_mixed_direct_and_indirect_not_penalized` → verify direct signal dominates
- `test_diffuse_blame_*` tests → delete
- `test_unlikely_stacks_with_indirect_penalty` → update to stack with origin weight
- `test_zero_confidence_below_floor` → delete or invert (score should be > 0)

- [ ] **Step 3: Delete test_bic_count_damping.py**

```bash
git rm tests/test_bic_count_damping.py
```

- [ ] **Step 4: Delete test_confidence_floor.py**

```bash
git rm tests/test_confidence_floor.py
```

- [ ] **Step 5: Run full test suite**

Run: `cd cve-analyzer && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add tests/ && git commit -m "test: update scoring tests for two-factor formula"
```

---

### Task 3: Regenerate web data and verify

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cd cve-analyzer && uv run pytest tests/ -x -q`

- [ ] **Step 2: Regenerate web data**

Run: `cd .. && python scripts/generate_web_data.py`
Expected: count >= 77

- [ ] **Step 3: Spot-check score changes**

Compare new vs old scores for known CVEs:
- CVEs with only `pr_body` signals should have higher scores (0.5× vs 0.25×)
- CVEs with `commit_metadata` signals should be unchanged
- No CVEs should have score = 0.0 that previously had signals (floor removed)

- [ ] **Step 4: Commit web data**

```bash
git add web/data/cves.json web/data/stats.json
git commit -m "data: regenerate after two-factor scoring simplification"
```
