# Decompose-First Signal Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the signal pipeline so signal detection runs after squash decomposition, on atomic commits, eliminating signal propagation/cleanup bugs.

**Architecture:** Move decomposition before signal detection (Phase B → B.1 → B.2). Add `origin` field to AiSignal for provenance tracking. Replace scattered signal aggregation with `effective_signals()` single source of truth. Unify confidence scoring in a shared module.

**Tech Stack:** Python 3.13, dataclasses, httpx, subprocess (git)

**Spec:** `docs/superpowers/specs/2026-03-22-decompose-first-signal-architecture-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/cve_analyzer/models.py` | Modify | AiSignal `origin`, BIC `pr_signals` + `effective_signals()`, CveAnalysisResult `rebuild_signals()`, DecomposedCommit committer fields |
| `src/cve_analyzer/scoring.py` | Create | Unified confidence computation (`compute_ai_confidence`) |
| `src/cve_analyzer/integrity.py` | Create | Signal integrity validation (`verify_signal_integrity`) |
| `src/cve_analyzer/pipeline.py` | Modify | Reorder phases, delete `_apply_confidence_cleanup`, rewrite `rescan_signals`, update `_collect_blamed` |
| `src/cve_analyzer/pr_enrichment.py` | Modify | Split into decomposition + PR body scan, add smart triggers |
| `src/cve_analyzer/ai_signatures.py` | Modify | Set `origin` on returned signals |
| `src/cve_analyzer/cache.py` | Modify | Call `rebuild_signals()` + `verify_signal_integrity()` before save |
| `scripts/generate_web_data.py` | Modify | Delete duplicate confidence, use effective_signals concept |
| `tests/test_signal_origin.py` | Create | Origin field migration + preservation tests |
| `tests/test_effective_signals.py` | Create | effective_signals() logic tests |
| `tests/test_scoring.py` | Create | Unified scoring tests |
| `tests/test_integrity.py` | Create | Integrity checker tests |

---

### Task 1: AiSignal `origin` Field

**Files:**
- Modify: `src/cve_analyzer/models.py:122-144`
- Create: `tests/test_signal_origin.py`

- [ ] **Step 1: Write failing test for origin field**

```python
# tests/test_signal_origin.py
from cve_analyzer.models import AiSignal, AiTool

def test_ai_signal_default_origin():
    sig = AiSignal(tool=AiTool.CLAUDE_CODE, signal_type="co_author_trailer",
                   matched_text="Co-Authored-By: Claude", confidence=0.95)
    assert sig.origin == "commit_metadata"

def test_ai_signal_custom_origin():
    sig = AiSignal(tool=AiTool.CLAUDE_CODE, signal_type="pr_body_keyword",
                   matched_text="Generated with Claude", confidence=0.9,
                   origin="pr_body")
    assert sig.origin == "pr_body"

def test_ai_signal_to_dict_includes_origin():
    sig = AiSignal(tool=AiTool.CLAUDE_CODE, signal_type="co_author_trailer",
                   matched_text="test", confidence=0.95, origin="pr_body")
    d = sig.to_dict()
    assert d["origin"] == "pr_body"

def test_ai_signal_from_dict_with_origin():
    d = {"tool": "claude_code", "signal_type": "co_author_trailer",
         "matched_text": "test", "confidence": 0.95, "origin": "pr_body"}
    sig = AiSignal.from_dict(d)
    assert sig.origin == "pr_body"

def test_ai_signal_from_dict_without_origin_defaults():
    """Old cached data without origin field."""
    d = {"tool": "claude_code", "signal_type": "co_author_trailer",
         "matched_text": "test", "confidence": 0.95}
    sig = AiSignal.from_dict(d)
    assert sig.origin == "commit_metadata"

def test_ai_signal_from_dict_infers_pr_body_origin():
    """Old cached pr_body_keyword signals get origin=pr_body."""
    d = {"tool": "claude_code", "signal_type": "pr_body_keyword",
         "matched_text": "Generated with Claude", "confidence": 0.9}
    sig = AiSignal.from_dict(d)
    assert sig.origin == "pr_body"

def test_ai_signal_from_dict_strips_squash_decomposed_prefix():
    """Old cached squash_decomposed_* signals: strip prefix, origin=commit_metadata."""
    d = {"tool": "claude_code", "signal_type": "squash_decomposed_co_author_trailer",
         "matched_text": "Co-Authored-By: Claude", "confidence": 0.95}
    sig = AiSignal.from_dict(d)
    assert sig.signal_type == "co_author_trailer"
    assert sig.origin == "commit_metadata"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd cve-analyzer && uv run pytest tests/test_signal_origin.py -v`
Expected: FAIL — AiSignal has no `origin` field

- [ ] **Step 3: Implement origin field on AiSignal**

In `models.py`, update `AiSignal`:

```python
@dataclass
class AiSignal:
    tool: AiTool
    signal_type: str
    matched_text: str
    confidence: float
    origin: str = "commit_metadata"  # commit_metadata | pr_body | verifier_discovered

    def to_dict(self) -> dict:
        d = {
            "tool": self.tool.value,
            "signal_type": self.signal_type,
            "matched_text": self.matched_text,
            "confidence": self.confidence,
        }
        if self.origin != "commit_metadata":
            d["origin"] = self.origin
        return d

    @classmethod
    def from_dict(cls, data: dict) -> AiSignal:
        signal_type = data["signal_type"]
        # Migration: infer origin from signal_type for old cached data
        origin = data.get("origin", "")
        if not origin:
            if signal_type in ("pr_body_keyword", "pr_body"):
                origin = "pr_body"
            elif signal_type.startswith("squash_decomposed_"):
                signal_type = signal_type.removeprefix("squash_decomposed_")
                origin = "commit_metadata"
            else:
                origin = "commit_metadata"
        return cls(
            tool=AiTool(data["tool"]),
            signal_type=signal_type,
            matched_text=data["matched_text"],
            confidence=data["confidence"],
            origin=origin,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd cve-analyzer && uv run pytest tests/test_signal_origin.py -v`
Expected: All PASS

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `cd cve-analyzer && uv run pytest tests/ -x -q`
Expected: 2274+ passed (some tests may need updating if they check `signal_type` values containing `squash_decomposed_` prefix)

- [ ] **Step 6: Commit**

```bash
git add src/cve_analyzer/models.py tests/test_signal_origin.py
git commit -m "feat: add origin field to AiSignal with old-cache migration"
```

---

### Task 2: BIC `pr_signals` and `effective_signals()`

**Files:**
- Modify: `src/cve_analyzer/models.py:276-331`
- Create: `tests/test_effective_signals.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_effective_signals.py
from cve_analyzer.models import (
    AiSignal, AiTool, BugIntroducingCommit, CommitInfo, DecomposedCommit,
)

def _commit(sha="abc123", signals=None):
    return CommitInfo(sha=sha, author_name="A", author_email="a@b.com",
                      committer_name="A", committer_email="a@b.com",
                      message="msg", authored_date="2025-01-01",
                      ai_signals=signals or [])

def _sig(tool=AiTool.CLAUDE_CODE, stype="co_author_trailer", origin="commit_metadata"):
    return AiSignal(tool=tool, signal_type=stype, matched_text="test",
                    confidence=0.95, origin=origin)

def _dc(sha="sub1", signals=None, touched=None):
    return DecomposedCommit(sha=sha, author_name="A", author_email="a@b.com",
                            message="msg", ai_signals=signals or [],
                            touched_blamed_file=touched)


def test_non_decomposed_returns_commit_signals():
    bic = BugIntroducingCommit(commit=_commit(signals=[_sig()]),
                               fix_commit_sha="fix1", blamed_file="a.py",
                               blamed_lines=[1])
    assert len(bic.effective_signals()) == 1
    assert bic.effective_signals()[0].signal_type == "co_author_trailer"

def test_non_decomposed_includes_pr_signals():
    pr = _sig(stype="pr_body_keyword", origin="pr_body")
    bic = BugIntroducingCommit(commit=_commit(), fix_commit_sha="fix1",
                               blamed_file="a.py", blamed_lines=[1],
                               pr_signals=[pr])
    assert len(bic.effective_signals()) == 1
    assert bic.effective_signals()[0].origin == "pr_body"

def test_decomposed_culprit_touched_returns_culprit_signals():
    culprit = _dc(sha="sub1", signals=[_sig()], touched=True)
    bic = BugIntroducingCommit(commit=_commit(), fix_commit_sha="fix1",
                               blamed_file="a.py", blamed_lines=[1],
                               decomposed_commits=[culprit, _dc(sha="sub2")],
                               culprit_sha="sub1")
    assert len(bic.effective_signals()) == 1

def test_decomposed_culprit_not_touched_returns_empty_plus_pr():
    culprit = _dc(sha="sub1", signals=[_sig()], touched=False)
    pr = _sig(stype="pr_body_keyword", origin="pr_body")
    bic = BugIntroducingCommit(commit=_commit(), fix_commit_sha="fix1",
                               blamed_file="a.py", blamed_lines=[1],
                               decomposed_commits=[culprit],
                               culprit_sha="sub1",
                               pr_signals=[pr])
    eff = bic.effective_signals()
    # Only PR signal, no commit signal (culprit didn't touch file)
    assert len(eff) == 1
    assert eff[0].origin == "pr_body"

def test_decomposed_no_culprit_sha_returns_commit_signals():
    """Decomposition attempted but culprit not identified."""
    bic = BugIntroducingCommit(commit=_commit(signals=[_sig()]),
                               fix_commit_sha="fix1", blamed_file="a.py",
                               blamed_lines=[1],
                               decomposed_commits=[_dc(sha="sub1")])
    # No culprit_sha → fall through to commit signals
    assert len(bic.effective_signals()) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd cve-analyzer && uv run pytest tests/test_effective_signals.py -v`
Expected: FAIL — BIC has no `pr_signals` or `effective_signals()`

- [ ] **Step 3: Implement pr_signals and effective_signals()**

In `models.py`, update `BugIntroducingCommit`:

```python
@dataclass
class BugIntroducingCommit:
    commit: CommitInfo
    fix_commit_sha: str
    blamed_file: str
    blamed_lines: list[int]
    blame_confidence: float = 1.0
    blame_strategy: BlameStrategy | str = ""
    screening_verification: LlmVerdict | None = None
    tribunal_verdict: dict | None = None
    deep_verification: dict | None = None
    decomposed_commits: list[DecomposedCommit] = field(default_factory=list)
    culprit_sha: str = ""
    pr_signals: list[AiSignal] = field(default_factory=list)

    def effective_signals(self) -> list[AiSignal]:
        """Authoritative signals from the atomic commit + PR-level signals."""
        if self.culprit_sha and self.decomposed_commits:
            culprit = next(
                (dc for dc in self.decomposed_commits if dc.sha == self.culprit_sha),
                None,
            )
            if culprit and culprit.touched_blamed_file:
                return list(culprit.ai_signals) + list(self.pr_signals)
            return list(self.pr_signals)
        return list(self.commit.ai_signals) + list(self.pr_signals)
```

Update `to_dict()` to serialize `pr_signals`:
```python
    if self.pr_signals:
        d["pr_signals"] = [s.to_dict() for s in self.pr_signals]
```

Update `from_dict()` to deserialize `pr_signals`:
```python
    pr_signals=[AiSignal.from_dict(s) for s in data.get("pr_signals", [])],
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd cve-analyzer && uv run pytest tests/test_effective_signals.py tests/test_signal_origin.py -v`
Expected: All PASS

- [ ] **Step 5: Run full test suite**

Run: `cd cve-analyzer && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/cve_analyzer/models.py tests/test_effective_signals.py
git commit -m "feat: add BIC effective_signals() and pr_signals field"
```

---

### Task 3: `rebuild_signals()` on CveAnalysisResult

**Files:**
- Modify: `src/cve_analyzer/models.py:334-407`
- Add test in: `tests/test_effective_signals.py`

- [ ] **Step 1: Write failing test**

```python
# append to tests/test_effective_signals.py
from cve_analyzer.models import CveAnalysisResult

def test_rebuild_signals_aggregates_from_effective():
    bic1 = BugIntroducingCommit(commit=_commit(signals=[_sig()]),
                                fix_commit_sha="fix1", blamed_file="a.py",
                                blamed_lines=[1])
    bic2 = BugIntroducingCommit(commit=_commit(sha="def456"),
                                fix_commit_sha="fix1", blamed_file="b.py",
                                blamed_lines=[2])
    result = CveAnalysisResult(cve_id="CVE-TEST", bug_introducing_commits=[bic1, bic2])
    assert result.ai_signals == []  # not yet rebuilt
    result.rebuild_signals()
    assert len(result.ai_signals) == 1  # only bic1 has signals

def test_rebuild_signals_deduplicates():
    sig = _sig()
    bic1 = BugIntroducingCommit(commit=_commit(signals=[sig]),
                                fix_commit_sha="fix1", blamed_file="a.py",
                                blamed_lines=[1])
    bic2 = BugIntroducingCommit(commit=_commit(sha="def456", signals=[sig]),
                                fix_commit_sha="fix1", blamed_file="b.py",
                                blamed_lines=[2])
    result = CveAnalysisResult(cve_id="CVE-TEST", bug_introducing_commits=[bic1, bic2])
    result.rebuild_signals()
    assert len(result.ai_signals) == 1  # deduped
```

- [ ] **Step 2: Run to verify fail**

Run: `cd cve-analyzer && uv run pytest tests/test_effective_signals.py::test_rebuild_signals_aggregates_from_effective -v`
Expected: FAIL — no `rebuild_signals` method

- [ ] **Step 3: Implement rebuild_signals()**

In `models.py`, add to `CveAnalysisResult`:

```python
    def rebuild_signals(self) -> None:
        """Rebuild top-level ai_signals from BIC effective_signals()."""
        signals: list[AiSignal] = []
        for bic in self.bug_introducing_commits:
            signals.extend(bic.effective_signals())
        self.ai_signals = signals
        self.deduplicate_signals()
```

- [ ] **Step 4: Run tests**

Run: `cd cve-analyzer && uv run pytest tests/test_effective_signals.py -v`
Expected: All PASS

- [ ] **Step 5: Full test suite**

Run: `cd cve-analyzer && uv run pytest tests/ -x -q`

- [ ] **Step 6: Commit**

```bash
git add src/cve_analyzer/models.py tests/test_effective_signals.py
git commit -m "feat: add CveAnalysisResult.rebuild_signals()"
```

---

### Task 4: DecomposedCommit Committer Fields

**Files:**
- Modify: `src/cve_analyzer/models.py:237-273`

- [ ] **Step 1: Write failing test**

```python
# append to tests/test_signal_origin.py
from cve_analyzer.models import DecomposedCommit

def test_decomposed_commit_committer_fields():
    dc = DecomposedCommit(sha="abc", author_name="A", author_email="a@b.com",
                          message="msg", committer_name="C", committer_email="c@b.com")
    d = dc.to_dict()
    assert d["committer_name"] == "C"
    dc2 = DecomposedCommit.from_dict(d)
    assert dc2.committer_name == "C"

def test_decomposed_commit_committer_defaults_to_author():
    d = {"sha": "abc", "author_name": "A", "author_email": "a@b.com", "message": "m"}
    dc = DecomposedCommit.from_dict(d)
    assert dc.committer_name == "A"
    assert dc.committer_email == "a@b.com"
```

- [ ] **Step 2: Run to verify fail**

- [ ] **Step 3: Add committer fields to DecomposedCommit**

```python
@dataclass
class DecomposedCommit:
    sha: str
    author_name: str
    author_email: str
    message: str
    ai_signals: list[AiSignal] = field(default_factory=list)
    touched_blamed_file: bool | None = None
    committer_name: str = ""
    committer_email: str = ""
```

Update `to_dict()`: add `committer_name`/`committer_email` if non-empty.
Update `from_dict()`: read from dict, default to `author_name`/`author_email`.

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Full test suite**

- [ ] **Step 6: Commit**

```bash
git add src/cve_analyzer/models.py tests/test_signal_origin.py
git commit -m "feat: add committer fields to DecomposedCommit"
```

---

### Task 5: Unified Scoring Module

**Files:**
- Create: `src/cve_analyzer/scoring.py`
- Create: `tests/test_scoring.py`
- Modify: `src/cve_analyzer/pipeline.py:1061-1203`

- [ ] **Step 1: Write tests for scoring module**

Create `tests/test_scoring.py` with tests that exercise the confidence formula using `effective_signals()`:
- BIC with authorship signals → positive score
- BIC with only workflow signals → score 0
- BIC with UNLIKELY deep verdict → penalized score
- Decomposed BIC where culprit touched file → positive score
- Decomposed BIC where culprit didn't touch file → score 0
- Mixed BICs → max score wins

- [ ] **Step 2: Run to verify fail**

- [ ] **Step 3: Extract scoring to `scoring.py`**

Copy `_compute_ai_confidence_score` from `pipeline.py:1061-1142` into `scoring.py`. Key change: replace `bic.commit.ai_signals` with `bic.effective_signals()` throughout. Import `WORKFLOW_SIGNAL_TYPES` from models.

```python
# src/cve_analyzer/scoring.py
"""Unified AI confidence scoring — single implementation for pipeline and web data."""
from cve_analyzer.models import CveAnalysisResult, WORKFLOW_SIGNAL_TYPES

def compute_ai_confidence(result: CveAnalysisResult) -> float:
    """Compute aggregate AI confidence score from effective signals."""
    # ... (extracted from pipeline.py, using bic.effective_signals())
```

- [ ] **Step 4: Update pipeline.py to import from scoring.py**

Replace `_compute_ai_confidence_score` calls with `scoring.compute_ai_confidence`.
Delete `_compute_ai_confidence_score`, `_apply_confidence_cleanup`, and `_compute_and_apply_ai_confidence` from pipeline.py.
Replace all call sites (lines ~3191, ~3412, ~3636) with:
```python
result.rebuild_signals()
result.ai_confidence = scoring.compute_ai_confidence(result)
```

- [ ] **Step 5: Run tests**

Run: `cd cve-analyzer && uv run pytest tests/test_scoring.py tests/ -x -q`

- [ ] **Step 6: Commit**

```bash
git add src/cve_analyzer/scoring.py tests/test_scoring.py src/cve_analyzer/pipeline.py
git commit -m "refactor: extract unified scoring to scoring.py using effective_signals()"
```

---

### Task 6: Integrity Checker

**Files:**
- Create: `src/cve_analyzer/integrity.py`
- Create: `tests/test_integrity.py`
- Modify: `src/cve_analyzer/cache.py`

- [ ] **Step 1: Write tests**

Test cases: top-level sync check, culprit touch validation, origin validation, ai_involved consistency.

- [ ] **Step 2: Run to verify fail**

- [ ] **Step 3: Implement `integrity.py`**

```python
# src/cve_analyzer/integrity.py
import logging
from cve_analyzer.models import CveAnalysisResult

logger = logging.getLogger(__name__)

def verify_signal_integrity(result: CveAnalysisResult) -> list[str]:
    """Validate signal invariants. Returns list of violations."""
    # ... (as specified in spec, using tool.value for set comparison)
```

- [ ] **Step 4: Wire into cache.py**

In `cache.py`, `save_cached()`:
```python
def save_cached(cve_id: str, result: CveAnalysisResult) -> None:
    from cve_analyzer.integrity import verify_signal_integrity
    result.rebuild_signals()
    issues = verify_signal_integrity(result)
    if issues:
        import logging
        logging.getLogger(__name__).warning(
            "Signal integrity issues in %s: %s", cve_id, "; ".join(issues)
        )
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{cve_id}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2))
```

- [ ] **Step 5: Run full test suite**

- [ ] **Step 6: Commit**

```bash
git add src/cve_analyzer/integrity.py tests/test_integrity.py src/cve_analyzer/cache.py
git commit -m "feat: add signal integrity checker, wire into cache save"
```

---

### Task 7: Remove Signal Detection from `_collect_blamed()`

**Files:**
- Modify: `src/cve_analyzer/pipeline.py:1770-1857`

This is the core phase reorder: Phase B no longer detects signals.

- [ ] **Step 1: Write test that verifies BICs are created without signals**

```python
# Test that _collect_blamed no longer sets ai_signals on commits
# (signals will be set later in Phase B.2)
```

- [ ] **Step 2: Remove signal detection from `_collect_blamed()`**

In `pipeline.py:1825-1826`, remove:
```python
signals = ai_signatures.detect_ai_signals(commit_info)
commit_info.ai_signals = signals
```

Also remove the `result.ai_signals.extend(signals)` at line 1857.

Update the per-SHA file cap (line 1831): remove `if not signals and` — all commits are now treated equally at this stage (signals come later in Phase B.2).

- [ ] **Step 3: Run test suite — expect some failures**

Some existing tests may depend on signals being set during blame. Fix those tests to account for the new phase ordering.

- [ ] **Step 4: Commit**

```bash
git add src/cve_analyzer/pipeline.py
git commit -m "refactor: remove signal detection from _collect_blamed (Phase B)"
```

---

### Task 8: Split PR Enrichment into B.1 (Decompose) + B.2 (Signals)

**Files:**
- Modify: `src/cve_analyzer/pr_enrichment.py`
- Modify: `src/cve_analyzer/pipeline.py:3555-3560`

- [ ] **Step 1: Split `enrich_bics_with_pr_body_signals()` into two functions**

```python
def decompose_bics(result, token, *, verbose=False):
    """Phase B.1: Decompose squash merges, find culprit sub-commits.

    Smart triggers: only decompose when BIC has AI signals OR repo has AI activity.
    """
    ...

def detect_bic_signals(result, token, *, verbose=False):
    """Phase B.2: Detect signals on atomic commits + PR body scan.

    Runs AFTER decomposition. Signals land on the correct (atomic) commit.
    """
    for bic in result.bug_introducing_commits:
        # 1. Commit-level signals on atomic commit
        if bic.culprit_sha and bic.decomposed_commits:
            culprit = next((dc for dc in bic.decomposed_commits
                           if dc.sha == bic.culprit_sha), None)
            if culprit:
                ci = _dc_to_commit_info(culprit)
                culprit.ai_signals = ai_signatures.detect_ai_signals(ci)
                for sig in culprit.ai_signals:
                    sig.origin = "commit_metadata"
        else:
            bic.commit.ai_signals = ai_signatures.detect_ai_signals(bic.commit)
            for sig in bic.commit.ai_signals:
                sig.origin = "commit_metadata"

        # 2. PR body scan
        pr_body = _fetch_pr_body_cached(bic, token)
        if pr_body:
            pr_sigs = ai_signatures.detect_ai_signals_in_text(pr_body)
            for sig in pr_sigs:
                sig.origin = "pr_body"
            bic.pr_signals = ai_signatures.filter_anachronistic_signals(
                pr_sigs, bic.commit.authored_date
            )

    result.rebuild_signals()
```

- [ ] **Step 2: Update `decompose_squash_signals()` to drop `squash_decomposed_` prefix**

Signals detected on sub-commits are now just regular signals (e.g., `co_author_trailer` not `squash_decomposed_co_author_trailer`). The `origin` field tracks provenance instead.

- [ ] **Step 3: Add smart decomposition trigger**

In `decompose_bics()`:
```python
for bic in result.bug_introducing_commits:
    if not _is_squash_merge(bic):
        continue
    has_signals = bool(bic.commit.ai_signals)
    repo_has_ai = bool(result.repo_ai_activity)
    if not has_signals and not repo_has_ai:
        # Lightweight AI scan for single-CVE mode
        if not repo_has_ai:
            repo_has_ai = _quick_ai_scan(local_path)
    if has_signals or repo_has_ai:
        _decompose_bic(bic, token, ...)
```

- [ ] **Step 4: Update pipeline.py orchestration**

In `_blame_for_batch()`, replace:
```python
_enrich_bics_with_pr_body_signals(result, token, verbose=verbose)
_phase_times["Phase B.5 (PR enrich)"] = ...
```
With:
```python
# Phase B.1: Decompose squash merges
_t0 = time.monotonic()
decompose_bics(result, token, verbose=verbose)
_phase_times["Phase B.1 (decompose)"] = time.monotonic() - _t0

# Phase B.2: Detect signals on atomic commits
_t0 = time.monotonic()
detect_bic_signals(result, token, verbose=verbose)
_phase_times["Phase B.2 (signals)"] = time.monotonic() - _t0
```

Update `_needs_enrich` guard to recognize both old and new phase keys.

- [ ] **Step 5: Update Phase D.5 re-enrichment**

After deep verify discovers new BICs (pipeline.py ~3622-3633), call both `decompose_bics()` and `detect_bic_signals()` on the newly discovered BICs.

- [ ] **Step 6: Run full test suite**

Run: `cd cve-analyzer && uv run pytest tests/ -x -q`
Fix any test failures from the phase split.

- [ ] **Step 7: Commit**

```bash
git add src/cve_analyzer/pr_enrichment.py src/cve_analyzer/pipeline.py
git commit -m "refactor: split Phase B.5 into B.1 (decompose) + B.2 (signals)"
```

---

### Task 9: Set `origin` in Signal Detection Functions

**Files:**
- Modify: `src/cve_analyzer/ai_signatures.py`

- [ ] **Step 1: Write test**

```python
def test_detect_ai_signals_sets_commit_metadata_origin():
    ci = CommitInfo(sha="abc", author_name="Claude", author_email="noreply@anthropic.com",
                    committer_name="GitHub", committer_email="noreply@github.com",
                    message="feat: add feature", authored_date="2025-06-01")
    signals = ai_signatures.detect_ai_signals(ci)
    assert all(s.origin == "commit_metadata" for s in signals)

def test_detect_ai_signals_in_text_sets_pr_body_origin():
    signals = ai_signatures.detect_ai_signals_in_text("Generated with Claude Code")
    assert all(s.origin == "pr_body" for s in signals)
```

- [ ] **Step 2: Implement**

In `detect_ai_signals()` (~line 1920), before returning:
```python
for sig in signals:
    sig.origin = "commit_metadata"
```

In `detect_ai_signals_in_text()` (~line 2020), before returning:
```python
for sig in signals:
    sig.origin = "pr_body"
```

- [ ] **Step 3: Run tests, commit**

```bash
git commit -m "feat: set origin field in signal detection functions"
```

---

### Task 10: Rewrite `rescan_signals()` with Origin-Based Logic

**Files:**
- Modify: `src/cve_analyzer/pipeline.py:3066-3206`
- Create: `tests/test_rescan_origin.py`

- [ ] **Step 1: Write fixture-based tests**

Test with old-format signals (`squash_decomposed_*`, `pr_body_keyword`): verify rescan preserves them correctly under origin-based logic. Test that `commit_metadata` signals are re-detected. Test that `pr_body` signals are preserved without API calls.

- [ ] **Step 2: Rewrite rescan_signals()**

Replace the entire function body with origin-based logic:
```python
def rescan_signals(*, dry_run=False, verbose=False):
    for result in cache.iter_cached():
        changed = False
        for bic in result.bug_introducing_commits:
            # Determine atomic commit
            if bic.culprit_sha and bic.decomposed_commits:
                culprit = next((dc for dc in bic.decomposed_commits
                               if dc.sha == bic.culprit_sha), None)
                if culprit:
                    ci = _dc_to_commit_info(culprit)
                    new_metadata = ai_signatures.detect_ai_signals(ci)
                    old_sigs = culprit.ai_signals
                    preserved = [s for s in old_sigs if s.origin != "commit_metadata"]
                    new_sigs = new_metadata + preserved
                    if _signals_changed(old_sigs, new_sigs):
                        culprit.ai_signals = new_sigs
                        changed = True
                    continue
            # Non-decomposed: re-detect on BIC commit
            new_metadata = ai_signatures.detect_ai_signals(bic.commit)
            old_sigs = bic.commit.ai_signals
            preserved = [s for s in old_sigs if s.origin != "commit_metadata"]
            new_sigs = new_metadata + preserved
            if _signals_changed(old_sigs, new_sigs):
                bic.commit.ai_signals = new_sigs
                changed = True

        if changed or _top_level_stale(result):
            result.rebuild_signals()
            result.ai_confidence = scoring.compute_ai_confidence(result)
            if not dry_run:
                cache.save_cached(result.cve_id, result)
```

Delete all the old prefix-based preservation code, squash decomposition cleanup, and API-only signal lists.

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor: rewrite rescan_signals with origin-based preservation"
```

---

### Task 11: Update `generate_web_data.py`

**Files:**
- Modify: `scripts/generate_web_data.py`

- [ ] **Step 1: Delete duplicate confidence computation**

Remove `_recompute_ai_confidence` function. Import `compute_ai_confidence` from `cve_analyzer.scoring`.

- [ ] **Step 2: Update `ai_tools_set` computation**

Change `build_cve_entry()` to use effective_signals concept: for each BIC, consult `culprit.ai_signals` if decomposed (not just `bic.commit.ai_signals`). Mirror the `effective_signals()` logic.

- [ ] **Step 3: Fix `_has_no_confirmed_verdict` loop**

Fix the early return on unverified BIC (line 836): the loop should continue checking other BICs, not return False immediately.

- [ ] **Step 4: Run full test suite + regenerate web data**

- [ ] **Step 5: Commit**

```bash
git commit -m "refactor: unify scoring in generate_web_data, fix verdict loop"
```

---

### Task 12: Integration Testing + Rescan Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cd cve-analyzer && uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 2: Run rescan on full cache**

Run: `cd cve-analyzer && uv run cve-analyzer rescan-signals`
Expected: 0 `lost_ai`, integrity checker reports 0 violations

- [ ] **Step 3: Regenerate web data**

Run: `cd .. && python scripts/generate_web_data.py`
Expected: count >= 78, 0 "lost AI signal data"

- [ ] **Step 4: Spot-check 3 OpenClaw CVEs**

Re-analyze in single-CVE mode to verify smart decomposition triggers:
```bash
uv run cve-analyzer --no-cache analyze GHSA-2mc2-g238-722j GHSA-cfvj-7rx7-fc7c GHSA-96qw-h329-v5rg
```
Expected: signals correctly detected via atomic commit

- [ ] **Step 5: Commit web data if changed**

```bash
git add web/data/cves.json web/data/stats.json
git commit -m "data: regenerate after decompose-first refactor"
```
