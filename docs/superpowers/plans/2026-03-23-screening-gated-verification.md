# Screening-Gated Verification Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `touched_blamed_file` hard gate with per-CVE LLM screening that decides which CVEs are worth deep-verifying.

**Architecture:** Add `all_ai_signals()` to surface all AI signals in a PR regardless of file-touch. New `screen_cve()` does one cheap LLM call per CVE to triage. `_cve_needs_deep_verify()` replaces `_should_deep_verify()` as CVE-level gate. `FilteringLog` persists decisions for post-hoc analysis.

**Tech Stack:** Python 3.13, dataclasses, httpx (via llm_client), pytest

**Spec:** `docs/superpowers/specs/2026-03-23-screening-gated-verification-design.md`

---

### Task 1: Add `all_ai_signals()` to `BugIntroducingCommit`

**Files:**
- Modify: `cve-analyzer/src/cve_analyzer/models.py:300-325` (BugIntroducingCommit class)
- Test: `cve-analyzer/tests/test_effective_signals.py`

**Context:** `BugIntroducingCommit` already has `effective_signals()` which returns signals from the culprit sub-commit only (gated by `touched_blamed_file`). We need a broader method that returns ALL AI signals from ANY decomposed sub-commit, used for the screening gate. `effective_signals()` stays unchanged — it's used for confidence scoring.

- [ ] **Step 1: Write failing tests for `all_ai_signals()`**

Add to `cve-analyzer/tests/test_effective_signals.py`:

Use the existing helpers `_commit()`, `_sig()`, `_dc()` already in `test_effective_signals.py`:
- `_commit(sha, signals)` — creates `CommitInfo` with all required fields
- `_sig(tool, stype, origin)` — creates `AiSignal`, tool is `AiTool` enum (e.g. `AiTool.GITHUB_COPILOT`)
- `_dc(sha, signals, touched)` — creates `DecomposedCommit`

```python
# --- all_ai_signals() tests ---

def test_all_ai_signals_returns_non_touched_dc_signals():
    """all_ai_signals() includes signals from DCs that didn't touch blamed file."""
    ai_dc = _dc("ai_dc", signals=[_sig(AiTool.GITHUB_COPILOT)], touched=False)
    non_ai_dc = _dc("human_dc", signals=[], touched=True)
    bic = BugIntroducingCommit(
        commit=_commit("squash_sha"), fix_commit_sha="fix",
        blamed_file="vuln.py", blamed_lines=[10],
        decomposed_commits=[ai_dc, non_ai_dc], culprit_sha="human_dc",
    )
    signals = bic.all_ai_signals()
    assert len(signals) == 1
    assert signals[0].tool == AiTool.GITHUB_COPILOT


def test_all_ai_signals_includes_pr_signals():
    """all_ai_signals() includes PR body signals."""
    pr_sig = _sig(AiTool.GITHUB_COPILOT, stype="pr_body_keyword")
    bic = BugIntroducingCommit(
        commit=_commit("sha"), fix_commit_sha="fix",
        blamed_file="f.py", blamed_lines=[1],
        pr_signals=[pr_sig],
    )
    signals = bic.all_ai_signals()
    assert len(signals) == 1
    assert signals[0].signal_type == "pr_body_keyword"


def test_all_ai_signals_empty_when_no_ai():
    """all_ai_signals() returns empty for BIC with zero AI signals anywhere."""
    bic = BugIntroducingCommit(
        commit=_commit("sha"), fix_commit_sha="fix",
        blamed_file="f.py", blamed_lines=[1],
    )
    assert bic.all_ai_signals() == []


def test_all_ai_signals_falls_back_to_commit_signals():
    """Without decomposed commits, all_ai_signals() returns commit.ai_signals."""
    bic = BugIntroducingCommit(
        commit=_commit("sha", signals=[_sig()]), fix_commit_sha="fix",
        blamed_file="f.py", blamed_lines=[1],
    )
    signals = bic.all_ai_signals()
    assert len(signals) == 1
    assert signals[0].tool == AiTool.CLAUDE_CODE


def test_all_ai_signals_aggregates_multiple_dcs():
    """all_ai_signals() aggregates signals from all decomposed commits."""
    dc1 = _dc("dc1", signals=[_sig(AiTool.GITHUB_COPILOT)], touched=False)
    dc2 = _dc("dc2", signals=[_sig(AiTool.CLAUDE_CODE, stype="author_email")], touched=False)
    bic = BugIntroducingCommit(
        commit=_commit("squash"), fix_commit_sha="fix",
        blamed_file="f.py", blamed_lines=[1],
        decomposed_commits=[dc1, dc2], culprit_sha="other",
    )
    signals = bic.all_ai_signals()
    tools = {s.tool for s in signals}
    assert tools == {AiTool.GITHUB_COPILOT, AiTool.CLAUDE_CODE}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_effective_signals.py -k "all_ai_signals" -v`
Expected: FAIL — `AttributeError: 'BugIntroducingCommit' object has no attribute 'all_ai_signals'`

- [ ] **Step 3: Implement `all_ai_signals()`**

Add method to `BugIntroducingCommit` in `cve-analyzer/src/cve_analyzer/models.py`, right after `effective_signals()` (after line 325):

```python
def all_ai_signals(self) -> list[AiSignal]:
    """ALL AI signals from any decomposed sub-commit + PR signals.

    Broader than effective_signals() — includes signals from sub-commits
    that did NOT touch the blamed file. Used for the screening gate
    (any AI presence in the PR → worth screening), not for confidence
    scoring (which uses effective_signals() for culprit-focused signals).
    """
    signals: list[AiSignal] = []
    for dc in self.decomposed_commits:
        signals.extend(dc.ai_signals)
    signals.extend(self.pr_signals)
    if not self.decomposed_commits:
        signals.extend(self.commit.ai_signals)
    return signals
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_effective_signals.py -v`
Expected: ALL PASS (both old effective_signals tests and new all_ai_signals tests)

- [ ] **Step 5: Commit**

```bash
cd /home/hanqing/agents/ai-slop && git add cve-analyzer/src/cve_analyzer/models.py cve-analyzer/tests/test_effective_signals.py && git commit -m "feat: add all_ai_signals() for broad AI signal visibility"
```

---

### Task 2: Add `CveScreeningResult` and `FilteringLog` dataclasses

**Files:**
- Modify: `cve-analyzer/src/cve_analyzer/models.py:374-455` (CveAnalysisResult class)
- Test: `cve-analyzer/tests/test_models_result.py`

**Context:** Two new dataclasses needed: `CveScreeningResult` (per-CVE screening output) and `FilteringLog` (records all filtering decisions). Both go in `models.py` before `CveAnalysisResult`. Named `CveScreeningResult` to avoid collision with existing `verifier.models.ScreeningResult` (different purpose).

- [ ] **Step 1: Write failing tests for serialization roundtrip**

Add to `cve-analyzer/tests/test_models_result.py`:

```python
from cve_analyzer.models import CveScreeningResult, FilteringLog


def test_cve_screening_result_roundtrip():
    sr = CveScreeningResult(
        worth_investigating=True,
        reasoning="Copilot commit in same module",
        relevant_commits=["abc123", "def456"],
        model="gpt-4.1-mini",
    )
    d = sr.to_dict()
    assert d["worth_investigating"] is True
    assert d["relevant_commits"] == ["abc123", "def456"]
    restored = CveScreeningResult.from_dict(d)
    assert restored.worth_investigating is True
    assert restored.reasoning == "Copilot commit in same module"
    assert restored.model == "gpt-4.1-mini"


def test_cve_screening_result_not_worth():
    sr = CveScreeningResult(
        worth_investigating=False,
        reasoning="AI commits in unrelated UI module",
    )
    d = sr.to_dict()
    restored = CveScreeningResult.from_dict(d)
    assert restored.worth_investigating is False
    assert restored.relevant_commits == []


def test_filtering_log_roundtrip():
    fl = FilteringLog(
        ai_signal_bics=["sha1", "sha2"],
        ai_atomic_commits=[
            {"sha": "dc1", "tool": "copilot", "touched_blamed_file": False, "bic_sha": "sha1"},
        ],
        screening_result={"worth_investigating": True, "reasoning": "same module"},
        deep_verify_verdicts=[
            {"sha": "sha1", "verdict": "CONFIRMED", "reasoning": "wrote vuln code"},
        ],
        final_included=True,
        exclusion_reason="",
    )
    d = fl.to_dict()
    restored = FilteringLog.from_dict(d)
    assert restored.ai_signal_bics == ["sha1", "sha2"]
    assert len(restored.ai_atomic_commits) == 1
    assert restored.final_included is True


def test_filtering_log_empty_roundtrip():
    fl = FilteringLog()
    d = fl.to_dict()
    restored = FilteringLog.from_dict(d)
    assert restored.ai_signal_bics == []
    assert restored.screening_result is None
    assert restored.final_included is False


def test_cve_analysis_result_with_screening_roundtrip():
    """CveAnalysisResult serializes/deserializes screening and filtering_log."""
    from cve_analyzer.models import CveAnalysisResult
    result = CveAnalysisResult(cve_id="CVE-2025-99999")
    result.screening = CveScreeningResult(
        worth_investigating=True, reasoning="test", model="m",
    )
    result.filtering_log = FilteringLog(ai_signal_bics=["sha1"])
    d = result.to_dict()
    assert "screening" in d
    assert "filtering_log" in d
    restored = CveAnalysisResult.from_dict(d)
    assert restored.screening is not None
    assert restored.screening.worth_investigating is True
    assert restored.filtering_log is not None
    assert restored.filtering_log.ai_signal_bics == ["sha1"]


def test_cve_analysis_result_without_screening_roundtrip():
    """Old results without screening/filtering_log deserialize fine."""
    from cve_analyzer.models import CveAnalysisResult
    result = CveAnalysisResult(cve_id="CVE-2025-00001")
    d = result.to_dict()
    assert "screening" not in d
    assert "filtering_log" not in d
    restored = CveAnalysisResult.from_dict(d)
    assert restored.screening is None
    assert restored.filtering_log is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_models_result.py -k "screening_result or filtering_log" -v`
Expected: FAIL — `ImportError: cannot import name 'CveScreeningResult'`

- [ ] **Step 3: Implement `CveScreeningResult` and `FilteringLog`**

Add before `CveAnalysisResult` in `models.py` (around line 373):

```python
@dataclass
class CveScreeningResult:
    """Per-CVE screening: is this CVE worth deep-verifying?"""

    worth_investigating: bool
    reasoning: str
    relevant_commits: list[str] = field(default_factory=list)
    model: str = ""

    def to_dict(self) -> dict:
        return {
            "worth_investigating": self.worth_investigating,
            "reasoning": self.reasoning,
            "relevant_commits": self.relevant_commits,
            "model": self.model,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CveScreeningResult:
        return cls(
            worth_investigating=data["worth_investigating"],
            reasoning=data.get("reasoning", ""),
            relevant_commits=data.get("relevant_commits", []),
            model=data.get("model", ""),
        )


@dataclass
class FilteringLog:
    """Records filtering decisions at each pipeline layer for post-hoc analysis."""

    ai_signal_bics: list[str] = field(default_factory=list)
    ai_atomic_commits: list[dict] = field(default_factory=list)
    screening_result: dict | None = None
    deep_verify_verdicts: list[dict] = field(default_factory=list)
    final_included: bool = False
    exclusion_reason: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "ai_signal_bics": self.ai_signal_bics,
            "ai_atomic_commits": self.ai_atomic_commits,
            "deep_verify_verdicts": self.deep_verify_verdicts,
            "final_included": self.final_included,
        }
        if self.screening_result is not None:
            d["screening_result"] = self.screening_result
        if self.exclusion_reason:
            d["exclusion_reason"] = self.exclusion_reason
        return d

    @classmethod
    def from_dict(cls, data: dict) -> FilteringLog:
        return cls(
            ai_signal_bics=data.get("ai_signal_bics", []),
            ai_atomic_commits=data.get("ai_atomic_commits", []),
            screening_result=data.get("screening_result"),
            deep_verify_verdicts=data.get("deep_verify_verdicts", []),
            final_included=data.get("final_included", False),
            exclusion_reason=data.get("exclusion_reason", ""),
        )
```

Then add fields to `CveAnalysisResult` (after `ai_contribution`):

```python
screening: CveScreeningResult | None = None
filtering_log: FilteringLog | None = None
```

Update `CveAnalysisResult.to_dict()` — add after `ai_contribution` block:

```python
if self.screening is not None:
    d["screening"] = self.screening.to_dict()
if self.filtering_log is not None:
    d["filtering_log"] = self.filtering_log.to_dict()
```

Update `CveAnalysisResult.from_dict()` — add in the constructor:

```python
screening=CveScreeningResult.from_dict(data["screening"]) if data.get("screening") else None,
filtering_log=FilteringLog.from_dict(data["filtering_log"]) if data.get("filtering_log") else None,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_models_result.py -v`
Expected: ALL PASS

- [ ] **Step 5: Run full test suite to check no regressions**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest --tb=short -q`
Expected: All existing tests pass (no changes to existing behavior)

- [ ] **Step 6: Commit**

```bash
cd /home/hanqing/agents/ai-slop && git add cve-analyzer/src/cve_analyzer/models.py cve-analyzer/tests/test_models_result.py && git commit -m "feat: add CveScreeningResult and FilteringLog dataclasses"
```

---

### Task 3: Implement `screen_cve()` in `llm_verify.py`

**Files:**
- Modify: `cve-analyzer/src/cve_analyzer/llm_verify.py`
- Create: `cve-analyzer/tests/test_screen_cve.py`

**Context:** New per-CVE screening function. Takes a `CveAnalysisResult` and returns a `CveScreeningResult`. Uses one LLM call with a lenient prompt. Cached by CVE ID + BIC SHA hash. Returns `None` on failure (fail-open). The existing `verify_result()` and `verify_bic()` remain in the file for backward compat but won't be called on new analyses.

- [ ] **Step 1: Write failing tests for `screen_cve()`**

Create `cve-analyzer/tests/test_screen_cve.py`:

```python
"""Tests for per-CVE screening (screen_cve)."""
from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest

from cve_analyzer.models import (
    AiSignal, AiTool, BugIntroducingCommit, CommitInfo,
    CveAnalysisResult, CveScreeningResult, DecomposedCommit,
)


def _commit(sha="abc123", msg="commit msg", signals=None):
    return CommitInfo(sha=sha, author_name="A", author_email="a@x",
                      committer_name="A", committer_email="a@x",
                      message=msg, authored_date="2025-01-01",
                      ai_signals=signals or [])


def _sig(tool=AiTool.GITHUB_COPILOT, stype="co_author_trailer", confidence=0.7):
    return AiSignal(tool=tool, signal_type=stype, matched_text="text", confidence=confidence)


def _make_result_with_ai_dc(touched=False):
    """Helper: result with one BIC containing one AI decomposed commit."""
    ai_dc = DecomposedCommit(
        sha="ai_dc_sha", author_name="bot", author_email="bot@x",
        message="Add feature", ai_signals=[_sig()],
        touched_blamed_file=touched, committer_name="bot", committer_email="bot@x",
    )
    bic = BugIntroducingCommit(
        commit=_commit("squash_sha"), fix_commit_sha="fix_sha",
        blamed_file="src/vuln.py", blamed_lines=[10],
        decomposed_commits=[ai_dc], culprit_sha="ai_dc_sha" if touched else "other_sha",
    )
    result = CveAnalysisResult(
        cve_id="CVE-2025-99999",
        description="Test vulnerability in module X",
        cwes=["CWE-79"],
    )
    result.bug_introducing_commits = [bic]
    return result


@patch("cve_analyzer.llm_verify.call_llm")
def test_screen_cve_worth_investigating(mock_call):
    from cve_analyzer.llm_verify import screen_cve
    mock_call.return_value = (
        {"worth_investigating": True, "reasoning": "same module", "relevant_commits": ["ai_dc_sha"]},
        "gpt-4.1-mini",
    )
    result = _make_result_with_ai_dc(touched=False)
    screening = screen_cve(result, "/fake/repo")
    assert screening is not None
    assert screening.worth_investigating is True
    assert "ai_dc_sha" in screening.relevant_commits


@patch("cve_analyzer.llm_verify.call_llm")
def test_screen_cve_not_worth(mock_call):
    from cve_analyzer.llm_verify import screen_cve
    mock_call.return_value = (
        {"worth_investigating": False, "reasoning": "different subsystem", "relevant_commits": []},
        "gpt-4.1-mini",
    )
    result = _make_result_with_ai_dc(touched=False)
    screening = screen_cve(result, "/fake/repo")
    assert screening is not None
    assert screening.worth_investigating is False


@patch("cve_analyzer.llm_verify.call_llm")
def test_screen_cve_returns_none_on_llm_failure(mock_call):
    from cve_analyzer.llm_verify import screen_cve
    mock_call.return_value = None
    result = _make_result_with_ai_dc()
    screening = screen_cve(result, "/fake/repo")
    assert screening is None


@patch("cve_analyzer.llm_verify.call_llm")
def test_screen_cve_returns_none_on_invalid_response(mock_call):
    from cve_analyzer.llm_verify import screen_cve
    mock_call.return_value = ({"invalid": "response"}, "model")
    result = _make_result_with_ai_dc()
    screening = screen_cve(result, "/fake/repo")
    assert screening is None


def test_screen_cve_skips_when_no_ai_signals():
    """screen_cve returns None for results with no AI signals at all."""
    from cve_analyzer.llm_verify import screen_cve
    result = CveAnalysisResult(cve_id="CVE-2025-00001")
    result.bug_introducing_commits = [
        BugIntroducingCommit(
            commit=_commit(), fix_commit_sha="fix",
            blamed_file="f.py", blamed_lines=[1],
        )
    ]
    screening = screen_cve(result, "/fake/repo")
    assert screening is None


@patch("cve_analyzer.llm_verify.call_llm")
def test_screen_cve_uses_cache(mock_call):
    """Second call with same BICs returns cached result without LLM call."""
    from cve_analyzer.llm_verify import screen_cve
    mock_call.return_value = (
        {"worth_investigating": True, "reasoning": "test", "relevant_commits": []},
        "model",
    )
    result = _make_result_with_ai_dc()
    # Patch cache to simulate hit
    with patch("cve_analyzer.llm_verify.api_cache.get_cached_response") as mock_cache:
        mock_cache.return_value = {
            "worth_investigating": True, "reasoning": "cached", "relevant_commits": ["x"],
            "model": "cached_model",
        }
        screening = screen_cve(result, "/fake/repo")
        assert screening is not None
        assert screening.reasoning == "cached"
        mock_call.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_screen_cve.py -v`
Expected: FAIL — `ImportError: cannot import name 'screen_cve' from 'cve_analyzer.llm_verify'`

- [ ] **Step 3: Implement `screen_cve()`**

Add to `cve-analyzer/src/cve_analyzer/llm_verify.py` (after the existing `verify_result()` function, around line 551):

```python
# ---------------------------------------------------------------------------
# Per-CVE screening (replaces per-BIC verify_result for new analyses)
# ---------------------------------------------------------------------------

_CVE_SCREENING_PROMPT = """\
You are a security researcher performing quick triage on AI involvement in a vulnerability.

Given a CVE description and a list of AI-authored commits from the blamed PR(s), determine if any AI commit could have contributed to introducing the vulnerability.

Respond with ONLY a JSON object (no markdown fences):
{
  "worth_investigating": true/false,
  "reasoning": "1-2 sentence explanation",
  "relevant_commits": ["sha1", "sha2"]
}

Guidelines (be LENIENT — err on the side of true):
- worth_investigating: false ONLY when AI commits are clearly in a DIFFERENT feature, module, or subsystem from the vulnerability
- worth_investigating: true when AI commits:
  - Touched the blamed file (strongest signal)
  - Are in the same module/package as the vulnerability
  - Could have changed calling context, API contracts, or configuration
  - Are ambiguous or you're not sure
- When in doubt, say true
- relevant_commits: list the SHAs of AI commits that could be relevant (empty list if none)
"""


def _screening_cache_key(cve_id: str, bic_shas: list[str], model: str) -> str:
    """Deterministic cache key for per-CVE screening."""
    raw = f"{cve_id}:{':'.join(sorted(bic_shas))}:{model}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _build_screening_prompt(
    result: CveAnalysisResult,
    vuln_analysis: dict | None = None,
) -> str | None:
    """Build the per-CVE screening prompt with all AI atomic commits."""
    ai_commit_sections = []

    for bic in result.bug_introducing_commits:
        ai_dcs = [dc for dc in bic.decomposed_commits if dc.ai_signals]
        ai_on_commit = bic.commit.ai_signals if not bic.decomposed_commits else []

        if not ai_dcs and not ai_on_commit and not bic.pr_signals:
            continue

        bic_section = f"### BIC: {bic.commit.sha[:12]} — blamed file: {bic.blamed_file}\n"

        if bic.culprit_sha:
            culprit = next((dc for dc in bic.decomposed_commits if dc.sha == bic.culprit_sha), None)
            if culprit:
                touched = "YES" if culprit.touched_blamed_file else "NO"
                has_ai = "YES (AI)" if culprit.ai_signals else "NO"
                bic_section += f"Culprit sub-commit: {culprit.sha[:12]} (touched blamed file: {touched}, AI: {has_ai})\n"

        for dc in ai_dcs:
            touched = "YES" if dc.touched_blamed_file else "NO" if dc.touched_blamed_file is False else "UNKNOWN"
            tools = ", ".join(s.tool.value for s in dc.ai_signals)
            bic_section += f"- AI commit {dc.sha[:12]}: \"{dc.message[:100]}\" (tools: {tools}, touched blamed file: {touched})\n"

        for sig in ai_on_commit:
            bic_section += f"- Direct signal on BIC: {sig.tool.value}/{sig.signal_type}\n"

        for sig in bic.pr_signals:
            bic_section += f"- PR body signal: {sig.tool.value}/{sig.signal_type}\n"

        ai_commit_sections.append(bic_section)

    if not ai_commit_sections:
        return None

    vuln_section = ""
    if vuln_analysis:
        vuln_section = (
            f"## Vulnerability Analysis\n"
            f"- Type: {vuln_analysis.get('vuln_type', 'unknown')}\n"
            f"- Root Cause: {vuln_analysis.get('vuln_description', 'unknown')}\n"
            f"- Vulnerable Pattern: {vuln_analysis.get('vulnerable_pattern', 'unknown')}\n\n"
        )

    return (
        f"## CVE: {result.cve_id}\n"
        f"## Description\n{result.description[:500]}\n\n"
        f"{vuln_section}"
        f"## AI-authored commits in blamed PRs\n\n"
        + "\n".join(ai_commit_sections)
    )


def screen_cve(
    result: CveAnalysisResult,
    repo_path: str,
    *,
    model: str = DEFAULT_MODEL,
    vuln_analysis: dict | None = None,
) -> CveScreeningResult | None:
    """Per-CVE screening: is this vulnerability worth deep-verifying for AI involvement?

    Returns CveScreeningResult or None on failure/skip (fail-open → pipeline
    proceeds to deep verify).
    """
    from cve_analyzer.models import CveScreeningResult

    # Quick check: any AI signals at all?
    has_any_ai = any(bic.all_ai_signals() for bic in result.bug_introducing_commits)
    if not has_any_ai:
        return None

    # Cache check
    bic_shas = [bic.commit.sha for bic in result.bug_introducing_commits]
    cache_key = _screening_cache_key(result.cve_id, bic_shas, model)
    cached = api_cache.get_cached_response("cve_screening", cache_key)
    if cached is not None:
        try:
            get_usage_stats().record_cache_hit()
            return CveScreeningResult.from_dict(cached)
        except (KeyError, ValueError):
            pass

    # Build prompt
    prompt = _build_screening_prompt(result, vuln_analysis=vuln_analysis)
    if prompt is None:
        return None

    call_result = call_llm(prompt, model, system_prompt=_CVE_SCREENING_PROMPT)
    if call_result is None:
        return None
    llm_result, used_model = call_result

    # Parse response
    if "worth_investigating" not in llm_result:
        logger.warning("CVE screening missing worth_investigating: %s", llm_result)
        return None

    screening = CveScreeningResult(
        worth_investigating=bool(llm_result["worth_investigating"]),
        reasoning=llm_result.get("reasoning", ""),
        relevant_commits=llm_result.get("relevant_commits", []),
        model=used_model,
    )

    api_cache.save_cached_response("cve_screening", cache_key, screening.to_dict())
    logger.info(
        "CVE screening for %s: %s — %s",
        result.cve_id,
        "INVESTIGATE" if screening.worth_investigating else "SKIP",
        screening.reasoning,
    )
    return screening
```

Also add the import at the top of `llm_verify.py`:

```python
from cve_analyzer.models import BlameVerdict, BugIntroducingCommit, CveAnalysisResult, CveScreeningResult, LlmVerdict
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_screen_cve.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
cd /home/hanqing/agents/ai-slop && git add cve-analyzer/src/cve_analyzer/llm_verify.py cve-analyzer/tests/test_screen_cve.py && git commit -m "feat: add screen_cve() for per-CVE screening"
```

---

### Task 4: Replace `_should_deep_verify` with `_cve_needs_deep_verify` in pipeline

**Files:**
- Modify: `cve-analyzer/src/cve_analyzer/pipeline.py:409-418` (delete `_should_deep_verify`), `847-852` (`_result_has_ai_involvement`), `898-903` (`_run_deep_verify` BIC filter)
- Test: `cve-analyzer/tests/test_pipeline_screening.py`

**Context:** The BIC-level `_should_deep_verify(bic)` is replaced by CVE-level `_cve_needs_deep_verify(result)`. This checks `result.screening` first, falls back to per-BIC screening compat, then to `all_ai_signals()`. The `_run_deep_verify()` function stops calling the old per-BIC `_should_deep_verify()` and instead uses the CVE-level gate + optional `relevant_commits` filter.

- [ ] **Step 1: Write failing tests**

Add to `cve-analyzer/tests/test_pipeline_screening.py` (or create if it only has per-BIC tests):

```python
"""Tests for CVE-level screening gate."""
from cve_analyzer.models import (
    AiSignal, AiTool, BlameVerdict, BugIntroducingCommit, CommitInfo,
    CveAnalysisResult, CveScreeningResult, DecomposedCommit, LlmVerdict,
)


def _commit(sha="abc", signals=None):
    return CommitInfo(sha=sha, author_name="A", author_email="a@x",
                      committer_name="A", committer_email="a@x",
                      message="m", authored_date="2025-01-01",
                      ai_signals=signals or [])


def _sig(tool=AiTool.GITHUB_COPILOT, stype="co_author_trailer"):
    return AiSignal(tool=tool, signal_type=stype, matched_text="t", confidence=0.7)


def test_cve_needs_deep_verify_with_screening_true():
    from cve_analyzer.pipeline import _cve_needs_deep_verify
    result = CveAnalysisResult(cve_id="CVE-TEST")
    result.screening = CveScreeningResult(worth_investigating=True, reasoning="yes")
    assert _cve_needs_deep_verify(result) is True


def test_cve_needs_deep_verify_with_screening_false():
    from cve_analyzer.pipeline import _cve_needs_deep_verify
    result = CveAnalysisResult(cve_id="CVE-TEST")
    result.screening = CveScreeningResult(worth_investigating=False, reasoning="no")
    assert _cve_needs_deep_verify(result) is False


def test_cve_needs_deep_verify_fallback_per_bic_confirmed():
    """Old per-BIC CONFIRMED screening → worth investigating."""
    from cve_analyzer.pipeline import _cve_needs_deep_verify
    bic = BugIntroducingCommit(
        commit=_commit(), fix_commit_sha="fix", blamed_file="f.py", blamed_lines=[1],
    )
    bic.screening_verification = LlmVerdict(
        verdict=BlameVerdict.CONFIRMED, reasoning="yes", model="m",
    )
    result = CveAnalysisResult(cve_id="CVE-TEST")
    result.bug_introducing_commits = [bic]
    assert _cve_needs_deep_verify(result) is True


def test_cve_needs_deep_verify_fallback_per_bic_unrelated():
    """Old per-BIC all UNRELATED screening → not worth investigating."""
    from cve_analyzer.pipeline import _cve_needs_deep_verify
    bic = BugIntroducingCommit(
        commit=_commit(), fix_commit_sha="fix", blamed_file="f.py", blamed_lines=[1],
    )
    bic.screening_verification = LlmVerdict(
        verdict=BlameVerdict.UNRELATED, reasoning="no", model="m",
    )
    result = CveAnalysisResult(cve_id="CVE-TEST")
    result.bug_introducing_commits = [bic]
    assert _cve_needs_deep_verify(result) is False


def test_cve_needs_deep_verify_fallback_all_ai_signals():
    """No screening at all → fall back to all_ai_signals()."""
    from cve_analyzer.pipeline import _cve_needs_deep_verify
    ai_dc = DecomposedCommit(
        sha="dc", author_name="b", author_email="b@x",
        message="m", ai_signals=[_sig()], touched_blamed_file=False,
    )
    bic = BugIntroducingCommit(
        commit=_commit(), fix_commit_sha="fix", blamed_file="f.py", blamed_lines=[1],
        decomposed_commits=[ai_dc], culprit_sha="other",
    )
    result = CveAnalysisResult(cve_id="CVE-TEST")
    result.bug_introducing_commits = [bic]
    assert _cve_needs_deep_verify(result) is True


def test_cve_needs_deep_verify_fallback_no_ai():
    """No screening, no AI signals → not worth investigating."""
    from cve_analyzer.pipeline import _cve_needs_deep_verify
    bic = BugIntroducingCommit(
        commit=_commit(), fix_commit_sha="fix", blamed_file="f.py", blamed_lines=[1],
    )
    result = CveAnalysisResult(cve_id="CVE-TEST")
    result.bug_introducing_commits = [bic]
    assert _cve_needs_deep_verify(result) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_pipeline_screening.py -k "cve_needs" -v`
Expected: FAIL — `ImportError: cannot import name '_cve_needs_deep_verify'`

- [ ] **Step 3: Implement `_cve_needs_deep_verify` and update pipeline**

In `cve-analyzer/src/cve_analyzer/pipeline.py`:

**a)** Replace `_should_deep_verify` (lines 409-418) with:

```python
def _cve_needs_deep_verify(result: CveAnalysisResult) -> bool:
    """CVE-level gate: did screening say worth investigating?

    Checks in order:
    1. Per-CVE screening result (new format)
    2. Per-BIC screening_verification (old format backward compat)
    3. Fall back to all_ai_signals() (no screening ran)
    """
    # New per-CVE screening is authoritative
    if result.screening is not None:
        return result.screening.worth_investigating

    # Backward compat: old per-BIC screening
    has_per_bic_screening = any(
        bic.screening_verification is not None
        for bic in result.bug_introducing_commits
    )
    if has_per_bic_screening:
        return any(
            bic.screening_verification is not None
            and bic.screening_verification.verdict != BlameVerdict.UNRELATED
            for bic in result.bug_introducing_commits
        )

    # No screening at all — fall back to any AI signals
    return any(bic.all_ai_signals() for bic in result.bug_introducing_commits)
```

Keep `_should_deep_verify` as a deprecated alias for backward compat (some test imports might reference it):

```python
# Deprecated — use _cve_needs_deep_verify instead
_should_deep_verify = lambda bic: bool(bic.effective_signals())
```

**b)** Update `_result_has_ai_involvement` (line 847-852):

```python
def _result_has_ai_involvement(result: CveAnalysisResult) -> bool:
    """Return True if the result has any AI involvement worth verifying."""
    return bool(result.ai_signals) or any(
        bic.all_ai_signals() or bic.screening_verification is not None
        for bic in result.bug_introducing_commits
    )
```

**c)** Update `_run_deep_verify` signature to accept `relevant_commits` and use it for BIC filtering:

Add `relevant_commits: list[str] | None = None` parameter. Change the BIC filter:

```python
def _run_deep_verify(
    result: CveAnalysisResult,
    cve_id: str,
    *,
    relevant_commits: list[str] | None = None,  # NEW: from screening
    force_verify: bool = False,
    ...
) -> None:
    ...
    bics_to_verify = [
        bic for bic in result.bug_introducing_commits
        if _bic_worth_verifying(bic, relevant_commits)
        and (force_verify or bic.deep_verification is None)
    ]
```

New helper:

```python
def _bic_worth_verifying(bic: BugIntroducingCommit, relevant_commits: list[str] | None) -> bool:
    """BIC is worth deep-verifying if it has effective signals OR screening flagged it."""
    if bic.effective_signals():
        return True
    if relevant_commits:
        # Screening flagged specific atomic commits — check if any are in this BIC
        for dc in bic.decomposed_commits:
            if any(dc.sha.startswith(rc) for rc in relevant_commits):
                return True
        if any(bic.commit.sha.startswith(rc) for rc in relevant_commits):
            return True
    return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/test_pipeline_screening.py -v`
Expected: ALL PASS

- [ ] **Step 5: Run full test suite**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest --tb=short -q`
Expected: All pass. If old tests reference `_should_deep_verify`, the deprecated alias handles it.

- [ ] **Step 6: Commit**

```bash
cd /home/hanqing/agents/ai-slop && git add cve-analyzer/src/cve_analyzer/pipeline.py cve-analyzer/tests/test_pipeline_screening.py && git commit -m "feat: replace _should_deep_verify with CVE-level _cve_needs_deep_verify"
```

---

### Task 5: Wire `screen_cve()` into pipeline flow and populate `FilteringLog`

**Files:**
- Modify: `cve-analyzer/src/cve_analyzer/pipeline.py` — Phase C.5 sections (two places: fresh-analysis path ~line 3383, cached-result path ~line 3175)

**Context:** The pipeline has TWO code paths that run screening+deep verify: (1) the fresh-analysis path in `_enrich_single()` around line 3383, and (2) the cached-result fast path around line 3175. Both currently call `verify_result()` (per-BIC). Replace both with `screen_cve()` (per-CVE) and add `FilteringLog` population.

- [ ] **Step 1: Read both pipeline paths to identify exact edit locations**

Read `pipeline.py` lines 3160-3220 (cached path) and 3370-3430 (fresh path). Identify where `verify_result()` is called and where Phase D is triggered.

- [ ] **Step 2: Build `_build_filtering_log` helper**

Add to `pipeline.py`:

```python
def _build_filtering_log(result: CveAnalysisResult) -> FilteringLog:
    """Populate initial filtering log with AI signal inventory."""
    from cve_analyzer.models import FilteringLog

    log = FilteringLog()
    for bic in result.bug_introducing_commits:
        all_sigs = bic.all_ai_signals()
        if all_sigs:
            log.ai_signal_bics.append(bic.commit.sha)
            for dc in bic.decomposed_commits:
                if dc.ai_signals:
                    for sig in dc.ai_signals:
                        log.ai_atomic_commits.append({
                            "sha": dc.sha,
                            "tool": sig.tool.value,
                            "touched_blamed_file": dc.touched_blamed_file,
                            "bic_sha": bic.commit.sha,
                        })
            if not bic.decomposed_commits:
                for sig in bic.commit.ai_signals:
                    log.ai_atomic_commits.append({
                        "sha": bic.commit.sha,
                        "tool": sig.tool.value,
                        "touched_blamed_file": None,
                        "bic_sha": bic.commit.sha,
                    })
    return log
```

- [ ] **Step 3: Replace per-BIC screening with per-CVE in fresh-analysis path**

In the fresh-analysis path (around line 3383), replace:

```python
# OLD: Phase C.5: LLM causality verification
if llm_verify and result.ai_signals:
    ...
    llm_mod.verify_result(result, ...)
```

With:

```python
# Phase C: Per-CVE screening
has_ai_bics = any(bic.all_ai_signals() for bic in result.bug_introducing_commits)
if llm_verify and has_ai_bics:
    _t0 = time.monotonic()
    from cve_analyzer import llm_verify as llm_mod

    if not verify_repo_path:
        for fc in result.fix_commits:
            local_path = git_ops.clone_repo(fc.repo_url, shallow_since=shallow_since)
            if local_path:
                verify_repo_path = str(local_path)
                break

    # Build filtering log
    result.filtering_log = _build_filtering_log(result)

    # Phase 1: Vulnerability analysis (unchanged, reused)
    if not vuln_analysis and verify_repo_path:
        vuln_analysis = llm_mod.analyze_vulnerability(
            result, verify_repo_path,
            model=llm_model or llm_mod.DEFAULT_MODEL,
        )

    # Phase C: Per-CVE screening
    if verify_repo_path:
        result.screening = llm_mod.screen_cve(
            result, verify_repo_path,
            model=llm_model or llm_mod.DEFAULT_MODEL,
            vuln_analysis=vuln_analysis,
        )
        if result.screening and result.filtering_log:
            result.filtering_log.screening_result = result.screening.to_dict()

    _phase_times["Phase C (screening)"] = time.monotonic() - _t0
```

- [ ] **Step 4: Replace per-BIC screening with per-CVE in cached-result path**

Similar change in the cached-result path (around line 3175). Replace the `_needs_llm` check and `verify_result()` call with `screen_cve()`.

- [ ] **Step 5: Update Phase D to use `_cve_needs_deep_verify`**

Replace both Phase D sections (fresh and cached paths):

```python
# Phase D: Deep verification (only if screening passed or was inconclusive)
if llm_verify and _cve_needs_deep_verify(result):
    _t0 = time.monotonic()
    _run_deep_verify(
        result, cve_id,
        force_verify=force_verify,
        verbose=verbose,
        shallow_since=shallow_since,
        verify_repo_path=verify_repo_path,
        verify_model=verify_model,
        verify_models=verify_models,
    )
    # Record deep verify outcomes in filtering log
    if result.filtering_log:
        result.filtering_log.deep_verify_verdicts = [
            {
                "sha": bic.commit.sha,
                "verdict": (bic.deep_verification.get("verdict", "") if bic.deep_verification else ""),
                "reasoning": (bic.deep_verification.get("reasoning", "")[:200] if bic.deep_verification else ""),
            }
            for bic in result.bug_introducing_commits
            if bic.deep_verification
        ]
    _phase_times["Phase D (deep verify)"] = time.monotonic() - _t0
```

- [ ] **Step 6: Add required imports to pipeline.py**

At the top of `pipeline.py`, add to the models import:

```python
from cve_analyzer.models import (
    ...
    CveScreeningResult,
    FilteringLog,
)
```

- [ ] **Step 7: Run full test suite**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest --tb=short -q`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
cd /home/hanqing/agents/ai-slop && git add cve-analyzer/src/cve_analyzer/pipeline.py && git commit -m "feat: wire screen_cve() into pipeline, populate FilteringLog"
```

---

### Task 6: Pass screening hints to deep verifier

**Files:**
- Modify: `cve-analyzer/src/cve_analyzer/pipeline.py:421-440` (`_build_bic_candidates`)
- Modify: `cve-analyzer/src/cve_analyzer/verifier/agent_loop.py:381-391` (investigation prompt)

**Context:** `_build_bic_candidates()` currently reads per-BIC `screening_verification` to pass hints to the investigator. Update it to also pass per-CVE screening `relevant_commits`. The investigation prompt should mention which atomic commits were flagged by screening.

- [ ] **Step 1: Update `_build_bic_candidates()` to accept screening param**

```python
def _build_bic_candidates(
    bics: list[BugIntroducingCommit],
    screening: CveScreeningResult | None = None,
) -> list[dict]:
```

After existing candidate dict construction, add:

```python
# Per-CVE screening hints (new)
if screening and screening.relevant_commits:
    relevant_in_bic = [
        sha for sha in screening.relevant_commits
        if any(dc.sha.startswith(sha) for dc in bic.decomposed_commits)
        or bic.commit.sha.startswith(sha)
    ]
    if relevant_in_bic:
        candidate["screening_flagged_commits"] = relevant_in_bic
    if not candidate.get("screening_reasoning"):
        candidate["screening_reasoning"] = screening.reasoning
```

- [ ] **Step 2: Update caller at pipeline.py:947**

Change:
```python
bic_candidates=_build_bic_candidates(bics_to_verify),
```
To:
```python
bic_candidates=_build_bic_candidates(bics_to_verify, screening=result.screening),
```

This works because `_run_deep_verify` already has access to `result` (it reads `result.bug_introducing_commits`, `result.fix_commits`, etc.).

- [ ] **Step 3: Update investigation prompt to show screening-flagged commits**

In `verifier/agent_loop.py:_build_investigation_prompt()`, where it builds candidate lines (line 382-390), add handling for `screening_flagged_commits`:

```python
if c.get("screening_flagged_commits"):
    flagged = ", ".join(c["screening_flagged_commits"])
    line += f"\n  **Screening flagged atomic commits**: {flagged}"
if c.get("screening_reasoning") and not c.get("screening_verdict"):
    line += f"\n  **Screening note**: {c['screening_reasoning'][:300]}"
```

- [ ] **Step 4: Run full test suite**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest --tb=short -q`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
cd /home/hanqing/agents/ai-slop && git add cve-analyzer/src/cve_analyzer/pipeline.py cve-analyzer/src/cve_analyzer/verifier/agent_loop.py && git commit -m "feat: pass screening hints to deep verifier"
```

---

### Task 7: Update `web_data/filters.py` to populate FilteringLog final fields

**Files:**
- Modify: `scripts/web_data/filters.py`
- Modify: `scripts/web_data/entry_builder.py` (pass filtering_log through)
- Test: `scripts/tests/test_web_data_filters.py`

**Context:** `should_include()` decides website inclusion but doesn't record WHY. Add `exclusion_reason` and `final_included` to the `FilteringLog` on the result object.

- [ ] **Step 1: Update `should_include()` to populate `filtering_log`**

Modify `should_include()` in `scripts/web_data/filters.py` to set `result.filtering_log.final_included` and `result.filtering_log.exclusion_reason` before returning. The function already takes the result object — just mutate its filtering_log.

```python
def should_include(
    result: CveAnalysisResult,
    audit_overrides: set[str] | None = None,
) -> bool:
    included, reason = _should_include_with_reason(result, audit_overrides)
    if result.filtering_log:
        result.filtering_log.final_included = included
        result.filtering_log.exclusion_reason = reason
    return included
```

Extract existing logic into `_should_include_with_reason()` that returns `(bool, str)`.

- [ ] **Step 2: Write tests for exclusion reasons**

```python
def test_should_include_records_exclusion_reason():
    result = CveAnalysisResult(cve_id="CVE-TEST", error="broken")
    result.filtering_log = FilteringLog()
    assert should_include(result) is False
    assert result.filtering_log.exclusion_reason == "error"
    assert result.filtering_log.final_included is False
```

- [ ] **Step 3: Run tests**

Run: `cd /home/hanqing/agents/ai-slop && uv run pytest scripts/tests/test_web_data_filters.py -v`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
cd /home/hanqing/agents/ai-slop && git add scripts/web_data/filters.py scripts/tests/test_web_data_filters.py && git commit -m "feat: populate FilteringLog final_included and exclusion_reason"
```

---

### Task 8: Full regression test and cleanup

**Files:**
- All modified files

- [ ] **Step 1: Run full cve-analyzer test suite**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest --tb=short -q`
Expected: All pass

- [ ] **Step 2: Run scripts test suite**

Run: `cd /home/hanqing/agents/ai-slop && uv run pytest scripts/tests/ --tb=short -q`
Expected: All pass

- [ ] **Step 3: Run ruff lint**

Run: `cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run ruff check src/ tests/`
Expected: No errors

- [ ] **Step 4: Regenerate web data and verify no TP regression**

Run: `cd /home/hanqing/agents/ai-slop && python scripts/generate_web_data.py`
Check: `python -c "import json; d=json.load(open('web/data/cves.json')); print(d['total'])"`
Expected: 79 or more (no TP regression)

- [ ] **Step 5: Integration test — verify screening on known CVEs**

Run a few known CVEs through the pipeline to validate the new screening behavior:

```bash
cd /home/hanqing/agents/ai-slop/cve-analyzer
# NOT_VERIFIED case: AI signals on non-touched-file commits — expect screening to run
uv run cve-analyzer --no-cache analyze CVE-2025-12875 2>&1 | grep -i "screening"
# Should see "CVE screening for CVE-2025-12875: SKIP" (AI in unrelated files)

# Potential TP: Copilot added wildcard CORS — expect screening INVESTIGATE
uv run cve-analyzer --no-cache analyze CVE-2025-59163 2>&1 | grep -i "screening"
# Should see "CVE screening for CVE-2025-59163: INVESTIGATE"
```

Verify idempotency: run CVE-2025-12875 a second time — should use cached screening, no new LLM call.

- [ ] **Step 6: Spot-check FilteringLog on a few results**

```bash
cd /home/hanqing/agents/ai-slop
python -c "
import json, glob
for f in sorted(glob.glob('~/.cache/cve-analyzer/results/CVE-2025-12875.json'))[:1]:
    d = json.load(open(f))
    fl = d.get('filtering_log')
    print(f'{d[\"cve_id\"]}: filtering_log={fl is not None}')
    if fl:
        print(f'  ai_signal_bics: {fl.get(\"ai_signal_bics\", [])}')
        print(f'  screening: {fl.get(\"screening_result\")}')
"
```

- [ ] **Step 6: Commit final state**

```bash
cd /home/hanqing/agents/ai-slop && git add -A && git commit -m "chore: full regression test pass for screening-gated verification"
```

---

## Dependency Graph

```
Task 1 (all_ai_signals)
    ↓
Task 2 (CveScreeningResult + FilteringLog)
    ↓
Task 3 (screen_cve) ← depends on Task 1 + 2
    ↓
Task 4 (_cve_needs_deep_verify) ← depends on Task 1 + 2
    ↓
Task 5 (wire into pipeline) ← depends on Task 3 + 4
    ↓
Task 6 (screening hints to verifier) ← depends on Task 5
    ↓
Task 7 (web_data filters) ← depends on Task 2
    ↓
Task 8 (regression test) ← depends on all
```

Tasks 1-2 are independent of each other and can run in parallel.
Tasks 3-4 depend on 1+2 but are independent of each other.
Task 7 only depends on Task 2 and can run in parallel with Tasks 3-6.
