# Rewrite generate_web_data.py Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 1823-line patched `scripts/generate_web_data.py` with a clean rewrite that uses `CveAnalysisResult` model objects instead of raw dicts, eliminating duplicated logic and accumulated tech debt.

**Architecture:** Load cached JSON files as `CveAnalysisResult` objects via `from_dict()`, use model methods (`effective_signals()`, `rebuild_signals()`) directly for all signal/verdict logic. Split the monolith into focused modules: severity parsing, entry building, data loading, and stats. Keep the script as a thin CLI orchestrator.

**Tech Stack:** Python 3.13, stdlib + cve_analyzer models/scoring, no new dependencies.

---

## Why Rewrite

The current script has 42 functions across 1823 lines with 18 debt markers. Core problems:

1. **Duplicated model logic** — `_get_effective_signals_dict()`, `_effective_verdict()`, `_has_no_confirmed_verdict()` are dict-level re-implementations of `BugIntroducingCommit.effective_signals()` and related model methods. Every model change requires syncing two places.
2. **Signal filtering scattered** — At least 4 separate locations filter by verdict, origin, workflow type. The `ai_tools` list is built in `build_cve_entry`, then patched in `main()` (audit overrides), then patched again (`ai_involved` fallback), then filtered (no-tools exclusion).
3. **Backward-compat layers** — `_get_screening_verdict()` checks `llm_verdict` fallback, `_get_deep_verdict()` checks `verification_verdict` and `tribunal_verdict` fallbacks. These are already handled by `BugIntroducingCommit.from_dict()`.
4. **Just-fixed bugs** — `ai_involved` not passed to entry dict, `_should_deep_verify` missing `effective_signals`, misleading "lost AI signal data" message — all symptoms of the dict-level approach.

## File Structure

```
scripts/
  generate_web_data.py          # Rewrite — thin CLI orchestrator (~200 lines)
  conftest.py                   # sys.path setup for scripts/ and cve-analyzer/src/
  web_data/                     # New package for web data generation
    __init__.py
    loader.py                   # Load cached results, reviews, NVD/GHSA dates, aliases (~200 lines)
    severity.py                 # CVSS parsing, severity label resolution + metric maps (~200 lines)
    languages.py                # File extension → language, template inference, git diff-tree (~130 lines)
    entry_builder.py            # CveAnalysisResult → web entry dict (~350 lines)
    stats.py                    # Aggregate statistics builder (~80 lines)
    filters.py                  # Inclusion/exclusion logic (~70 lines)
    constants.py                # Shared constants (extension map, template exts, defaults) (~50 lines)
  tests/
    test_web_data_entry.py      # Tests for entry_builder
    test_web_data_severity.py   # Tests for severity parsing
    test_web_data_filters.py    # Tests for filters
```

**Key design rule:** `entry_builder.py` receives `CveAnalysisResult` objects, not dicts. All verdict/signal logic uses model methods. No `result.get("bug_introducing_commits")` anywhere in the new code.

## Verification Strategy

After the rewrite, run the new script and compare output with a baseline snapshot field-by-field. Differences must be explainable (bugs fixed = better output). The baseline snapshot is a one-time migration artifact deleted after verification.

---

### Task 1: Snapshot old output for regression baseline

**Files:**
- Read: `scripts/generate_web_data.py`
- Create: `web/data/cves_baseline.json`

- [ ] **Step 1: Generate baseline with current script**

```bash
cd /home/hanqing/agents/ai-slop
cp web/data/cves.json web/data/cves_baseline.json
```

This captures the current 58-CVE output as ground truth.

- [ ] **Step 2: Commit baseline**

```bash
git add web/data/cves_baseline.json
git commit -m "test: snapshot web data baseline for rewrite regression test"
```

---

### Task 2: Create package, conftest, and constants module

**Files:**
- Create: `scripts/web_data/__init__.py`
- Create: `scripts/web_data/constants.py`
- Create: `scripts/conftest.py`

- [ ] **Step 1: Create conftest for import paths**

`scripts/conftest.py` adds both `scripts/` and `cve-analyzer/src/` to `sys.path` so tests can import `web_data.*` and `cve_analyzer.*`:

```python
# scripts/conftest.py
import sys
from pathlib import Path

_scripts = str(Path(__file__).resolve().parent)
_src = str(Path(__file__).resolve().parent.parent / "cve-analyzer" / "src")
for p in (_scripts, _src):
    if p not in sys.path:
        sys.path.insert(0, p)
```

- [ ] **Step 2: Create package and constants module**

Create `scripts/web_data/__init__.py` (empty).

Create `scripts/web_data/constants.py` with:
- `EXTENSION_TO_LANGUAGE` dict (lines 49-90 of old script)
- `TEMPLATE_EXTENSIONS` frozenset (lines 95-105)
- `DEFAULT_CACHE_DIR`, `DEFAULT_REVIEWS_DIR`, `DEFAULT_NVD_FEEDS_DIR`, `DEFAULT_GHSA_DB_DIR`, `DEFAULT_REPOS_DIR`, `DEFAULT_OUTPUT_DIR` (lines 35-42)
- `STRONG_SIGNAL_TYPES` frozenset (lines 1183-1186)
- `CONF_MAP` dict — string→numeric confidence: `{"high": 0.95, "medium": 0.7, "low": 0.4}`

**Note:** CVSS metric weight maps (`_AV`, `_AC`, `_PR_UNCHANGED`, `_PR_CHANGED`, `_UI`, `_CIA`, `_SEVERITY_KEYWORDS`) stay in `severity.py` as module-level constants — they're internal to severity parsing.

- [ ] **Step 3: Commit**

```bash
git add scripts/web_data/ scripts/conftest.py
git commit -m "refactor: create web_data package with constants and conftest"
```

---

### Task 3: Extract severity module

**Files:**
- Create: `scripts/web_data/severity.py`
- Create: `scripts/tests/test_web_data_severity.py`

- [ ] **Step 1: Write failing tests for severity parsing**

```python
# scripts/tests/test_web_data_severity.py
from web_data.severity import parse_severity, extract_cvss_score

def test_cvss31_critical():
    assert parse_severity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "CRITICAL"

def test_cvss31_medium():
    assert parse_severity("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N") == "MEDIUM"

def test_plain_label():
    assert parse_severity("HIGH") == "HIGH"

def test_extract_score():
    score = extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score >= 9.0

def test_pre_score_overrides():
    assert extract_cvss_score("", pre_score=8.5) == 8.5

def test_unknown_string():
    assert parse_severity("") == "UNKNOWN"

def test_ghsa_fallback():
    assert parse_severity("", ghsa_severity="CRITICAL") == "CRITICAL"
```

- [ ] **Step 2: Implement severity module**

Move from old script into `scripts/web_data/severity.py`:
- `_parse_cvss_vector()` (line 247) — with all CVSS metric weight maps as module-level constants
- `_compute_cvss_score()` (line 266)
- `_extract_cvss_score()` (line 312)
- `_parse_cvss4_severity()` (line 334)
- `_parse_severity_label()` (line 396)
- `_infer_severity_from_description()` (line 451) — with `_SEVERITY_KEYWORDS`

Expose two public functions:
- `parse_severity(severity_str, cvss_score=0.0, ghsa_severity="", description="", vuln_type="") -> str`
- `extract_cvss_score(severity_str, pre_score=0.0) -> float`

- [ ] **Step 3: Run tests, commit**

```bash
cd /home/hanqing/agents/ai-slop && python -m pytest scripts/tests/test_web_data_severity.py -v
git add scripts/web_data/severity.py scripts/tests/test_web_data_severity.py
git commit -m "refactor: extract severity parsing into scripts/web_data/severity.py"
```

---

### Task 4: Extract languages module

**Files:**
- Create: `scripts/web_data/languages.py`

- [ ] **Step 1: Implement languages module**

Move from old script into `scripts/web_data/languages.py`:
- `_file_extension_to_language()` (line 108)
- `_fix_commit_files()` (line 123) — uses `subprocess.run("git diff-tree")` on local repo clones
- `_infer_language_from_template()` (line 148) — project-level language inference for template files
- `determine_languages()` (line 186) — public entry point, takes `bug_commits` list (web-format dicts with `blamed_file`) and optional `fix_commits`

Uses `EXTENSION_TO_LANGUAGE` and `TEMPLATE_EXTENSIONS` from `web_data.constants`.

- [ ] **Step 2: Commit**

```bash
git add scripts/web_data/languages.py
git commit -m "refactor: extract language inference into scripts/web_data/languages.py"
```

---

### Task 5: Extract data loader module

**Files:**
- Create: `scripts/web_data/loader.py`

- [ ] **Step 1: Implement loader module**

Move from old script into `scripts/web_data/loader.py`:
- `load_cached_results()` → **change return type to `list[CveAnalysisResult]`** using `CveAnalysisResult.from_dict()` + `rebuild_signals()`
- `load_reviews()` (unchanged — returns `dict[str, dict]`)
- `load_nvd_published_dates()` (unchanged)
- `load_ghsa_published_dates()` (unchanged)
- `load_ghsa_severities()` (unchanged)
- `load_fix_commit_dates()` → **adapt to accept `list[CveAnalysisResult]`** (access `result.cve_id`, `result.fix_commits`, `fc.sha`, `fc.repo_url` as attributes not dict keys)
- `fetch_ghsa_published_dates_api()` (unchanged)
- `build_alias_map()` (unchanged, rename from `_build_alias_map`)
- `load_audit_overrides()` / `load_audit_override_details()` (rename from `_load_*`)
- `_parse_github_owner_repo()` (internal helper, used by `load_fix_commit_dates` and `_repo_url_to_dir`)
- `_repo_url_to_dir()` (internal helper)

```python
def load_cached_results(cache_dir: str = DEFAULT_CACHE_DIR) -> list[CveAnalysisResult]:
    results: list[CveAnalysisResult] = []
    for filepath in sorted(glob.glob(os.path.join(cache_dir, "*.json"))):
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            result = CveAnalysisResult.from_dict(data)
            result.rebuild_signals()
            results.append(result)
        except Exception as exc:
            print(f"Warning: skipping {filepath}: {exc}", file=sys.stderr)
    return results

def load_fix_commit_dates(results: list[CveAnalysisResult], ...) -> dict[str, str]:
    """Look up commit dates from local repos. Accepts model objects."""
    ...
    for result in results:
        for fc in result.fix_commits:
            repo_dir = _repo_url_to_dir(fc.repo_url)
            ...
```

- [ ] **Step 2: Commit**

```bash
git add scripts/web_data/loader.py
git commit -m "refactor: extract data loaders into scripts/web_data/loader.py"
```

---

### Task 6: Extract filters module

**Files:**
- Create: `scripts/web_data/filters.py`
- Create: `scripts/tests/test_web_data_filters.py`

- [ ] **Step 1: Write failing tests**

```python
# scripts/tests/test_web_data_filters.py
from cve_analyzer.models import CveAnalysisResult, BugIntroducingCommit, CommitInfo, AiSignal, AiTool
from web_data.filters import should_include

def _make_result(cve_id="CVE-2026-0001", ai_involved=None, bics=None):
    r = CveAnalysisResult(cve_id=cve_id)
    r.ai_involved = ai_involved
    if bics:
        r.bug_introducing_commits = bics
        r.rebuild_signals()
    return r

def test_ai_involved_true_included():
    assert should_include(_make_result(ai_involved=True)) is True

def test_ai_involved_false_excluded():
    assert should_include(_make_result(ai_involved=False)) is False

def test_error_result_excluded():
    r = _make_result()
    r.error = "some error"
    assert should_include(r) is False

def test_rejected_cve_excluded():
    r = _make_result()
    r.description = "** REJECTED ** This CVE ID has been rejected"
    assert should_include(r) is False

def test_fallback_verdict_ignored():
    """BIC with is_fallback deep verdict should be treated as unverified."""
    r = _make_result()
    # ... setup BIC with is_fallback=True deep_verification ...
    assert should_include(r) is True  # benefit of the doubt
```

- [ ] **Step 2: Implement filters module**

```python
# scripts/web_data/filters.py
from cve_analyzer.models import CveAnalysisResult

def is_fallback_verdict(dv: dict) -> bool:
    """Return True if the verdict is a timeout/error fallback, not real analysis."""
    if dv.get("is_fallback"):
        return True
    reasoning = dv.get("reasoning", "")
    evidence = dv.get("evidence", None)
    if "Fallback verdict" in reasoning and (not evidence or len(evidence) == 0):
        return True
    return False

def should_include(result: CveAnalysisResult, audit_overrides: set[str] | None = None) -> bool:
    """Determine if a CVE result should appear on the website."""
    if result.error:
        return False
    desc = (result.description or "").lower()
    if "rejected reason:" in desc or "this cve id has been rejected" in desc:
        return False
    if result.cve_id in (audit_overrides or set()):
        return True
    # ai_involved is authoritative when set by investigator
    if result.ai_involved is True:
        return True
    if result.ai_involved is False:
        return False
    # Fallback: check per-BIC verdicts
    has_passing = False
    for bic in result.bug_introducing_commits:
        if not bic.effective_signals() and bic.screening_verification is None:
            continue
        dv = bic.deep_verification
        if dv and not is_fallback_verdict(dv):
            verdict = (dv.get("verdict") or dv.get("final_verdict") or "").upper()
            if verdict == "CONFIRMED":
                return True
            continue  # UNLIKELY/UNRELATED — skip
        has_passing = True  # No deep verify or fallback — benefit of the doubt
    return has_passing
```

Note: `is_fallback_verdict()` preserves the critical fallback-detection logic from the old `_is_fallback_verdict()`.

- [ ] **Step 3: Run tests, commit**

```bash
cd /home/hanqing/agents/ai-slop && python -m pytest scripts/tests/test_web_data_filters.py -v
git add scripts/web_data/filters.py scripts/tests/test_web_data_filters.py
git commit -m "refactor: extract inclusion filters into scripts/web_data/filters.py"
```

---

### Task 7: Implement entry builder (core rewrite)

**Files:**
- Create: `scripts/web_data/entry_builder.py`
- Create: `scripts/tests/test_web_data_entry.py`

This is the largest task — replaces `build_cve_entry()`, `_build_bug_commit()`, and all their helpers.

- [ ] **Step 1: Write failing tests**

```python
# scripts/tests/test_web_data_entry.py
from cve_analyzer.models import (
    CveAnalysisResult, BugIntroducingCommit, CommitInfo, AiSignal, AiTool,
    FixCommit, DecomposedCommit,
)
from web_data.entry_builder import build_entry

def _commit(sha="a"*40, ai_signals=None, **kw):
    defaults = dict(sha=sha, author_name="Dev", author_email="dev@x.com",
                    committer_name="Dev", committer_email="dev@x.com",
                    message="fix: stuff", authored_date="2026-01-01")
    defaults.update(kw)
    c = CommitInfo(**defaults)
    c.ai_signals = ai_signals or []
    return c

def _sig(tool=AiTool.CLAUDE_CODE, signal_type="co_author_trailer", confidence=0.95, origin="commit_metadata"):
    return AiSignal(tool=tool, signal_type=signal_type,
                    matched_text="Co-authored-by: Claude", confidence=confidence, origin=origin)

def _result(bics, ai_involved=None):
    r = CveAnalysisResult(cve_id="CVE-2026-0001", description="Test vuln")
    r.fix_commits = [FixCommit(sha="f"*40, repo_url="https://github.com/owner/repo", source="osv")]
    r.bug_introducing_commits = bics
    r.ai_involved = ai_involved
    r.rebuild_signals()
    return r

def test_basic_entry_has_required_fields():
    bic = BugIntroducingCommit(commit=_commit(ai_signals=[_sig()]),
                                fix_commit_sha="f"*40, blamed_file="src/main.py",
                                blamed_lines=[10], blame_confidence=0.9)
    entry = build_entry(_result([bic]))
    assert entry["id"] == "CVE-2026-0001"
    assert entry["ai_tools"] == ["claude_code"]
    assert entry["signal_source"] == "commit"
    assert "bug_commits" in entry

def test_pr_body_only_signal_source():
    sig = _sig(signal_type="pr_body_keyword", origin="pr_body")
    bic = BugIntroducingCommit(commit=_commit(), fix_commit_sha="f"*40,
                                blamed_file="src/main.py", blamed_lines=[10],
                                blame_confidence=0.9, pr_signals=[sig])
    entry = build_entry(_result([bic]))
    assert entry["signal_source"] == "pr_body"

def test_ai_involved_true_gets_ai_assisted_fallback():
    bic = BugIntroducingCommit(commit=_commit(), fix_commit_sha="f"*40,
                                blamed_file="src/main.py", blamed_lines=[10],
                                blame_confidence=0.9)
    entry = build_entry(_result([bic], ai_involved=True))
    assert "ai_assisted" in entry["ai_tools"]

def test_culprit_promotion():
    """Culprit sub-commit's SHA/author/signals should replace squash merge's."""
    dc = DecomposedCommit(sha="culprit123", author_name="AI Dev",
                           author_email="ai@x.com", message="add feature",
                           ai_signals=[_sig()], touched_blamed_file=True)
    bic = BugIntroducingCommit(commit=_commit(sha="squash456"),
                                fix_commit_sha="f"*40, blamed_file="src/main.py",
                                blamed_lines=[10], blame_confidence=0.9,
                                decomposed_commits=[dc], culprit_sha="culprit123")
    entry = build_entry(_result([bic]))
    bc = entry["bug_commits"][0]
    assert bc["sha"] == "culprit123"
    assert bc["squash_merge_sha"] == "squash456"

def test_unrelated_bic_excluded_from_bug_commits():
    """BICs with UNRELATED verdict should not appear in bug_commits."""
    bic = BugIntroducingCommit(commit=_commit(ai_signals=[_sig()]),
                                fix_commit_sha="f"*40, blamed_file="src/main.py",
                                blamed_lines=[10], blame_confidence=0.9,
                                deep_verification={"verdict": "UNRELATED", "model": "test"})
    entry = build_entry(_result([bic], ai_involved=True))
    assert entry["bug_commits"] == []
```

- [ ] **Step 2: Implement entry_builder module**

```python
# scripts/web_data/entry_builder.py
from __future__ import annotations
from cve_analyzer.models import (
    CveAnalysisResult, BugIntroducingCommit, AiSignal, WORKFLOW_SIGNAL_TYPES,
)
from cve_analyzer.scoring import compute_ai_confidence
from web_data.constants import STRONG_SIGNAL_TYPES, CONF_MAP
from web_data.severity import parse_severity, extract_cvss_score
from web_data.languages import determine_languages
from web_data.filters import is_fallback_verdict
```

The module must implement these internal functions (moved from old script):

| Function | Old location | What it does |
|----------|-------------|--------------|
| `build_entry()` | `build_cve_entry` L1163 | Top-level: CveAnalysisResult → web dict |
| `_build_bug_commit()` | `_build_bug_commit` L990 | BIC → web-format bug commit dict |
| `_build_signal_entry()` | `_build_signal_entry` L980 | AiSignal → compact display dict |
| `_first_line()` | `_first_line` L943 | Extract first line of commit message |
| `_lookup_pr_for_commit()` | `_lookup_pr_for_commit` L953 | Look up PR URL from API cache |
| `_extract_published_year()` | `_extract_published_year` L929 | Year from CVE ID as date fallback |
| `_model_with_reasoning_tag()` | nested in `build_cve_entry` L1342 | Model name + reasoning suffix for `verified_by` |
| `_get_effective_verdict()` | replaces `_effective_verdict` | Read `bic.deep_verification` dict directly, check for fallback |

Key behaviors `build_entry()` must handle (in order):

1. **AI tools extraction** — iterate `result.bug_introducing_commits`, call `bic.effective_signals()`, skip WORKFLOW_SIGNAL_TYPES, skip UNRELATED verdict BICs, skip weak `unknown_ai`. Track `signal_source` from origins.
2. **ai_involved fallback** — if `result.ai_involved is True` but `ai_tools` is empty, set `["ai_assisted"]`.
3. **Bug commits** — call `_build_bug_commit(bic)` for BICs with effective signals and non-UNRELATED/UNLIKELY verdict. Deduplicate by SHA (merge blamed_file). Deduplicate by identical verification reasoning.
4. **Culprit SHA promotion** — in `_build_bug_commit`: if BIC has `culprit_sha` + `decomposed_commits`, find culprit DC, swap sha/author/message/ai_signals, record `squash_merge_sha`. Infer culprit if not set (prefer DC with `touched_blamed_file=True` and signals).
5. **Verification formatting** — in `_build_bug_commit`: extract `screening_verification`, format `deep_verification` (both old multi-model and new single-model format), map string confidence via `CONF_MAP`.
6. **PR URL lookup** — in `_build_bug_commit`: call `_lookup_pr_for_commit()` using API response cache.
7. **Severity resolution** — call `parse_severity()` with all fallback sources.
8. **verified_by** — extract from first CONFIRMED deep verdict, apply `_model_with_reasoning_tag()`.
9. **how_introduced / root_cause / vuln_type** — prefer screening `causal_chain` over deep-verify reasoning for confirmed BICs. Fall back when only screening exists without deep verify.
10. **Audit override** — when `is_override` and no CONFIRMED verdict, force verdict to CONFIRMED, set `verified_by` to "independent-audit", replace deep-verify verdicts with screening data.

**Critical invariant:** Uses `bic.effective_signals()` not `bic.commit.ai_signals`. Uses `bic.deep_verification` as a dict directly (it's stored as raw dict in the model). Uses `bic.screening_verification` as `LlmVerdict` model (access `.verdict`, `.reasoning`, etc. as attributes).

- [ ] **Step 3: Run tests, commit**

```bash
cd /home/hanqing/agents/ai-slop && python -m pytest scripts/tests/test_web_data_entry.py -v
git add scripts/web_data/entry_builder.py scripts/tests/test_web_data_entry.py
git commit -m "feat: implement model-based entry builder for web data"
```

---

### Task 8: Extract stats module

**Files:**
- Create: `scripts/web_data/stats.py`

- [ ] **Step 1: Move `build_stats()` and helpers**

Move from old script to `scripts/web_data/stats.py`:
- `build_stats()` (line 1516)
- `_extract_month()` (line 1593)
- `_repo_url_to_display_name()` (line 573)

These operate on web entry dicts (output of entry_builder), not model objects — no change needed.

- [ ] **Step 2: Commit**

```bash
git add scripts/web_data/stats.py
git commit -m "refactor: extract stats builder into scripts/web_data/stats.py"
```

---

### Task 9: Rewrite main script as thin orchestrator

**Files:**
- Modify: `scripts/generate_web_data.py` — replace 1823-line monolith with ~200-line orchestrator

- [ ] **Step 1: Rewrite the script**

The new `main()` must handle these orchestration steps (currently scattered in old `main()` lines 1609-1823):

```python
def main(argv=None):
    # 1. Parse args: --output-dir, --cache-dir, --since
    # 2. Load: cached results (as CveAnalysisResult), reviews, NVD/GHSA dates, severities
    # 3. Merge date sources: NVD takes precedence, GHSA fills gaps
    # 4. Filter: should_include() per result, count excluded
    # 5. Fetch missing GHSA dates via API
    # 6. Fix commit date fallback from local repos
    # 7. Build entries: build_entry() per filtered result, collect non-None
    # 8. Exclude entries with no ai_tools (after ai_involved fallback in build_entry)
    # 9. Alias deduplication: build_alias_map(), prefer CVE-* over GHSA-*
    # 10. Sort: CONFIRMED-first, then confidence descending
    # 11. Coverage stats: count total_in_range, with_fix_commits for --since window
    # 12. Build stats: build_stats()
    # 13. Write cves.json and stats.json
    # 14. Print summary
```

**Note:** `--min-confidence` flag is intentionally removed (always defaulted to 0.0, never used in practice). The `should_include` filter is verdict-based, not confidence-based.

- [ ] **Step 2: Run and compare with baseline**

```bash
cd /home/hanqing/agents/ai-slop
python scripts/generate_web_data.py
python -c "
import json
old = json.load(open('web/data/cves_baseline.json'))
new = json.load(open('web/data/cves.json'))
old_ids = {e['id'] for e in old['cves']}
new_ids = {e['id'] for e in new['cves']}
print(f'Old: {len(old_ids)} CVEs, New: {len(new_ids)} CVEs')
print(f'Only in old: {old_ids - new_ids}')
print(f'Only in new: {new_ids - old_ids}')
for oid in sorted(old_ids & new_ids):
    oe = next(e for e in old['cves'] if e['id'] == oid)
    ne = next(e for e in new['cves'] if e['id'] == oid)
    for key in ('ai_tools', 'confidence', 'severity', 'verdict', 'signal_source'):
        if oe.get(key) != ne.get(key):
            print(f'  {oid}.{key}: {oe.get(key)} -> {ne.get(key)}')
"
```

Expected: Identical or explainable differences.

- [ ] **Step 3: Commit**

```bash
git add scripts/generate_web_data.py
git commit -m "refactor: rewrite generate_web_data.py as thin orchestrator over web_data package"
```

---

### Task 10: Clean up — delete baseline, verify, final tests

**Files:**
- Delete: `web/data/cves_baseline.json`

- [ ] **Step 1: Verify no dict-level model logic remains**

```bash
grep -rn "result.get(\"bug_introducing_commits\")\|_get_effective_signals_dict\|_effective_verdict\|_has_no_confirmed_verdict\|_get_deep_verdict\|_get_screening_verdict" scripts/web_data/*.py scripts/generate_web_data.py
```

Expected: No matches.

- [ ] **Step 2: Run full test suite**

```bash
cd /home/hanqing/agents/ai-slop/cve-analyzer && uv run pytest tests/ -q
cd /home/hanqing/agents/ai-slop && python -m pytest scripts/tests/ -q
```

Expected: All pass.

- [ ] **Step 3: Delete baseline and commit**

```bash
git rm web/data/cves_baseline.json
git add -A
git commit -m "chore: complete web data rewrite, remove baseline"
```

---

## Summary

| Task | What | Lines |
|------|------|-------|
| 1 | Snapshot baseline | 0 new |
| 2 | Package + constants + conftest | ~60 |
| 3 | Extract severity | ~200 |
| 4 | Extract languages | ~130 |
| 5 | Extract loader | ~200 |
| 6 | Extract filters | ~70 |
| 7 | Entry builder (core) | ~350 |
| 8 | Extract stats | ~80 |
| 9 | Rewrite main | ~200 |
| 10 | Cleanup | 0 new |

**Total new code:** ~1,290 lines across 7 focused modules (vs 1,823 in one file). Net reduction of ~530 lines, with all model logic deduplicated.

**Key invariant:** Every signal/verdict decision goes through model methods. No raw dict access for model data.
