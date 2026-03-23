# Screening-Gated Verification Pipeline

## Problem

The verification pipeline has two structural flaws:

### 1. `touched_blamed_file` is a hard gate, not a hint

`effective_signals()` (models.py:314-324) drops all AI signals when `culprit.touched_blamed_file is False`. This means:
- If an AI atomic commit didn't touch the specific file that `git blame` points to, its signals are invisible to the entire pipeline
- `_should_deep_verify()` returns False, screening never runs, deep verify never runs
- 92 CVEs currently have AI signals in decomposed sub-commits but get zero verification

The audit of these 92 CVEs found all were correctly excluded (AI code was genuinely unrelated), but the reasoning path is wrong. File-level matching is a syntactic shortcut — vulnerabilities can have cross-file causal chains where AI code changes calling context, API contracts, or configuration without touching the blamed file.

### 2. Screening exists but doesn't gate anything

`_should_deep_verify()` (pipeline.py:409-418) only checks `effective_signals()`, completely ignoring screening verdicts. Screening runs, stores results, but its verdicts have zero influence on whether deep verification happens. Meanwhile `touched_blamed_file` — a file-name match — makes the decision that screening should be making.

Additionally, screening is per-BIC while the real question is per-CVE: "did AI contribute to this vulnerability?" A single BIC examined in isolation misses cross-BIC causal chains.

### Current funnel (2026-03-23)

```
  6,642  CVEs with BICs
    242  Any AI signals in BIC/PR (Layer 1)
    150  effective_signals() non-empty — touched_blamed_file gate (Layer 2)
     70  Have screening verification
    150  Have deep verification
     79  Final website output
```

92 CVEs filtered between Layer 1→2 by `touched_blamed_file` alone, with zero LLM judgment.

## Design

### Architecture

```
Phase B.2: Signal detection on all decomposed atomic commits (unchanged)
      ↓ CVEs with any AI atomic commits (242 today)
Phase C: Per-CVE screening (new — replaces per-BIC llm_verify)
      - Input: vulnerability + ALL AI atomic commits + blamed files + touched_blamed_file info
      - Output: worth_investigating + relevant atomic commit SHAs + reasoning
      - Gate: lenient — only filter obviously unrelated cases
      ↓ worth_investigating=true
Phase D: Deep investigator (existing — per-CVE, tool access)
      - Receives screening's relevant_commits as focus hints
      - Only runs on BICs whose atomic commits appear in relevant_commits
      - Final verdict
```

### Key principle: screening is lenient, deep verify is strict

Screening's job is cost control — filter obviously unrelated cases cheaply. It should err on the side of inclusion. Only cases where AI code is clearly in a different feature/module/subsystem get filtered. Ambiguous cases (same module, possible indirect contribution, unclear causal chain) pass through to deep verify.

### Change 1: Add `all_ai_signals()` method, keep `effective_signals()` unchanged

`effective_signals()` retains its `touched_blamed_file is not False` check — this is correct for **confidence scoring** (AI wrote the blamed code directly → higher confidence). The gate decision uses a new method instead.

```python
# On BugIntroducingCommit:

def all_ai_signals(self) -> list[AiSignal]:
    """ALL AI signals from any decomposed sub-commit + PR signals.

    Used for the screening gate: any AI presence in the PR, regardless of
    which sub-commit touched the blamed file. This is broader than
    effective_signals(), which only returns culprit signals.
    """
    signals: list[AiSignal] = []
    for dc in self.decomposed_commits:
        signals.extend(dc.ai_signals)
    signals.extend(self.pr_signals)
    if not self.decomposed_commits:
        signals.extend(self.commit.ai_signals)
    return signals
```

**Separation of concerns:**
- `effective_signals()` → confidence scoring (culprit-focused, `touched_blamed_file` matters)
- `all_ai_signals()` → screening gate (any AI in the PR → worth screening)

### Change 2: Per-CVE screening replaces per-BIC

New function `screen_cve()` in `llm_verify.py`, replacing `verify_result()` as the primary screening entry point. `verify_bic()` and `verify_result()` remain for backward compatibility with cached per-BIC results but are no longer called on new analyses.

**Input** (one LLM call per CVE):
- CVE description, CWEs, severity
- Vulnerability analysis (from existing Phase 1 `analyze_vulnerability()`)
- For each BIC with AI atomic commits:
  - BIC SHA, blamed file, blame strategy
  - Each AI atomic commit: SHA, author, message, files touched, `touched_blamed_file`
  - Non-AI culprit info (if culprit is not AI): SHA, message, files touched

**Output**:
```json
{
  "worth_investigating": true,
  "reasoning": "Copilot commit ef7e662f modified OTA download logic in the same module as the firmware verification vulnerability",
  "relevant_commits": ["ef7e662f", "daeb9e35"]
}
```

**Prompt guidance** (lenient):
- `worth_investigating: false` ONLY when AI commits are clearly in a different feature, module, or subsystem from the vulnerability
- `worth_investigating: true` when AI commits:
  - Touched the blamed file
  - Are in the same module/package as the vulnerability
  - Could have changed calling context, API contracts, or configuration
  - Are ambiguous or you're not sure
- When in doubt, say `true`

**Failure handling:** If the LLM call fails (timeout, rate limit, parse error), `screen_cve()` returns `None`. The pipeline treats `None` as "screening inconclusive" → proceed to deep verify (fail-open, consistent with lenient design).

**Caching:** Keyed by CVE ID + model + hash of BIC SHAs. On re-run with same BICs, cached screening is reused. If BICs change (new blame run), screening re-runs.

### Change 3: CVE-level gate replaces BIC-level gate

Delete `_should_deep_verify(bic)`. Replace with:

```python
def _cve_needs_deep_verify(result: CveAnalysisResult) -> bool:
    """CVE-level gate: did screening say worth investigating?"""
    if result.screening is not None:
        return result.screening.worth_investigating
    # No screening yet (old cached result or screening failed) —
    # fall back to any AI signals present
    return any(bic.all_ai_signals() for bic in result.bug_introducing_commits)
```

**Deep verify scope narrowing:** When screening provides `relevant_commits`, `_run_deep_verify()` passes this list to the investigator. The investigator focuses on these commits but is not restricted to them — it can examine other commits if its tool-based investigation reveals connections. The `relevant_commits` are hints, not hard constraints.

### Change 4: Filtering log in result JSON

New dataclass for post-hoc analysis of pipeline decisions:

```python
@dataclass
class FilteringLog:
    """Records filtering decisions at each pipeline layer."""
    # Phase B.2: which BICs have AI signals anywhere
    ai_signal_bics: list[str] = field(default_factory=list)         # BIC SHAs
    ai_atomic_commits: list[dict] = field(default_factory=list)     # {sha, tool, touched_blamed_file, bic_sha}
    # Phase C: screening decision
    screening_result: dict | None = None                            # screen_cve() output
    # Phase D: deep verification outcomes
    deep_verify_verdicts: list[dict] = field(default_factory=list)  # {sha, verdict, confidence, reasoning}
    # Final: website inclusion decision
    final_included: bool = False
    exclusion_reason: str = ""                                      # why excluded from website

    def to_dict(self) -> dict: ...
    @classmethod
    def from_dict(cls, data: dict) -> FilteringLog: ...
```

**Population points:**
- `ai_signal_bics` + `ai_atomic_commits`: populated after Phase B.2 (signal detection), before screening
- `screening_result`: populated after Phase C (screening)
- `deep_verify_verdicts`: populated after Phase D (deep verify), from each BIC's `deep_verification`
- `final_included` + `exclusion_reason`: populated by `generate_web_data.py` during website generation

Added to `CveAnalysisResult`:
```python
filtering_log: FilteringLog | None = None
```

**Serialization:** `to_dict()` includes `filtering_log` when present. `from_dict()` reads it with `FilteringLog.from_dict(data["filtering_log"])` if key exists, else `None`.

### Change 5: CVE-level screening result on CveAnalysisResult

```python
@dataclass
class CveScreeningResult:
    """Per-CVE screening output (replaces per-BIC screening_verification)."""
    worth_investigating: bool
    reasoning: str
    relevant_commits: list[str] = field(default_factory=list)  # atomic commit SHAs
    model: str = ""

    def to_dict(self) -> dict: ...
    @classmethod
    def from_dict(cls, data: dict) -> CveScreeningResult: ...
```

Named `CveScreeningResult` to avoid collision with existing `verifier.models.ScreeningResult` (which is the triage agent's output — different concept, different schema).

Added to `CveAnalysisResult`:
```python
screening: CveScreeningResult | None = None
```

**Serialization:** `to_dict()` includes `"screening": self.screening.to_dict()` when present. `from_dict()` reads it if key exists.

**Backward compatibility with per-BIC screening:**
- `_cve_needs_deep_verify()` checks `result.screening` first (new per-CVE format)
- If `result.screening` is `None` but any BIC has `screening_verification` (old per-BIC format), synthesize: `worth_investigating = any CONFIRMED or UNLIKELY BIC exists`
- On re-run, new per-CVE screening overrides old per-BIC results for the gate decision. Per-BIC `screening_verification` values are preserved on BICs for historical reference but not consulted for gate decisions.

### Change 6: Pipeline flow update

```python
# Phase C: Per-CVE screening (new)
has_ai_bics = any(bic.all_ai_signals() for bic in result.bug_introducing_commits)
if llm_verify and has_ai_bics:
    # Populate filtering log: signal inventory
    result.filtering_log = _build_filtering_log(result)

    # Run per-CVE screening (returns None on failure → fail-open)
    result.screening = screen_cve(result, repo_path, vuln_analysis=vuln_analysis)
    if result.screening:
        result.filtering_log.screening_result = result.screening.to_dict()

# Phase D: Deep verification (only if screening passed or was inconclusive)
if llm_verify and _cve_needs_deep_verify(result):
    _run_deep_verify(
        result, cve_id,
        relevant_commits=result.screening.relevant_commits if result.screening else None,
        ...
    )
    # Record deep verify outcomes in filtering log
    if result.filtering_log:
        result.filtering_log.deep_verify_verdicts = [
            {"sha": bic.commit.sha, "verdict": bic.deep_verification.get("verdict", ""),
             "reasoning": bic.deep_verification.get("reasoning", "")}
            for bic in result.bug_introducing_commits
            if bic.deep_verification
        ]
```

### Change 7: Deep verifier receives screening hints

Update `_build_bic_candidates()` to pass per-CVE screening context instead of per-BIC:

```python
def _build_bic_candidates(bics, screening=None):
    candidates = []
    for bic in bics:
        candidate = {
            "sha": bic.commit.sha,
            "blamed_file": bic.blamed_file,
            ...
        }
        # Pass screening hints (which atomic commits are relevant)
        if screening and screening.relevant_commits:
            relevant_in_bic = [
                sha for sha in screening.relevant_commits
                if any(dc.sha.startswith(sha) for dc in bic.decomposed_commits)
            ]
            if relevant_in_bic:
                candidate["screening_flagged_commits"] = relevant_in_bic
                candidate["screening_reasoning"] = screening.reasoning
        candidates.append(candidate)
    return candidates
```

### Change 8: Deprecate per-BIC screening in pipeline

In `_enrich_single()` and the cached-result path:
- Remove the `_needs_llm` check that calls `verify_result()` (per-BIC screening)
- Replace with `screen_cve()` call (per-CVE screening)
- Keep `verify_result()` / `verify_bic()` in `llm_verify.py` for backward compatibility (reading cached per-BIC results) but stop calling them on new analyses

## Backward Compatibility

| Scenario | Behavior |
|----------|----------|
| Old cached result with per-BIC `screening_verification` | Gate falls back to checking per-BIC verdicts: any CONFIRMED/UNLIKELY → deep verify |
| Old cached result, re-run with new pipeline | Per-CVE screening runs, `result.screening` populated, overrides per-BIC for gate |
| New result | Only per-CVE screening, no per-BIC `screening_verification` written |
| `FilteringLog` missing | Treated as `None`, no breakage |
| `CveScreeningResult` missing | Treated as `None`, falls back to `all_ai_signals()` check |

**Serialization migration:**
- `CveAnalysisResult.from_dict()`: reads `screening` and `filtering_log` if present, defaults to `None`
- `CveAnalysisResult.to_dict()`: writes `screening` and `filtering_log` when not `None`
- No migration script needed — old and new formats coexist

## Cost Impact

- 92 new CVEs enter screening (previously gate-blocked): +92 cheap LLM calls (~$0.04 each = ~$3.68)
- Audit shows all 92 are genuinely unrelated → most will screen out → deep verify cost ~unchanged
- Sensitivity: if 20% pass screening (18 CVEs), deep verify adds ~$7-15 depending on model
- Per-CVE screening replaces per-BIC: fewer total screening calls (1 per CVE vs N per BIC)
- Net: slightly more screening calls, roughly same deep verify calls, better accuracy

## Files to Modify

| File | Change |
|------|--------|
| `models.py` | Add `all_ai_signals()` on BIC, `CveScreeningResult`, `FilteringLog`, serialization |
| `llm_verify.py` | Add `screen_cve()`, deprecate `verify_result()` calls in pipeline |
| `pipeline.py` | Replace `_should_deep_verify` with `_cve_needs_deep_verify`, rewire Phase C/D, populate filtering_log, stop calling `verify_result()` |
| `verifier/agent_loop.py` | Accept `relevant_commits` hint, pass to investigation prompt |
| `web_data/filters.py` | Populate `filtering_log.final_included` / `exclusion_reason` |
| `web_data/entry_builder.py` | Read per-CVE screening for display (optional) |

## Verification

### Unit tests
1. `all_ai_signals()` returns signals from non-touched-file decomposed commits
2. `all_ai_signals()` returns empty for BICs with no AI signals anywhere
3. `CveScreeningResult` and `FilteringLog` serialization roundtrip
4. `_cve_needs_deep_verify()` with per-CVE screening (true/false)
5. `_cve_needs_deep_verify()` fallback with per-BIC screening (old format)
6. `_cve_needs_deep_verify()` fallback with no screening (uses `all_ai_signals`)

### Integration tests
7. Re-run 5 NOT_VERIFIED CVEs (CVE-2025-12875, CVE-2025-13321, CVE-2025-59418, CVE-2026-27938, CVE-2026-32294) — these have AI signals on non-touched-file commits. Expect screening to run and return `worth_investigating: false` (AI code clearly unrelated)
8. Re-run CVE-2025-59163 — Copilot added wildcard CORS in same module. Expect screening `worth_investigating: true`
9. Pipeline re-run idempotency: running twice produces same result (screening cached)

### Regression tests
10. `uv run pytest` — all existing tests pass
11. Regenerate web data — no TP regression (79 or more)
12. Compare filtering funnel before/after across full 242 AI-signal CVEs
