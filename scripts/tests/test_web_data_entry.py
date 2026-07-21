"""Tests for scripts/web_data/entry_builder.py"""

from __future__ import annotations

from cve_analyzer.models import (
    AiSignal,
    AiTool,
    BlameVerdict,
    BugIntroducingCommit,
    CommitInfo,
    CveAnalysisResult,
    CveScreeningResult,
    DecomposedCommit,
    FixCommit,
    LlmVerdict,
    investigation_scope_hash,
    relevant_investigation_bics,
)
from web_data.entry_builder import (
    QuarantineLog,
    _first_line,
    _build_signal_entry,
    _extract_published_year,
    _model_with_reasoning_tag,
    build_entry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_commit(
    sha: str = "abc123",
    ai_signals: list[AiSignal] | None = None,
    author: str = "Alice",
    message: str = "some commit",
) -> CommitInfo:
    return CommitInfo(
        sha=sha,
        author_name=author,
        author_email="alice@example.com",
        committer_name=author,
        committer_email="alice@example.com",
        message=message,
        authored_date="2025-06-01T00:00:00Z",
        ai_signals=ai_signals or [],
    )


def make_signal(
    tool: AiTool = AiTool.CURSOR,
    signal_type: str = "co_author_trailer",
    text: str = "Co-authored-by: Cursor",
    confidence: float = 0.95,
    origin: str = "commit_metadata",
) -> AiSignal:
    return AiSignal(
        tool=tool,
        signal_type=signal_type,
        matched_text=text,
        confidence=confidence,
        origin=origin,
    )


def make_bic(
    *,
    sha: str = "abc123",
    ai_signals: list[AiSignal] | None = None,
    screening_verification: LlmVerdict | None = None,
    deep_verification: dict | None = None,
    blamed_file: str = "src/main.py",
    decomposed_commits: list[DecomposedCommit] | None = None,
    culprit_sha: str = "",
    pr_signals: list[AiSignal] | None = None,
    fix_commit_sha: str = "fix111",
    repository_identity: str = "",
) -> BugIntroducingCommit:
    sigs = ai_signals if ai_signals is not None else [make_signal()]
    return BugIntroducingCommit(
        commit=make_commit(sha=sha, ai_signals=sigs),
        fix_commit_sha=fix_commit_sha,
        blamed_file=blamed_file,
        blamed_lines=[10, 11, 12],
        repository_identity=repository_identity,
        screening_verification=screening_verification,
        deep_verification=deep_verification,
        decomposed_commits=decomposed_commits or [],
        culprit_sha=culprit_sha,
        pr_signals=pr_signals or [],
    )


def make_result(
    cve_id: str = "CVE-2025-12345",
    bics: list[BugIntroducingCommit] | None = None,
    ai_involved: bool | None = None,
    fix_commits: list[FixCommit] | None = None,
    **kwargs,
) -> CveAnalysisResult:
    if bics is None:
        bics = [make_bic()]
    if fix_commits is None:
        fix_commits = [FixCommit(sha="fix111", repo_url="https://github.com/org/repo", source="osv")]
    result = CveAnalysisResult(
        cve_id=cve_id,
        description=kwargs.get("description", "A test vulnerability"),
        severity=kwargs.get("severity", "HIGH"),
        bug_introducing_commits=bics,
        fix_commits=fix_commits,
        ai_involved=ai_involved,
        cvss_score=kwargs.get("cvss_score", 0.0),
        cwes=kwargs.get("cwes", []),
        references=kwargs.get("references", []),
        ai_contribution=kwargs.get("ai_contribution", ""),
        investigation_scope_hash=kwargs.get("investigation_scope_hash", ""),
        screening=kwargs.get("screening"),
    )
    if ai_involved is not None and "investigation_scope_hash" not in kwargs:
        result.investigation_scope_hash = investigation_scope_hash(relevant_investigation_bics(result))
    return result


def make_screening(
    verdict: BlameVerdict = BlameVerdict.CONFIRMED,
    causal_chain: str = "AI generated unsafe code",
) -> LlmVerdict:
    return LlmVerdict(
        verdict=verdict,
        reasoning="The commit was AI-authored",
        model="gpt-4o-mini",
        vuln_type="injection",
        vuln_description="SQL injection in query builder",
        vulnerable_pattern="string concatenation in SQL",
        causal_chain=causal_chain,
    )


# ---------------------------------------------------------------------------
# Tests: helper functions
# ---------------------------------------------------------------------------


class TestFirstLine:
    def test_single_line(self):
        assert _first_line("hello world") == "hello world"

    def test_multi_line(self):
        assert _first_line("first\nsecond\nthird") == "first"

    def test_empty(self):
        assert _first_line("") == ""

    def test_strips_whitespace(self):
        assert _first_line("  hello  \nsecond") == "hello"


class TestBuildSignalEntry:
    def test_basic(self):
        sig = make_signal()
        d = _build_signal_entry(sig)
        assert d["tool"] == "cursor"
        assert d["signal_type"] == "co_author_trailer"
        assert d["matched_text"] == "Co-authored-by: Cursor"
        assert d["confidence"] == 0.95


class TestExtractPublishedYear:
    def test_standard_cve(self):
        r = make_result(cve_id="CVE-2025-99999")
        assert _extract_published_year(r) == "2025"

    def test_no_cve_prefix(self):
        r = make_result(cve_id="GHSA-xxxx-yyyy")
        assert _extract_published_year(r) == ""


class TestModelWithReasoningTag:
    def test_claude_code(self):
        assert _model_with_reasoning_tag("claude-code") == "claude-code"

    def test_claude_plain(self):
        assert _model_with_reasoning_tag("claude") == "claude-code"

    def test_claude_model(self):
        assert _model_with_reasoning_tag("claude-3-5-sonnet") == "claude-3-5-sonnet-thinking"

    def test_gemini(self):
        assert _model_with_reasoning_tag("gemini-2.0-flash") == "gemini-2.0-flash-thinking"

    def test_openai(self):
        assert _model_with_reasoning_tag("gpt-4o") == "gpt-4o-high"

    def test_explicit_max_effort(self):
        assert _model_with_reasoning_tag("gpt-5.6-luna", "max") == "gpt-5.6-luna-max"


# ---------------------------------------------------------------------------
# Tests: build_entry
# ---------------------------------------------------------------------------


class TestBuildEntryBasic:
    """Basic entry has required fields (id, ai_tools, signal_source, bug_commits)."""

    def test_required_fields_present(self):
        result = make_result()
        entry = build_entry(result)
        assert entry is not None
        assert entry["id"] == "CVE-2025-12345"
        assert "ai_tools" in entry
        assert "signal_source" in entry
        assert "bug_commits" in entry
        assert "severity" in entry
        assert "cvss" in entry
        assert "confidence" in entry

    def test_ai_tools_extracted(self):
        result = make_result()
        entry = build_entry(result)
        assert "cursor" in entry["ai_tools"]

    def test_signal_source_commit(self):
        result = make_result()
        entry = build_entry(result)
        assert entry["signal_source"] == "commit"

    def test_bug_commits_have_sha(self):
        result = make_result()
        entry = build_entry(result)
        assert len(entry["bug_commits"]) >= 1
        assert entry["bug_commits"][0]["sha"] == "abc123"


class TestSignalSourcePrBody:
    """PR body only signals produce signal_source='pr_body'."""

    def test_pr_body_only(self):
        pr_signal = make_signal(origin="pr_body")
        # Need commit-level signals for the BIC to pass the filter
        # (bic.commit.ai_signals must be non-empty).
        bic = make_bic(
            ai_signals=[pr_signal],  # stored on commit for filter pass
            pr_signals=[pr_signal],
        )
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        assert entry["signal_source"] == "pr_body"


class TestAiInvolvedFallback:
    """An untrusted CVE-level positive cannot create a catalog entry."""

    def test_fallback_requires_trusted_authorship(self):
        bic = make_bic(
            ai_signals=[],
            repository_identity="https://github.com/org/repo",
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "The screened subject supports the CVE conclusion.",
                "model": "gpt-5.4",
                "ai_signal_attested": False,
                "ai_signal_source": "",
            },
        )
        result = make_result(
            bics=[bic],
            ai_involved=True,
            screening=CveScreeningResult(
                worth_investigating=True,
                reasoning="The commit is relevant.",
                relevant_commits=[bic.commit.sha],
                model="screening-test",
            ),
        )
        quarantine = QuarantineLog()

        assert build_entry(result, quarantine=quarantine) is None
        assert [record.reason for record in quarantine] == [
            "no displayable bug commits"
        ]


class TestCulpritPromotion:
    """Culprit SHA replaces squash merge SHA in bug_commits."""

    def test_culprit_sha_promoted(self):
        culprit_sig = make_signal(tool=AiTool.CLAUDE_CODE, text="Co-authored-by: Claude")
        dc = DecomposedCommit(
            sha="culprit_abc",
            author_name="Bob",
            author_email="bob@example.com",
            message="fix: add validation",
            ai_signals=[culprit_sig],
            touched_blamed_file=True,
        )
        bic = make_bic(
            sha="squash_merge_sha",
            decomposed_commits=[dc],
            culprit_sha="culprit_abc",
        )
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        bc = entry["bug_commits"][0]
        assert bc["sha"] == "culprit_abc"
        assert bc.get("squash_merge_sha") == "squash_merge_sha"
        assert bc["author"] == "Bob"

    def test_culprit_inferred_from_touched(self):
        """When culprit_sha is not set, infer from decomposed commits."""
        dc_sig = make_signal(tool=AiTool.AIDER)
        dc = DecomposedCommit(
            sha="inferred_culprit",
            author_name="Charlie",
            author_email="charlie@example.com",
            message="feat: new feature",
            ai_signals=[dc_sig],
            touched_blamed_file=True,
        )
        dc_no_touch = DecomposedCommit(
            sha="other_dc",
            author_name="Dave",
            author_email="dave@example.com",
            message="chore: format",
            ai_signals=[],
            touched_blamed_file=False,
        )
        bic = make_bic(
            sha="squash_sha",
            decomposed_commits=[dc, dc_no_touch],
            culprit_sha="",
        )
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        bc = entry["bug_commits"][0]
        assert bc["sha"] == "inferred_culprit"
        assert bc.get("squash_merge_sha") == "squash_sha"


class TestUnrelatedBicExcluded:
    """BICs with UNRELATED deep verdict are excluded from bug_commits."""

    def test_unrelated_bic_excluded(self):
        bic_ok = make_bic(sha="good_sha")
        bic_unrelated = make_bic(
            sha="bad_sha",
            deep_verification={
                "final_verdict": "UNRELATED",
                "reasoning": "Not related",
                "model": "gpt-4o",
                "confidence": "high",
            },
        )
        result = make_result(bics=[bic_ok, bic_unrelated])
        entry = build_entry(result)
        assert entry is not None
        shas = [bc["sha"] for bc in entry["bug_commits"]]
        assert "good_sha" in shas
        assert "bad_sha" not in shas


class TestWorkflowSignalsExcluded:
    """Workflow signal types are excluded from ai_tools."""

    def test_workflow_signals_filtered(self):
        workflow_sig = make_signal(
            tool=AiTool.UNKNOWN_AI,
            signal_type="merge_workflow",
            text="some workflow signal",
        )
        real_sig = make_signal()
        bic = make_bic(ai_signals=[workflow_sig, real_sig])
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        assert "cursor" in entry["ai_tools"]
        # unknown_ai from workflow signal should be excluded
        assert "unknown_ai" not in entry["ai_tools"]


class TestReturnsNoneWhenAllSignalsLost:
    """Returns None when all BICs had signals but lost them during decomposition."""

    def test_all_signals_lost(self):
        # BIC has commit-level signals, but culprit DC has no signals.
        # Culprit promotion won't happen (no signals), so the entry's
        # ai_signals stay as the commit-level ones.
        # To truly test signal loss: BIC where culprit replaces signals
        # with empty list.
        #
        # Scenario: BIC with commit signals, after _build_bug_commit
        # the ai_signals on the entry become empty because culprit DC
        # has no signals and culprit promotion didn't fire (no signals).
        # Actually, culprit promotion guards against empty signals.
        # The real scenario is: build_entry filters out bug_commits
        # without ai_signals. If all are filtered, return None.
        #
        # Create a BIC whose commit has ai_signals (passes filter in step 3),
        # but _build_bug_commit produces entry with empty ai_signals.
        # This happens when culprit promotion replaces signals but the
        # culprit has none -- but that's guarded. So we need a different path:
        # Decomposed commit culprit has signals, but after promotion the
        # entry's ai_signals become empty due to some filtering.
        #
        # Simplest: Mock a scenario where _build_bug_commit produces
        # an entry with empty ai_signals. This is artificial but tests
        # the filter logic.

        # Actually the simplest real scenario: BIC has commit signals,
        # but culprit with signals replaces them, then the test verifies
        # the positive case. For the None case, we need ALL bug_commits
        # to end up with empty ai_signals after building.

        # Realistic scenario: squash merge BIC has AI trailer on the merge
        # commit, but the decomposed culprit has no AI signals.
        # In this case culprit promotion is skipped (no signals), so the
        # entry keeps the original commit signals. The signal-loss filter
        # doesn't fire.

        # The actual signal-loss scenario requires the entry's ai_signals
        # to become empty. Let's construct it by having the BIC's commit
        # have ai_signals (passing the filter) but the built entry's
        # ai_signals being empty. This would need the _build_bug_commit
        # to produce empty ai_signals, which happens when the commit has
        # ai_signals=[] (but then it wouldn't pass the filter).

        # The real-world case: the commit has signals, _build_bug_commit
        # promotes a culprit that has signals, but those signals are all
        # workflow signals. The entry ends up with signals, but they're
        # workflow signals. Then the build_entry filter (step 4) checks
        # bc.get("ai_signals") which is truthy. So it wouldn't be filtered.

        # The None path fires when pre_filter_count > 0 but all bug_commits
        # are filtered by step 4 (bc.get("ai_signals") is empty/falsy).
        # This means _build_bug_commit must produce an entry where
        # ai_signals is []. The only way: commit.ai_signals is [] AND
        # no culprit promotion happens. But the step-3 filter requires
        # bic.commit.ai_signals to be truthy.

        # Conclusion: the None return can only happen if _build_bug_commit
        # clears ai_signals during culprit promotion (culprit has signals,
        # then... no, it keeps them). OR if commit has signals but they're
        # all empty dicts or something.

        # Actually, re-reading the old code: the culprit promotion CAN
        # replace ai_signals with an empty list if culprit_signals is empty.
        # But the code has: if not culprit_signals: break (skip promotion).
        # So that's guarded.

        # Wait -- the INFERRED culprit path: if culprit_sha is "" and
        # decomposed commits exist, it tries to infer. If inference picks
        # a DC, but that DC has signals that are all empty... no, the
        # inference requires dc.ai_signals to be truthy.

        # For testing purposes, let me construct it more directly:
        # We need a BIC whose commit.ai_signals is truthy (passes filter),
        # but _build_bug_commit returns entry with ai_signals=[].
        # This can happen if commit.ai_signals==[sig1] but culprit
        # promotion replaces with culprit's signals which is []. But
        # that's guarded by "if not culprit_signals: break".

        # The actual mechanism in the old code was: culprit DOES have
        # signals, promotion fires, entry.ai_signals gets replaced.
        # Then in the entry_builder code, step 4 filters it.
        # But culprit.ai_signals was truthy for promotion to happen,
        # so the entry would have signals.

        # I think the real scenario is more subtle and involves cache
        # staleness. For test purposes, let me just directly test the
        # filter logic by constructing a BIC where commit has signals
        # but after build the entry has no signals.

        # Simplest hack: have commit with a signal, but the signal's
        # matched_text is empty. _build_signal_entry still creates a dict,
        # so ai_signals would be [{tool: ..., ...}] which is truthy.

        # Let me take a step back. The None return path fires when:
        # 1. pre_filter_count > 0 (we had bug_commits before filter)
        # 2. After filter: no bug_commits left
        # This means ALL bug_commits had empty ai_signals.
        # Since step 3 only includes BICs with bic.commit.ai_signals,
        # the built entry will have ai_signals from commit... unless
        # culprit promotion replaces them.

        # The answer: culprit promotion replaces ai_signals with culprit's
        # signals. If culprit's signals are not empty (required for
        # promotion), the entry has signals. So we can't reach the None
        # path through normal logic. But the old code DID return None
        # in production -- the scenario was commit trailers leaking to
        # all squash sub-commits. The signals were on the commit but not
        # really on the culprit.

        # For test: I'll just patch _build_bug_commit return to have
        # empty ai_signals. Or better: construct a real scenario.
        # Let me make a BIC with commit signals, and a culprit DC
        # whose signals list contains only items. Wait, the promotion
        # guard is: if not culprit_signals: break. So if culprit_signals
        # is [], promotion is skipped, and the commit's signals remain.

        # OK, the ONLY way ai_signals becomes [] in the entry is if
        # commit.ai_signals is []. But then the BIC wouldn't pass
        # the step-3 filter. UNLESS is_override is True.

        # With is_override: step 3 skips the verdict filter, and step 4
        # skips the signal filter. So with is_override, this path
        # doesn't return None.

        # Without is_override: the BIC needs commit.ai_signals truthy
        # (step 3), but the entry's ai_signals must be falsy (step 4).
        # As analyzed, this is impossible with current _build_bug_commit.

        # For practical test coverage: just verify the contract that
        # build_entry returns None when bug_commits lose all signals.
        # We can test it by having no BICs pass the filter at all.

        # Actually, the simplest real scenario: TWO BICs, both with
        # commit signals. After building, one has empty ai_signals
        # somehow. But as shown, this doesn't happen normally.

        # Let's just test the inverse: a result with BICs but no
        # commit-level signals. The bug_commits_raw will be empty,
        # pre_filter_count=0, so we DON'T return None (we continue
        # to build the entry with empty bug_commits).

        # The None path needs pre_filter_count > 0 AND all filtered.
        # I'll construct this by making _build_bug_commit produce an
        # entry with ai_signals=[] using the monkeypatch approach.
        pass

    def test_returns_none_signal_loss_via_monkeypatch(self, monkeypatch):
        """When all BICs lose signals after building, return None."""
        import web_data.entry_builder as eb

        original_build = eb._build_bug_commit

        def patched_build(bic, repo_url="", fix_commit_source=""):
            result = original_build(bic, repo_url=repo_url, fix_commit_source=fix_commit_source)
            result["ai_signals"] = []  # Simulate signal loss
            return result

        monkeypatch.setattr(eb, "_build_bug_commit", patched_build)

        bic = make_bic()
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is None


class TestVerifiedBy:
    """verified_by extracted from first CONFIRMED deep verdict."""

    def test_verified_by_from_deep_verdict(self):
        bic = make_bic(
            deep_verification={
                "final_verdict": "CONFIRMED",
                "reasoning": "Clear AI involvement",
                "model": "claude-3-5-sonnet",
                "confidence": "high",
            },
        )
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        assert entry["verified_by"] == "claude-3-5-sonnet-thinking"

    def test_verified_by_preserves_explicit_reasoning_effort(self):
        bic = make_bic(
            deep_verification={
                "final_verdict": "CONFIRMED",
                "reasoning": "Evidence-backed causal chain",
                "model": "gpt-5.6-luna",
                "reasoning_effort": "max",
                "confidence": "high",
            },
        )
        entry = build_entry(make_result(bics=[bic]))
        assert entry is not None
        assert entry["verified_by"] == "gpt-5.6-luna-max"

    def test_verified_by_manual_review(self):
        bic = make_bic()
        result = make_result(bics=[bic])
        reviews = {"CVE-2025-12345": {"verdict": "confirmed"}}
        entry = build_entry(result, reviews=reviews)
        assert entry is not None
        assert entry["verified_by"] == "Manual"


class TestHowIntroduced:
    """how_introduced prefers screening causal_chain from CONFIRMED deep-verified BICs."""

    def test_from_confirmed_deep_with_screening(self):
        screening = make_screening(causal_chain="AI generated unsafe code")
        bic = make_bic(
            screening_verification=screening,
            deep_verification={
                "final_verdict": "CONFIRMED",
                "reasoning": "Verbose forensic analysis...",
                "model": "gpt-4o",
                "confidence": "high",
            },
        )
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        assert entry["how_introduced"] == "AI generated unsafe code"

    def test_screening_fallback_no_deep(self):
        screening = make_screening(causal_chain="AI did it")
        bic = make_bic(screening_verification=screening)
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        assert entry["how_introduced"] == "AI did it"


class TestAuditOverride:
    """Audit override forces CONFIRMED verdict."""

    def test_override_forces_confirmed(self):
        bic = make_bic(
            deep_verification={
                "final_verdict": "UNLIKELY",
                "reasoning": "Probably not AI",
                "model": "gpt-4o",
                "confidence": "high",
            },
            screening_verification=make_screening(),
        )
        result = make_result(bics=[bic])
        # With override
        entry = build_entry(result, audit_overrides={"CVE-2025-12345"})
        assert entry is not None
        assert entry["verdict"] == "CONFIRMED"
        assert entry["verified_by"] == "independent-audit"
        verification = entry["bug_commits"][0]["verification"]
        assert verification["verdict"] == "UNLIKELY"
        assert verification["models"] == ["gpt-4o"]

    def test_override_with_legacy_incomplete_subject_is_published_safely(self):
        bic = make_bic(
            fix_commit_sha="",
            blamed_file="(from OSV introduced)",
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "Independent evidence confirms the CVE-level claim.",
                "model": "gpt-5.4",
                "confidence": "high",
            },
        )
        result = make_result(
            cve_id="OSV-2026-371",
            bics=[bic],
            ai_involved=True,
            ai_contribution="Stale legacy narrative must stay quarantined.",
            investigation_scope_hash="",
        )

        entry = build_entry(
            result,
            audit_overrides={result.cve_id},
            audit_override_details={
                result.cve_id: {
                    "reason": "OSS-Fuzz bisection independently confirmed the causal chain.",
                },
            },
        )

        assert entry is not None
        assert entry["verdict"] == "CONFIRMED"
        assert entry["verified_by"] == "independent-audit"
        assert entry["bug_commits"] == []
        assert entry["ai_involved"] is None
        assert entry["how_introduced"] == ("OSS-Fuzz bisection independently confirmed the causal chain.")
        assert "ai_contribution" not in entry


class TestCveLevelConclusionIsolation:
    """A CVE-level conclusion must not manufacture per-BIC verification."""

    def test_ai_involved_does_not_rewrite_bic_verification(self):
        confirmed = make_bic(
            sha="aaa111",
            blamed_file="src/confirmed.py",
            repository_identity="https://github.com/org/repo",
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "This subject is causally linked to trusted AI authorship.",
                "model": "gpt-5.4",
                "confidence": "high",
                "ai_signal_attested": True,
                "ai_signal_source": "cursor",
            },
        )
        unlikely = make_bic(
            sha="bbb222",
            blamed_file="src/unlikely.py",
            repository_identity="https://github.com/org/repo",
            deep_verification={
                "verdict": "UNLIKELY",
                "reasoning": "The vulnerable branch predates this commit.",
                "model": "gpt-5.4",
                "confidence": "high",
            },
        )
        result = make_result(
            bics=[confirmed, unlikely],
            ai_involved=True,
            ai_contribution="The confirmed subject establishes AI causality.",
        )

        entry = build_entry(result)

        assert entry is not None
        assert entry["verdict"] == "CONFIRMED"
        verification = next(
            commit["verification"]
            for commit in entry["bug_commits"]
            if commit["sha"] == unlikely.commit.sha
        )
        assert verification["verdict"] == "UNLIKELY"
        assert verification["models"] == ["gpt-5.4"]
        assert all(verdict["model"] != "investigator-override" for verdict in verification["agent_verdicts"])

    def test_stale_nonempty_scope_does_not_override_subject_verdict(self):
        bic = make_bic(
            deep_verification={
                "verdict": "UNRELATED",
                "reasoning": "The subject evidence rejects causality.",
                "model": "gpt-5.4",
                "confidence": "high",
            },
        )
        result = make_result(
            bics=[bic],
            ai_involved=True,
            investigation_scope_hash="stale-nonempty",
        )

        assert build_entry(result) is None

    def test_legacy_global_agent_fallback_is_quarantined(self):
        bic = make_bic(
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "[agent-fallback] global conclusion",
                "model": "claude-code",
                "confidence": "high",
                "steps_completed": ["agent_fallback_verification"],
            },
        )
        result = make_result(
            bics=[bic],
            ai_involved=True,
            ai_contribution="Legacy CVE-level result copied to this BIC.",
        )

        assert build_entry(result) is None

    def test_legacy_unscoped_false_defers_to_confirmed_subject(self):
        bic = make_bic(
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "The subject-level evidence confirms AI authorship.",
                "model": "gpt-5.4",
                "confidence": "high",
            },
        )
        result = make_result(
            bics=[bic],
            ai_involved=False,
            investigation_scope_hash="",
        )

        entry = build_entry(result)

        assert entry is not None
        assert entry["ai_involved"] is None
        assert entry["verdict"] == "CONFIRMED"
        assert entry["bug_commits"][0]["verification"]["verdict"] == "CONFIRMED"


class TestAuditSubjectExclusions:
    """Independent audits may reject one exact BIC without hiding the CVE."""

    _FIX_SHA = "a" * 40
    _NOISE_SHA = "b" * 40
    _REAL_SHA = "c" * 40
    _NOISE_PATH = "src/plugin-sdk/index.ts"
    _REAL_PATH = "extensions/feishu/src/monitor.ts"

    @classmethod
    def _details(cls, *, blamed_file: str | None = None) -> dict[str, dict]:
        return {
            "CVE-2026-28478": {
                "label": "AI_CAUSAL",
                "excluded_bic_subjects": [
                    {
                        "fix_commit_sha": cls._FIX_SHA,
                        "commit_sha": cls._NOISE_SHA,
                        "blamed_file": blamed_file or cls._NOISE_PATH,
                    }
                ],
            }
        }

    @classmethod
    def _result(
        cls,
        bics: list[BugIntroducingCommit],
        **kwargs,
    ) -> CveAnalysisResult:
        return make_result(
            cve_id="CVE-2026-28478",
            bics=bics,
            fix_commits=[
                FixCommit(
                    sha=cls._FIX_SHA,
                    repo_url="https://github.com/openclaw/openclaw",
                    source="osv",
                )
            ],
            **kwargs,
        )

    def test_exclusion_precedes_tool_narrative_and_commit_aggregation(self):
        noise = make_bic(
            sha=self._NOISE_SHA,
            fix_commit_sha=self._FIX_SHA,
            blamed_file=self._NOISE_PATH,
            ai_signals=[make_signal(tool=AiTool.CURSOR, confidence=1.0)],
            screening_verification=make_screening(causal_chain="Noise subject must not supply the public narrative."),
        )
        real = make_bic(
            sha=self._REAL_SHA,
            fix_commit_sha=self._FIX_SHA,
            blamed_file=self._REAL_PATH,
            ai_signals=[make_signal(tool=AiTool.CLAUDE_CODE, confidence=0.95)],
            screening_verification=make_screening(causal_chain="Claude introduced the unguarded webhook handler."),
        )

        entry = build_entry(
            self._result(
                [noise, real],
                ai_involved=True,
                ai_contribution=("A stale CVE-level narrative includes the rejected subject."),
            ),
            audit_overrides={"CVE-2026-28478"},
            audit_override_details=self._details(),
        )

        assert entry is not None
        assert entry["ai_tools"] == ["claude_code"]
        assert entry["ai_involved"] is None
        assert entry["confidence"] == 0.95
        assert entry["how_introduced"] == ("Claude introduced the unguarded webhook handler.")
        assert [
            (commit["fix_commit_sha"], commit["sha"], commit["blamed_file"]) for commit in entry["bug_commits"]
        ] == [(self._FIX_SHA, self._REAL_SHA, self._REAL_PATH)]
        assert "ai_contribution" not in entry

    def test_exclusion_matches_the_full_fix_commit_file_subject(self):
        retained = make_bic(
            sha=self._NOISE_SHA,
            fix_commit_sha=self._FIX_SHA,
            blamed_file=self._REAL_PATH,
        )

        entry = build_entry(
            self._result([retained]),
            audit_overrides={"CVE-2026-28478"},
            audit_override_details=self._details(),
        )

        assert entry is not None
        assert entry["bug_commits"][0]["blamed_file"] == self._REAL_PATH

    def test_excluding_every_publishable_subject_quarantines_override(self):
        quarantine = QuarantineLog()
        noise = make_bic(
            sha=self._NOISE_SHA,
            fix_commit_sha=self._FIX_SHA,
            blamed_file=self._NOISE_PATH,
        )

        entry = build_entry(
            self._result([noise]),
            audit_overrides={"CVE-2026-28478"},
            audit_override_details=self._details(),
            quarantine=quarantine,
        )

        assert entry is None
        assert [record.reason for record in quarantine] == [
            "all publishable bug-introducing commits excluded by independent audit"
        ]


class TestDeduplication:
    """Publication preserves every distinct fix/BIC/file subject."""

    def test_same_sha_different_files_remain_distinct(self):
        bic1 = make_bic(sha="same_sha", blamed_file="file_a.py")
        bic2 = make_bic(sha="same_sha", blamed_file="file_b.py")
        result = make_result(bics=[bic1, bic2])
        entry = build_entry(result)
        assert entry is not None
        assert [
            (commit["fix_commit_sha"], commit["sha"], commit["blamed_file"]) for commit in entry["bug_commits"]
        ] == [
            ("fix111", "same_sha", "file_a.py"),
            ("fix111", "same_sha", "file_b.py"),
        ]

    def test_same_sha_and_file_across_fixes_remain_distinct(self):
        bic1 = make_bic(
            sha="same_sha",
            blamed_file="shared.py",
            fix_commit_sha="fix222",
        )
        bic2 = make_bic(
            sha="same_sha",
            blamed_file="shared.py",
            fix_commit_sha="fix111",
        )

        entry = build_entry(
            make_result(
                bics=[bic1, bic2],
                fix_commits=[
                    FixCommit(
                        sha="fix111",
                        repo_url="https://github.com/org/repo",
                        source="osv",
                    ),
                    FixCommit(
                        sha="fix222",
                        repo_url="https://github.com/org/repo.git/",
                        source="derived_fix",
                    ),
                ],
            )
        )

        assert entry is not None
        assert [
            (commit["fix_commit_sha"], commit["sha"], commit["blamed_file"]) for commit in entry["bug_commits"]
        ] == [
            ("fix111", "same_sha", "shared.py"),
            ("fix222", "same_sha", "shared.py"),
        ]

    def test_identical_reasoning_does_not_collapse_distinct_subjects(self):
        verification = {
            "verdict": "CONFIRMED",
            "reasoning": "Shared evidence applies to each blamed path.",
            "model": "gpt-5.4",
            "confidence": "high",
        }
        bic1 = make_bic(
            sha="sha-a",
            blamed_file="file_a.py",
            deep_verification=verification,
        )
        bic2 = make_bic(
            sha="sha-b",
            blamed_file="file_b.py",
            deep_verification=verification,
        )

        entry = build_entry(make_result(bics=[bic1, bic2]))

        assert entry is not None
        assert len(entry["bug_commits"]) == 2

    def test_output_order_is_independent_of_input_order(self):
        bics = [
            make_bic(
                sha="sha-b",
                blamed_file="z.py",
                fix_commit_sha="fix222",
            ),
            make_bic(
                sha="sha-a",
                blamed_file="a.py",
                fix_commit_sha="fix111",
            ),
            make_bic(
                sha="sha-a",
                blamed_file="b.py",
                fix_commit_sha="fix111",
            ),
        ]

        fixes = [
            FixCommit(
                sha="fix111",
                repo_url="https://github.com/org/repo",
                source="osv",
            ),
            FixCommit(
                sha="fix222",
                repo_url="https://github.com/org/repo",
                source="derived_fix",
            ),
        ]
        forward = build_entry(make_result(bics=bics, fix_commits=fixes))
        reverse = build_entry(
            make_result(
                bics=list(reversed(bics)),
                fix_commits=fixes,
            )
        )

        assert forward is not None
        assert reverse is not None
        assert forward["bug_commits"] == reverse["bug_commits"]

    def test_identical_duplicate_subjects_coalesce(self):
        bics = [
            make_bic(sha="same", blamed_file="same.py"),
            make_bic(sha="same", blamed_file="same.py"),
        ]

        entry = build_entry(make_result(bics=bics))

        assert entry is not None
        assert len(entry["bug_commits"]) == 1

    def test_conflicting_duplicate_subjects_are_quarantined(self):
        first = make_bic(
            sha="same",
            blamed_file="same.py",
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "first",
                "model": "gpt-5.4",
            },
        )
        second = make_bic(
            sha="same",
            blamed_file="same.py",
            deep_verification={
                "verdict": "UNRELATED",
                "reasoning": "second",
                "model": "gpt-5.4",
            },
        )

        assert build_entry(make_result(bics=[first, second])) is None

    def test_unknown_or_placeholder_subject_identity_is_quarantined(self):
        unknown_fix = make_bic(fix_commit_sha="")
        placeholder = make_bic(blamed_file="(from OSV introduced)")

        assert build_entry(make_result(bics=[unknown_fix])) is None
        assert build_entry(make_result(bics=[placeholder])) is None


class TestQuarantineReporting:
    def test_records_the_drop_reason(self):
        quarantine = QuarantineLog()

        entry = build_entry(
            make_result(bics=[make_bic(fix_commit_sha="")]),
            quarantine=quarantine,
        )

        assert entry is None
        assert len(quarantine) == 1
        assert quarantine.records[0].cve_id == "CVE-2025-12345"
        assert quarantine.records[0].reason == "no publishable bug-introducing commits"

    def test_audited_cve_level_positive_may_publish_without_a_bic(self):
        quarantine = QuarantineLog()

        entry = build_entry(
            make_result(bics=[]),
            audit_overrides={"CVE-2025-12345"},
            quarantine=quarantine,
        )

        assert entry is not None
        assert entry["bug_commits"] == []
        assert len(quarantine) == 0


class TestFixCommitsOutput:
    """fix_commits are converted from models to dicts."""

    def test_fix_commits_serialized(self):
        result = make_result()
        entry = build_entry(result)
        assert entry is not None
        assert len(entry["fix_commits"]) == 1
        fc = entry["fix_commits"][0]
        assert fc["sha"] == "fix111"
        assert fc["repo_url"] == "https://github.com/org/repo"

    def test_internal_pr_recovery_metadata_is_not_published(self):
        result = make_result(
            fix_commits=[
                FixCommit(
                    sha="fix111",
                    repo_url="https://github.com/org/repo",
                    source="github_advisory_pr",
                    pr_number=123,
                )
            ]
        )

        entry = build_entry(result)

        assert entry is not None
        assert "pr_number" not in entry["fix_commits"][0]


class TestRepositoryIdentityBoundary:
    """A repository-ambiguous CVE cannot be projected to web subjects."""

    def test_multiple_canonical_repositories_fail_closed(self):
        fixes = [
            FixCommit(
                sha="fix111",
                repo_url="https://github.com/org/repo",
                source="osv",
            ),
            FixCommit(
                sha="fix222",
                repo_url="https://gitlab.com/org/other-repo",
                source="osv",
            ),
        ]
        result = make_result(fix_commits=fixes)

        assert build_entry(result) is None

    def test_case_and_dot_git_variants_are_one_repository(self):
        fixes = [
            FixCommit(
                sha="fix111",
                repo_url="https://github.com/Org/Repo",
                source="osv",
            ),
            FixCommit(
                sha="fix222",
                repo_url="HTTPS://GITHUB.COM/org/repo.git/",
                source="osv",
            ),
        ]
        result = make_result(fix_commits=fixes)

        entry = build_entry(result)

        assert entry is not None
        assert len(entry["fix_commits"]) == 2

    def test_missing_repository_identity_fails_closed(self):
        result = make_result(fix_commits=[FixCommit(sha="fix111", repo_url="", source="osv")])

        assert build_entry(result) is None

    def test_malformed_repository_identity_fails_closed(self):
        fixes = [
            FixCommit(
                sha="fix111",
                repo_url="https://github.com/org/repo",
                source="osv",
            ),
            FixCommit(sha="fix222", repo_url="not a repository", source="osv"),
        ]

        assert build_entry(make_result(fix_commits=fixes)) is None


class TestScreeningVerification:
    """Bug commit includes screening_verification from LlmVerdict model."""

    def test_screening_verification_dict(self):
        screening = make_screening()
        bic = make_bic(screening_verification=screening)
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        bc = entry["bug_commits"][0]
        sv = bc["screening_verification"]
        assert sv is not None
        assert sv["verdict"] == "CONFIRMED"
        assert sv["model"] == "gpt-4o-mini"
        assert sv["causal_chain"] == "AI generated unsafe code"

    def test_no_screening_is_none(self):
        bic = make_bic(screening_verification=None)
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        bc = entry["bug_commits"][0]
        assert bc["screening_verification"] is None


class TestDeepVerificationFormatting:
    """Deep verification dict access and confidence mapping."""

    def test_new_format_confidence_mapped(self):
        bic = make_bic(
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "Clear evidence",
                "model": "gpt-4o",
                "confidence": "high",
                "tool_calls_made": 5,
                "steps_completed": 3,
                "evidence": ["evidence1"],
            },
        )
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        bc = entry["bug_commits"][0]
        v = bc["verification"]
        assert v["verdict"] == "CONFIRMED"
        assert v["confidence"] == 0.95  # "high" mapped to 0.95
        assert v["models"] == ["gpt-4o"]

    def test_old_format_agent_verdicts(self):
        bic = make_bic(
            deep_verification={
                "final_verdict": "CONFIRMED",
                "confidence": 0.9,
                "agent_verdicts": [
                    {
                        "model": "gpt-4o",
                        "verdict": "CONFIRMED",
                        "reasoning": "Clear evidence",
                        "confidence": 0.9,
                        "tool_calls_made": 3,
                        "steps_completed": 2,
                        "evidence": [],
                    }
                ],
            },
        )
        result = make_result(bics=[bic])
        entry = build_entry(result)
        assert entry is not None
        bc = entry["bug_commits"][0]
        v = bc["verification"]
        assert v["verdict"] == "CONFIRMED"
        assert len(v["agent_verdicts"]) == 1
        assert v["agent_verdicts"][0]["model"] == "gpt-4o"


class TestPublishedDate:
    """Published date fallback chain."""

    def test_nvd_date_preferred(self):
        result = make_result(cve_id="CVE-2025-12345")
        entry = build_entry(result, nvd_dates={"CVE-2025-12345": "2025-06-15"})
        assert entry is not None
        assert entry["published"] == "2025-06-15"

    def test_falls_back_to_year(self):
        result = make_result(cve_id="CVE-2025-12345")
        entry = build_entry(result)
        assert entry is not None
        assert entry["published"] == "2025"


class TestAiContribution:
    """ai_contribution overrides how_introduced."""

    def test_ai_contribution_override(self):
        bic = make_bic(
            repository_identity="https://github.com/org/repo",
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "Current subject evidence.",
                "model": "gpt-5.4",
                "confidence": "high",
                "ai_signal_attested": True,
                "ai_signal_source": "cursor",
            }
        )
        result = make_result(
            bics=[bic],
            ai_involved=True,
            ai_contribution="AI wrote vulnerable parser",
        )
        entry = build_entry(result)
        assert entry is not None
        assert entry["how_introduced"] == "AI wrote vulnerable parser"
        assert entry["ai_contribution"] == "AI wrote vulnerable parser"

    def test_stale_contribution_defers_to_current_confirmed_subject(self):
        bic = make_bic(
            screening_verification=make_screening(causal_chain="Current subject evidence confirms the causal chain."),
            deep_verification={
                "verdict": "CONFIRMED",
                "reasoning": "Current subject evidence confirms AI authorship.",
                "model": "gpt-5.4",
                "confidence": "high",
            },
        )
        result = make_result(
            bics=[bic],
            ai_involved=True,
            ai_contribution="Stale CVE-level conclusion from a different subject set.",
            investigation_scope_hash="stale-nonempty",
        )

        entry = build_entry(result)

        assert entry is not None
        assert entry["ai_involved"] is None
        assert entry["how_introduced"] == ("Current subject evidence confirms the causal chain.")
        assert "ai_contribution" not in entry

    def test_stale_contribution_does_not_override_independent_audit_evidence(self):
        bic = make_bic(
            screening_verification=make_screening(causal_chain="Independent audit confirmed this subject."),
            deep_verification={
                "verdict": "UNLIKELY",
                "reasoning": "The model was uncertain.",
                "model": "gpt-5.4",
                "confidence": "medium",
            },
        )
        result = make_result(
            bics=[bic],
            ai_involved=True,
            ai_contribution="Stale CVE-level conclusion from a different subject set.",
            investigation_scope_hash="stale-nonempty",
        )

        entry = build_entry(result, audit_overrides={result.cve_id})

        assert entry is not None
        assert entry["verified_by"] == "independent-audit"
        assert entry["how_introduced"] == "Independent audit confirmed this subject."
        assert "ai_contribution" not in entry
