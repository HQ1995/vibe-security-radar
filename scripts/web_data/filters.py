"""Inclusion filters: which CVE results appear on the website."""

from __future__ import annotations

from cve_analyzer.models import CveAnalysisResult


def is_fallback_verdict(dv: dict) -> bool:
    """Return True if the deep verdict is a timeout/error fallback, not real analysis.

    Fallback verdicts are generated when the deep verifier exhausts its tool-call
    budget or encounters an error.  They should not be trusted as genuine verdicts.
    Detected via:
    - ``is_fallback`` flag (new format, set by agent_loop.py)
    - Reasoning containing "Fallback verdict" with empty evidence (legacy format)
    """
    if dv.get("is_fallback"):
        return True
    reasoning = dv.get("reasoning", "")
    evidence = dv.get("evidence", None)
    if "Fallback verdict" in reasoning and (not evidence or len(evidence) == 0):
        return True
    return False


def should_include(
    result: CveAnalysisResult,
    audit_overrides: set[str] | None = None,
) -> bool:
    """Determine if a CVE result should appear on the website.

    Evaluation order:
    1. Exclude if result.error is set.
    2. Exclude rejected/withdrawn CVEs (description contains rejection marker).
    3. Include if CVE ID is in audit_overrides (independently verified true positive).
    4. Include if result.ai_involved is True (authoritative CVE-level verdict).
    5. Exclude if result.ai_involved is False (authoritative CVE-level verdict).
    6. Fallback per-BIC logic:
       - Skip BICs with no effective signals and no screening_verification.
       - If deep_verification exists and is NOT a fallback:
           CONFIRMED → include.
           Other verdicts → skip this BIC (UNLIKELY/UNRELATED excluded).
       - No deep verification or fallback → benefit of the doubt (has_passing = True).
    7. Return has_passing.
    """
    included, reason = _should_include_with_reason(result, audit_overrides)
    if result.filtering_log is not None:
        result.filtering_log.final_included = included
        result.filtering_log.exclusion_reason = reason
    return included


def _should_include_with_reason(
    result: CveAnalysisResult,
    audit_overrides: set[str] | None = None,
) -> tuple[bool, str]:
    """Core inclusion logic returning (included, exclusion_reason)."""
    if result.error:
        return False, "error"

    desc = (result.description or "").lower()
    if "rejected reason:" in desc or "this cve id has been rejected" in desc:
        return False, "rejected_cve"

    if audit_overrides and result.cve_id in audit_overrides:
        return True, ""

    if result.ai_involved is True:
        return True, ""
    if result.ai_involved is False:
        return False, "ai_not_involved"

    # Fallback: per-BIC verdict logic
    has_passing = False
    for bic in result.bug_introducing_commits:
        has_signals = bool(bic.effective_signals())
        has_screening = bic.screening_verification is not None
        if not has_signals and not has_screening:
            continue

        dv = bic.deep_verification
        if dv and not is_fallback_verdict(dv):
            verdict = (dv.get("final_verdict") or dv.get("verdict") or "").upper()
            if verdict == "CONFIRMED":
                return True, ""
            # UNLIKELY or UNRELATED — skip this BIC
            continue

        # No deep verification or fallback verdict → benefit of the doubt
        has_passing = True

    if has_passing:
        return True, ""
    return False, "no_confirmed_verdict"
