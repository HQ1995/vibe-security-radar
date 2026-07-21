"""Inclusion filters: which CVE results appear on the website."""

from __future__ import annotations

from cve_analyzer.models import CveAnalysisResult, investigation_scope_is_current


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
    audit_exclusions: set[str] | None = None,
) -> bool:
    """Determine if a CVE result should appear on the website.

    Evaluation order:
    1. Exclude if result.error is set.
    2. Exclude rejected/withdrawn CVEs (description contains rejection marker).
    3. Include if CVE ID is in audit_overrides (independently verified true positive).
    4. Honor result.ai_involved only when investigation_scope_hash proves that
       the CVE-level verdict covers the current subject set.
    5. Per-BIC fallback includes only a non-fallback CONFIRMED verdict whose
       effective signal set contains trusted authorship evidence.
    6. Screening, workflow-only signals, and unverified candidates remain
       diagnostics for the detector inventory.
    """
    included, reason = _should_include_with_reason(
        result,
        audit_overrides,
        audit_exclusions,
    )
    if result.filtering_log is not None:
        result.filtering_log.final_included = included
        result.filtering_log.exclusion_reason = reason
    return included


def _should_include_with_reason(
    result: CveAnalysisResult,
    audit_overrides: set[str] | None = None,
    audit_exclusions: set[str] | None = None,
) -> tuple[bool, str]:
    """Core inclusion logic returning (included, exclusion_reason)."""
    if result.error:
        return False, "error"

    desc = (result.description or "").lower()
    if "rejected reason:" in desc or "this cve id has been rejected" in desc:
        return False, "rejected_cve"

    if audit_exclusions and result.cve_id in audit_exclusions:
        return False, "audit_not_ai"

    if audit_overrides and result.cve_id in audit_overrides:
        return True, ""

    # A recorded negative is always safe to exclude.  A recorded positive is
    # promotable only when its scope hash covers the current repo/BIC set.
    if result.ai_involved is False:
        return False, "ai_not_involved"
    if investigation_scope_is_current(result) and result.ai_involved is True:
        return True, ""

    # Per-BIC fallback remains strict: screening is diagnostic, and a positive
    # needs both causal confirmation and an authorship-bearing signal.
    for bic in result.bug_introducing_commits:
        has_signals = bool(bic.all_ai_signals())
        has_screening = bic.screening_verification is not None
        if not has_signals and not has_screening:
            continue

        dv = bic.deep_verification
        if dv and not is_fallback_verdict(dv):
            verdict = (dv.get("final_verdict") or dv.get("verdict") or "").upper()
            source = str(dv.get("ai_signal_source") or "")
            if verdict == "CONFIRMED" and bic.has_authorship_attestation(source):
                return True, ""
            continue
    return False, "no_confirmed_verdict"
