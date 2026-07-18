"""Build web-format CVE entries from CveAnalysisResult models.

Replaces the old dict-based ``build_cve_entry()`` and ``_build_bug_commit()``
from ``generate_web_data.py`` with a model-based implementation that
operates directly on typed dataclass instances.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from cve_analyzer.git_url import parse_repo_url
from cve_analyzer.models import (
    AiSignal,
    BugIntroducingCommit,
    CveAnalysisResult,
    WORKFLOW_SIGNAL_TYPES,
    investigation_scope_is_current,
    is_legacy_unscoped_verification,
)
from cve_analyzer.scoring import compute_ai_confidence

from web_data.constants import CONFIDENCE_STR_TO_NUMERIC, STRONG_SIGNAL_TYPES
from web_data.filters import is_fallback_verdict
from web_data.languages import determine_languages
from web_data.loader import normalize_published
from web_data.severity import extract_cvss_score, parse_severity

# ---------------------------------------------------------------------------
# Cache directory for PR lookup
# ---------------------------------------------------------------------------

DEFAULT_API_RESPONSES_DIR = os.path.expanduser("~/.cache/cve-analyzer/api-responses")


# ---------------------------------------------------------------------------
# Quarantine log — records which CVEs were dropped by build_entry() and why
# ---------------------------------------------------------------------------

@dataclass
class QuarantineRecord:
    """One quarantined CVE: its id and the reason it was dropped."""
    cve_id: str
    reason: str


@dataclass
class QuarantineLog:
    """Collects QuarantineRecords across build_entry() calls for reporting."""
    records: list[QuarantineRecord] = field(default_factory=list)

    def add(self, cve_id: str, reason: str) -> None:
        """Record that ``cve_id`` was quarantined for ``reason``."""
        self.records.append(QuarantineRecord(cve_id, reason))

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self):
        return iter(self.records)


def _quarantine_drop(
    quarantine: QuarantineLog | None,
    cve_id: str,
    reason: str,
) -> None:
    """Record ``reason`` in ``quarantine`` (if given) and return None."""
    if quarantine is not None:
        quarantine.add(cve_id, reason)
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _first_line(message: str) -> str:
    """Return only the first non-empty line of a commit message."""
    if not message:
        return ""
    return message.split("\n")[0].strip()


def _build_signal_entry(sig: AiSignal) -> dict:
    """Convert an AiSignal model to a compact display dict."""
    return {
        "tool": sig.tool.value,
        "signal_type": sig.signal_type,
        "matched_text": sig.matched_text,
        "confidence": sig.confidence,
    }


def _parse_github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL, or None if unparseable."""
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/*$",
        repo_url.rstrip("/"),
    )
    return (m.group(1), m.group(2)) if m else None


def _canonical_repository_identity(repo_url: str) -> tuple[str, str, str] | None:
    """Return a case-insensitive canonical identity for a supported repo URL."""
    parsed = parse_repo_url((repo_url or "").strip().lower())
    if parsed is None:
        return None
    return tuple(part.lower() for part in parsed)


def _lookup_pr_for_commit(
    repo_url: str,
    sha: str,
    api_responses_dir: str = DEFAULT_API_RESPONSES_DIR,
) -> tuple[str, str]:
    """Look up PR URL and title for a commit from the gh_commit_prs cache.

    Returns (pr_url, pr_title) or ("", "") if not found.
    """
    parts = _parse_github_owner_repo(repo_url)
    if not parts or not sha or not re.fullmatch(r"[0-9a-fA-F]{4,64}", sha):
        return ("", "")
    owner, repo = parts
    cache_path = os.path.join(
        api_responses_dir, "gh_commit_prs", owner, repo, "commits", sha, "pulls.json",
    )
    try:
        with open(cache_path, encoding="utf-8") as fh:
            prs = json.load(fh)
        if prs and isinstance(prs, list):
            pr = prs[0]
            return (pr.get("html_url", ""), pr.get("title", ""))
    except (json.JSONDecodeError, OSError):
        pass
    return ("", "")


def _extract_published_year(result: CveAnalysisResult) -> str:
    """Extract the publication year from the CVE ID (CVE-YYYY-NNNNN)."""
    cve_id = result.cve_id or ""
    if cve_id.startswith("CVE-"):
        parts = cve_id.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            return parts[1]
    return ""


def _numeric_confidence(value: object) -> float | None:
    """Coerce a verifier confidence to a number, or None if not numeric.

    Legacy caches may carry strings ("high") or nothing; the web contract is
    ``number | null``.
    """
    mapped = CONFIDENCE_STR_TO_NUMERIC.get(str(value).lower(), value)
    if isinstance(mapped, bool):
        return None
    return float(mapped) if isinstance(mapped, (int, float)) else None


def _as_count(value: object) -> int:
    """Coerce a verifier counter to int (legacy caches store step lists)."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return len(value)
    return 0


def _model_with_reasoning_tag(model: str) -> str:
    """Append a reasoning-mode suffix to the model name.

    Historical ``claude-code`` records already identify their execution mode,
    so they retain their existing label.
    """
    m = model.lower()
    if m in ("claude-code", "claude"):
        return "claude-code"
    if "claude" in m:
        return f"{model}-thinking"
    if "gemini" in m:
        return f"{model}-thinking"
    return f"{model}-high"


def _get_deep_verdict(bic: BugIntroducingCommit) -> dict | None:
    """Return the best deep-verification verdict dict for a BIC.

    Prefers deep_verification (new single-model verifier) over
    tribunal_verdict (old 3-model voting).  Normalises ``final_verdict``
    key.  Ignores timeout/error fallback verdicts.
    """
    vv = bic.deep_verification
    if vv:
        if is_fallback_verdict(vv) or is_legacy_unscoped_verification(vv):
            return None
        if "final_verdict" not in vv and "verdict" in vv:
            return {**vv, "final_verdict": vv["verdict"]}
        return vv
    return bic.tribunal_verdict


def _effective_verdict(bic: BugIntroducingCommit) -> str:
    """Return the best available verdict string for a BIC (upper-cased).

    Prefers deep verification over screening.
    """
    dv = _get_deep_verdict(bic)
    if dv and dv.get("final_verdict"):
        return dv["final_verdict"].upper()
    sv = bic.screening_verification
    if sv and sv.verdict:
        return sv.verdict.value.upper()
    return ""


# ---------------------------------------------------------------------------
# _build_bug_commit
# ---------------------------------------------------------------------------

def _build_bug_commit(
    bic: BugIntroducingCommit,
    repo_url: str = "",
    fix_commit_source: str = "",
) -> dict:
    """Transform a BIC model into a web-format bug commit dict."""
    commit = bic.commit
    sv = bic.screening_verification
    dv = _get_deep_verdict(bic)

    entry: dict = {
        "sha": commit.sha,
        "author": commit.author_name,
        "date": commit.authored_date,
        "message": _first_line(commit.message),
        "ai_signals": [_build_signal_entry(sig) for sig in (bic.effective_signals() or bic.all_ai_signals() or commit.ai_signals)],
        "blamed_file": bic.blamed_file or "",
        "blame_confidence": bic.blame_confidence,
    }

    if fix_commit_source:
        entry["fix_commit_source"] = fix_commit_source
    if bic.blame_strategy:
        entry["blame_strategy"] = str(bic.blame_strategy)
    if bic.fix_commit_sha:
        entry["fix_commit_sha"] = bic.fix_commit_sha

    # Screening verification (LlmVerdict model — attribute access)
    if sv:
        entry["screening_verification"] = {
            "verdict": sv.verdict.value if sv.verdict else "",
            "reasoning": sv.reasoning,
            "model": sv.model,
            "vuln_type": sv.vuln_type,
            "vuln_description": sv.vuln_description,
            "vulnerable_pattern": sv.vulnerable_pattern,
            "causal_chain": sv.causal_chain,
        }
    else:
        entry["screening_verification"] = None

    # PR URL lookup
    pr_url, pr_title = _lookup_pr_for_commit(repo_url, commit.sha)
    if pr_url:
        entry["pr_url"] = pr_url
        entry["pr_title"] = pr_title

    # Deep verification (raw dict — .get() access)
    if dv:
        if dv.get("agent_verdicts"):
            # Old format: multi-model with agent_verdicts list
            entry["verification"] = {
                "verdict": dv.get("final_verdict", ""),
                "confidence": _numeric_confidence(dv.get("confidence", "")),
                "models": [
                    av.get("model", "") for av in dv.get("agent_verdicts", [])
                ],
                "agent_verdicts": [
                    {
                        "model": av.get("model", ""),
                        "verdict": av.get("verdict", ""),
                        "reasoning": av.get("reasoning", ""),
                        "confidence": _numeric_confidence(av.get("confidence", 0)) or 0.0,
                        "tool_calls_made": _as_count(av.get("tool_calls_made", 0)),
                        "steps_completed": _as_count(av.get("steps_completed", 0)),
                        "evidence": av.get("evidence", []),
                    }
                    for av in dv["agent_verdicts"]
                ],
            }
        else:
            # New verifier format: single-model flat structure.
            numeric_conf = _numeric_confidence(dv.get("confidence", ""))
            entry["verification"] = {
                "verdict": dv.get("final_verdict", ""),
                "confidence": numeric_conf,
                "models": [dv["model"]] if dv.get("model") else [],
                "agent_verdicts": [
                    {
                        "model": dv.get("model", ""),
                        "verdict": dv.get("final_verdict", ""),
                        "reasoning": dv.get("reasoning", ""),
                        "confidence": numeric_conf or 0.0,
                        "tool_calls_made": _as_count(dv.get("tool_calls_made", 0)),
                        "steps_completed": _as_count(dv.get("steps_completed", 0)),
                        "evidence": dv.get("evidence", []),
                    }
                ],
            }

    # Decomposed sub-commits from squash merge PRs
    if bic.decomposed_commits:
        entry["decomposed_commits"] = [
            {
                "sha": dc.sha,
                "author_name": dc.author_name,
                "message": _first_line(dc.message),
                "ai_signals": [_build_signal_entry(sig) for sig in dc.ai_signals],
                "touched_blamed_file": dc.touched_blamed_file,
            }
            for dc in bic.decomposed_commits
        ]

    # Culprit SHA promotion
    culprit_sha = bic.culprit_sha
    decomposed = bic.decomposed_commits
    if not culprit_sha and decomposed:
        touched = [
            dc for dc in decomposed
            if dc.ai_signals and dc.touched_blamed_file is True
        ]
        if len(touched) == 1:
            culprit_sha = touched[0].sha
        elif len(touched) > 1:
            best = max(
                touched,
                key=lambda dc: max(
                    (s.confidence for s in dc.ai_signals), default=0,
                ),
            )
            culprit_sha = best.sha

    if culprit_sha and decomposed:
        for dc in decomposed:
            if dc.sha == culprit_sha:
                culprit_signals = dc.ai_signals
                if not culprit_signals:
                    break
                entry["squash_merge_sha"] = entry["sha"]
                entry["sha"] = culprit_sha
                entry["author"] = dc.author_name or entry["author"]
                entry["message"] = _first_line(dc.message)
                entry["ai_signals"] = [
                    _build_signal_entry(s) for s in culprit_signals
                ]
                break

    return entry


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_entry(
    result: CveAnalysisResult,
    nvd_dates: dict[str, str] | None = None,
    ghsa_severities: dict[str, str] | None = None,
    reviews: dict[str, dict] | None = None,
    audit_overrides: set[str] | None = None,
    quarantine: QuarantineLog | None = None,
) -> dict | None:
    """Transform a CveAnalysisResult into a web-friendly CVE entry.

    Returns None when the entry cannot be published faithfully (ambiguous
    repository projection, conflicting evidence, or all AI signals lost
    during squash decomposition).  Each drop is recorded in ``quarantine``
    (when given) with the CVE id and a human-readable reason.
    """
    cve_id = result.cve_id
    is_override = cve_id in (audit_overrides or set())
    trusted_ai_involved = (
        result.ai_involved if investigation_scope_is_current(result) else None
    )

    # BIC subjects do not yet carry repository identity.  Publishing a CVE
    # with fixes from multiple repositories would therefore attach every BIC
    # to an arbitrary repository.  Quarantine that ambiguous projection.
    repository_identities: set[tuple[str, str, str]] = set()
    for fix in result.fix_commits:
        identity = _canonical_repository_identity(fix.repo_url)
        if identity is None:
            return _quarantine_drop(
                quarantine, cve_id,
                f"unparseable fix commit repo URL: {fix.repo_url!r}",
            )
        repository_identities.add(identity)
    if len(repository_identities) != 1:
        return _quarantine_drop(
            quarantine, cve_id,
            f"fix commits span {len(repository_identities)} repositories",
        )

    known_fix_shas = {fix.sha for fix in result.fix_commits if fix.sha}
    publishable_bics = [
        bic
        for bic in result.bug_introducing_commits
        if bic.fix_commit_sha in known_fix_shas
        and bool(bic.blamed_file)
        and not bic.blamed_file.startswith("(")
    ]
    if not publishable_bics:
        return _quarantine_drop(
            quarantine, cve_id, "no publishable bug-introducing commits",
        )

    unique_bics: dict[tuple[str, str, str], BugIntroducingCommit] = {}
    for bic in publishable_bics:
        subject = (bic.fix_commit_sha, bic.commit.sha, bic.blamed_file)
        existing = unique_bics.get(subject)
        if existing is not None and json.dumps(
            existing.to_dict(), sort_keys=True, ensure_ascii=False,
        ) != json.dumps(bic.to_dict(), sort_keys=True, ensure_ascii=False):
            return _quarantine_drop(
                quarantine, cve_id,
                f"conflicting BIC evidence for subject {subject}",
            )
        unique_bics[subject] = bic
    publishable_bics = [unique_bics[key] for key in sorted(unique_bics)]

    has_legacy_unscoped = any(
        is_legacy_unscoped_verification(bic.deep_verification)
        for bic in publishable_bics
    )
    has_scoped_confirmation = any(
        (verdict := _get_deep_verdict(bic))
        and (verdict.get("final_verdict") or "").upper() == "CONFIRMED"
        for bic in publishable_bics
    )
    if has_legacy_unscoped and not (has_scoped_confirmation or is_override):
        return _quarantine_drop(
            quarantine, cve_id,
            "legacy unscoped verification without scoped confirmation",
        )

    # ------------------------------------------------------------------
    # 1. AI tools extraction
    # ------------------------------------------------------------------
    ai_tools_set: set[str] = set()
    has_commit_signal = False
    has_pr_body_signal = False

    for bic in publishable_bics:
        signals = bic.effective_signals()
        if not signals:
            continue
        verdict = _effective_verdict(bic)
        if verdict == "UNRELATED":
            continue
        for sig in signals:
            if sig.signal_type in WORKFLOW_SIGNAL_TYPES:
                continue
            tool_name = sig.tool.value
            if not tool_name:
                continue
            # unknown_ai from weak signal types is too noisy
            if tool_name == "unknown_ai" and sig.signal_type not in STRONG_SIGNAL_TYPES:
                continue
            ai_tools_set.add(tool_name)
            if sig.origin == "pr_body":
                has_pr_body_signal = True
            else:
                has_commit_signal = True

    ai_tools = sorted(ai_tools_set)

    if has_commit_signal and has_pr_body_signal:
        signal_source = "both"
    elif has_pr_body_signal:
        signal_source = "pr_body"
    else:
        signal_source = "commit"

    # ------------------------------------------------------------------
    # 2. ai_involved fallback — infer potential tool from ALL BICs
    # ------------------------------------------------------------------
    signal_note = ""
    if trusted_ai_involved is True and not ai_tools:
        # Scan ALL signals across all BICs — effective_signals, commit signals,
        # decomposed sub-commit signals (even touched=False), and PR signals.
        # This catches tools like roo_code/copilot on non-culprit sub-commits
        # that effective_signals() filters out.
        best_tool = ""
        best_confidence = 0.0
        best_sha = ""
        best_sig_type = ""
        best_verdict = ""
        best_source = ""  # "commit", "sub-commit", "pr_body"
        for bic in publishable_bics:
            verdict = _effective_verdict(bic)
            # Collect (signal, source_description) pairs from every source
            sig_sources: list[tuple] = []
            for sig in bic.commit.ai_signals:
                sig_sources.append((sig, bic.commit.sha[:12], "commit", verdict))
            for dc in bic.decomposed_commits:
                for sig in dc.ai_signals:
                    sig_sources.append((sig, dc.sha[:12], "sub-commit", verdict))
            for sig in bic.pr_signals:
                sig_sources.append((sig, bic.commit.sha[:12], "pr_body", verdict))
            for sig, sha, source, v in sig_sources:
                if sig.signal_type in WORKFLOW_SIGNAL_TYPES:
                    continue
                if sig.tool.value == "unknown_ai":
                    continue
                if sig.confidence > best_confidence:
                    best_tool = sig.tool.value
                    best_confidence = sig.confidence
                    best_sha = sha
                    best_sig_type = sig.signal_type
                    best_verdict = v
                    best_source = source
        if best_tool:
            ai_tools = [best_tool]
            # Build detailed explanation
            where = f"{best_sig_type} signal on {best_source} {best_sha}"
            if best_verdict == "UNRELATED":
                why = "that commit was ruled unrelated to the vulnerability"
            elif best_source == "sub-commit":
                why = "that sub-commit did not modify the vulnerable file"
            else:
                why = "no direct link to the vulnerability-introducing code"
            signal_note = (
                f"Detected {best_tool} ({where}), but {why}. "
                f"Tool inferred from the same PR — see ai_contribution for the investigator's causal analysis."
            )
        else:
            ai_tools = ["ai_assisted"]
            signal_note = (
                "AI involvement confirmed by investigator but no tool-specific commit signal detected. "
                "See ai_contribution for the investigator's causal analysis."
            )

    # ------------------------------------------------------------------
    # 3. Bug commits list
    # ------------------------------------------------------------------
    fix_repo_url = ""
    if repository_identities:
        host, owner, repo = next(iter(repository_identities))
        fix_repo_url = f"https://{host}/{owner}/{repo}"

    fix_source_by_sha: dict[str, str] = {}
    for fc in result.fix_commits:
        if fc.sha:
            fix_source_by_sha[fc.sha] = fc.source

    bug_commits_raw = [
        _build_bug_commit(
            bic,
            repo_url=fix_repo_url,
            fix_commit_source=fix_source_by_sha.get(bic.fix_commit_sha, ""),
        )
        for bic in publishable_bics
        if (bic.effective_signals() or bic.all_ai_signals() or bic.commit.ai_signals)
        and (is_override or trusted_ai_involved is True or _effective_verdict(bic) not in ("UNRELATED", "UNLIKELY"))
    ]

    # Preserve every fix/BIC/file subject. Legacy caches may still contain
    # exact duplicates. Identical projections coalesce; conflicting evidence
    # for one subject quarantines the CVE instead of selecting first-wins.
    commits_by_subject: dict[tuple[str, str, str], dict] = {}
    for commit in bug_commits_raw:
        subject = (
            commit.get("fix_commit_sha", ""),
            commit["sha"],
            commit.get("blamed_file", ""),
        )
        existing = commits_by_subject.get(subject)
        if existing is not None and json.dumps(
            existing, sort_keys=True, ensure_ascii=False,
        ) != json.dumps(commit, sort_keys=True, ensure_ascii=False):
            return _quarantine_drop(
                quarantine, cve_id,
                f"conflicting commit projections for subject {subject}",
            )
        commits_by_subject[subject] = commit

    bug_commits = sorted(
        commits_by_subject.values(),
        key=lambda commit: (
            commit.get("fix_commit_sha", ""),
            commit["sha"],
            commit.get("blamed_file", ""),
        ),
    )

    # ------------------------------------------------------------------
    # 4. Filter lost signals (skip when ai_involved=True — investigator
    #    confirmed AI involvement at CVE level, keep BICs for display)
    # ------------------------------------------------------------------
    pre_filter_count = len(bug_commits)
    if not is_override and trusted_ai_involved is not True:
        bug_commits = [bc for bc in bug_commits if bc.get("ai_signals")]
    if pre_filter_count > 0 and not bug_commits:
        return _quarantine_drop(
            quarantine, cve_id,
            "all AI signals lost after filtering (squash decomposition pollution)",
        )
    if not bug_commits and trusted_ai_involved is not True and not is_override:
        return _quarantine_drop(
            quarantine, cve_id, "no displayable bug commits",
        )

    # ------------------------------------------------------------------
    # 8. Severity
    # ------------------------------------------------------------------
    # Extract vuln_type early for severity inference
    first_vuln_type = ""
    for bic in publishable_bics:
        sv = bic.screening_verification
        if sv and sv.verdict.value == "CONFIRMED":
            first_vuln_type = sv.vuln_type
            if first_vuln_type:
                break

    ghsa_sev = (ghsa_severities or {}).get(cve_id, "")
    severity = parse_severity(
        result.severity,
        cvss_score=result.cvss_score,
        ghsa_severity=ghsa_sev,
        description=result.description,
        vuln_type=first_vuln_type,
    )
    cvss = extract_cvss_score(result.severity, pre_score=result.cvss_score)

    # ------------------------------------------------------------------
    # Published date — contract: "YYYY-MM-DD", "YYYY" (year-only), or ""
    # ------------------------------------------------------------------
    published = ""
    if nvd_dates and cve_id in nvd_dates:
        published = normalize_published(nvd_dates[cve_id])
    if not published:
        published = _extract_published_year(result)

    # ------------------------------------------------------------------
    # 9. verified_by
    # ------------------------------------------------------------------
    verified_by = ""
    review = reviews.get(cve_id) if reviews else None
    if review and review.get("verdict") in ("confirmed", "uncertain"):
        verified_by = "Manual"
    else:
        for bic in publishable_bics:
            dv = _get_deep_verdict(bic)
            if dv and (dv.get("final_verdict") or "").upper() == "CONFIRMED":
                if dv.get("model"):
                    verified_by = _model_with_reasoning_tag(dv["model"])
                break

    # ------------------------------------------------------------------
    # 10. how_introduced / root_cause / vuln_type / vulnerable_pattern
    # ------------------------------------------------------------------
    how_introduced = ""
    root_cause = ""
    vuln_type = ""
    vulnerable_pattern = ""
    screening_fallback = ""
    screening_root_cause = ""
    screening_vuln_type = ""
    screening_vulnerable_pattern = ""

    for bic in publishable_bics:
        dv = _get_deep_verdict(bic)
        dv_verdict = ""
        if dv:
            dv_verdict = (dv.get("final_verdict") or dv.get("verdict") or "").upper()

        # Best source: deep verify CONFIRMED
        if dv_verdict == "CONFIRMED":
            sv = bic.screening_verification
            if sv and sv.verdict.value == "CONFIRMED":
                how_introduced = sv.causal_chain or dv.get("reasoning", "")
                root_cause = sv.vuln_description
                vuln_type = sv.vuln_type
                vulnerable_pattern = sv.vulnerable_pattern
            else:
                how_introduced = dv.get("reasoning", "")
                for av in dv.get("agent_verdicts", []):
                    if av.get("verdict") == "CONFIRMED" and av.get("reasoning"):
                        how_introduced = av["reasoning"]
                        break
            if how_introduced:
                break

        # Screening CONFIRMED, only when no deep verify exists for this BIC
        sv = bic.screening_verification
        if sv and sv.verdict.value == "CONFIRMED" and not dv_verdict:
            candidate = sv.causal_chain
            if candidate and not screening_fallback:
                screening_fallback = candidate
                screening_root_cause = sv.vuln_description
                screening_vuln_type = sv.vuln_type
                screening_vulnerable_pattern = sv.vulnerable_pattern

    if not how_introduced and screening_fallback:
        how_introduced = screening_fallback
        root_cause = screening_root_cause
        vuln_type = screening_vuln_type
        vulnerable_pattern = screening_vulnerable_pattern

    # ------------------------------------------------------------------
    # Best verdict across all BICs (ai_involved=True overrides per-BIC)
    # ------------------------------------------------------------------
    best_verdict = ""
    if trusted_ai_involved is True:
        best_verdict = "CONFIRMED"
    else:
        for bic in publishable_bics:
            v = _effective_verdict(bic)
            if v == "CONFIRMED":
                best_verdict = "CONFIRMED"
                break
            if v == "UNLIKELY" and best_verdict != "CONFIRMED":
                best_verdict = "UNLIKELY"

    # ------------------------------------------------------------------
    # 11. Audit override
    # ------------------------------------------------------------------
    if is_override and best_verdict != "CONFIRMED":
        best_verdict = "CONFIRMED"
        verified_by = "independent-audit"
        if not how_introduced:
            for bic in publishable_bics:
                sv = bic.screening_verification
                if sv and sv.verdict.value == "CONFIRMED":
                    how_introduced = sv.causal_chain
                    root_cause = sv.vuln_description
                    vuln_type = sv.vuln_type
                    vulnerable_pattern = sv.vulnerable_pattern
                    if how_introduced:
                        break
        # The override is a CVE-level adjudication. Per-BIC model assessments
        # remain immutable evidence and retain their original verdicts.

    # ------------------------------------------------------------------
    # 12. Output dict
    # ------------------------------------------------------------------
    ai_contribution = result.ai_contribution or ""

    # Convert fix_commits models to dicts for web output
    fix_commits_dicts = [fc.to_dict() for fc in result.fix_commits]

    entry = {
        "id": cve_id,
        "description": result.description or "",
        "severity": severity,
        "cvss": cvss,
        "cwes": result.cwes or [],
        "ecosystem": "",
        "published": published,
        "ai_tools": ai_tools,
        "ai_involved": trusted_ai_involved,
        "signal_source": signal_source,
        **({"signal_note": signal_note} if signal_note else {}),
        "languages": determine_languages(bug_commits, fix_commits_dicts),
        "confidence": compute_ai_confidence(result),
        "verified_by": verified_by,
        "how_introduced": ai_contribution or how_introduced,
        "root_cause": root_cause,
        "vuln_type": vuln_type,
        "vulnerable_pattern": vulnerable_pattern,
        "verdict": best_verdict,
        "bug_commits": bug_commits,
        "fix_commits": fix_commits_dicts,
        "references": result.references or [],
    }
    if ai_contribution:
        entry["ai_contribution"] = ai_contribution
    return entry
