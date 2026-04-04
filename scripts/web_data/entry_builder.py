"""Build web-format CVE entries from CveAnalysisResult models.

Replaces the old dict-based ``build_cve_entry()`` and ``_build_bug_commit()``
from ``generate_web_data.py`` with a model-based implementation that
operates directly on typed dataclass instances.
"""

from __future__ import annotations

import json
import os
import re

from cve_analyzer.models import (
    AiSignal,
    BugIntroducingCommit,
    CveAnalysisResult,
    WORKFLOW_SIGNAL_TYPES,
)
from cve_analyzer.scoring import compute_ai_confidence

from web_data.constants import CONFIDENCE_STR_TO_NUMERIC, STRONG_SIGNAL_TYPES
from web_data.filters import is_fallback_verdict
from web_data.languages import determine_languages
from web_data.severity import extract_cvss_score, parse_severity

# ---------------------------------------------------------------------------
# Cache directory for PR lookup
# ---------------------------------------------------------------------------

DEFAULT_API_RESPONSES_DIR = os.path.expanduser("~/.cache/cve-analyzer/api-responses")


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


def _model_with_reasoning_tag(model: str) -> str:
    """Append a reasoning-mode suffix to the model name.

    claude-code is the SDK-based conflict resolver -- no suffix needed
    since the SDK controls its own model version internally.
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
        if is_fallback_verdict(vv):
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
                "confidence": dv.get("confidence", ""),
                "models": [
                    av.get("model", "") for av in dv.get("agent_verdicts", [])
                ],
                "agent_verdicts": [
                    {
                        "model": av.get("model", ""),
                        "verdict": av.get("verdict", ""),
                        "reasoning": av.get("reasoning", ""),
                        "confidence": av.get("confidence", 0),
                        "tool_calls_made": av.get("tool_calls_made", 0),
                        "steps_completed": av.get("steps_completed", 0),
                        "evidence": av.get("evidence", []),
                    }
                    for av in dv["agent_verdicts"]
                ],
            }
        else:
            # New verifier format: single-model flat structure.
            raw_conf = dv.get("confidence", "")
            numeric_conf = CONFIDENCE_STR_TO_NUMERIC.get(
                str(raw_conf).lower(), raw_conf,
            )
            entry["verification"] = {
                "verdict": dv.get("final_verdict", ""),
                "confidence": numeric_conf,
                "models": [dv["model"]] if dv.get("model") else [],
                "agent_verdicts": [
                    {
                        "model": dv.get("model", ""),
                        "verdict": dv.get("final_verdict", ""),
                        "reasoning": dv.get("reasoning", ""),
                        "confidence": numeric_conf,
                        "tool_calls_made": dv.get("tool_calls_made", 0),
                        "steps_completed": dv.get("steps_completed", 0),
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
) -> dict | None:
    """Transform a CveAnalysisResult into a web-friendly CVE entry.

    Returns None if all AI signals are lost during squash decomposition
    (trailer pollution -- AI co-author on merge commits, not on vuln code).
    """
    cve_id = result.cve_id
    is_override = cve_id in (audit_overrides or set())

    # ------------------------------------------------------------------
    # 1. AI tools extraction
    # ------------------------------------------------------------------
    ai_tools_set: set[str] = set()
    has_commit_signal = False
    has_pr_body_signal = False

    for bic in result.bug_introducing_commits:
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
    if result.ai_involved is True and not ai_tools:
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
        for bic in result.bug_introducing_commits:
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
    for fc in result.fix_commits:
        if fc.repo_url:
            fix_repo_url = fc.repo_url
            break

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
        for bic in result.bug_introducing_commits
        if (bic.effective_signals() or bic.all_ai_signals() or bic.commit.ai_signals)
        and (is_override or result.ai_involved is True or _effective_verdict(bic) not in ("UNRELATED", "UNLIKELY"))
    ]

    # Deduplicate by SHA (merge blamed_file strings)
    seen_shas: dict[str, dict] = {}
    bug_commits: list[dict] = []
    for bc in bug_commits_raw:
        sha = bc["sha"]
        if sha in seen_shas:
            existing = seen_shas[sha]
            if bc["blamed_file"] and bc["blamed_file"] != existing["blamed_file"]:
                existing["blamed_file"] += f", {bc['blamed_file']}"
        else:
            seen_shas[sha] = bc
            bug_commits.append(bc)

    # Deduplicate by identical verification reasoning
    seen_reasonings: set[str] = set()
    deduped: list[dict] = []
    for bc in bug_commits:
        reasoning = ""
        for av in bc.get("verification", {}).get("agent_verdicts", []):
            reasoning = av.get("reasoning", "")
            break
        if reasoning and reasoning in seen_reasonings:
            continue
        if reasoning:
            seen_reasonings.add(reasoning)
        deduped.append(bc)
    bug_commits = deduped

    # ------------------------------------------------------------------
    # 4. Filter lost signals (skip when ai_involved=True — investigator
    #    confirmed AI involvement at CVE level, keep BICs for display)
    # ------------------------------------------------------------------
    pre_filter_count = len(bug_commits)
    if not is_override and result.ai_involved is not True:
        bug_commits = [bc for bc in bug_commits if bc.get("ai_signals")]
    if pre_filter_count > 0 and not bug_commits:
        return None

    # ------------------------------------------------------------------
    # 8. Severity
    # ------------------------------------------------------------------
    # Extract vuln_type early for severity inference
    first_vuln_type = ""
    for bic in result.bug_introducing_commits:
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
    # Published date
    # ------------------------------------------------------------------
    published = ""
    if nvd_dates and cve_id in nvd_dates:
        published = nvd_dates[cve_id]
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
        for bic in result.bug_introducing_commits:
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

    for bic in result.bug_introducing_commits:
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
    if result.ai_involved is True:
        best_verdict = "CONFIRMED"
    else:
        for bic in result.bug_introducing_commits:
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
            for bic in result.bug_introducing_commits:
                sv = bic.screening_verification
                if sv and sv.verdict.value == "CONFIRMED":
                    how_introduced = sv.causal_chain
                    root_cause = sv.vuln_description
                    vuln_type = sv.vuln_type
                    vulnerable_pattern = sv.vulnerable_pattern
                    if how_introduced:
                        break
        # Replace incorrect deep-verify verdicts with screening data
        for bc in bug_commits:
            v = bc.get("verification", {})
            if v and (v.get("verdict") or "").upper() in ("UNLIKELY", "UNRELATED"):
                sv_dict = bc.get("screening_verification", {})
                if sv_dict and sv_dict.get("verdict") == "CONFIRMED":
                    bc["verification"] = {
                        "verdict": "CONFIRMED",
                        "confidence": sv_dict.get("confidence", 0.8),
                        "models": ["independent-audit"],
                        "agent_verdicts": [{
                            "model": "independent-audit",
                            "verdict": "CONFIRMED",
                            "reasoning": sv_dict.get("reasoning", ""),
                            "confidence": sv_dict.get("confidence", 0.8),
                            "tool_calls_made": 0,
                            "steps_completed": ["audit_override"],
                            "evidence": [],
                        }],
                    }

    # ------------------------------------------------------------------
    # 11b. ai_involved=True override: replace contradictory per-BIC verdicts
    # ------------------------------------------------------------------
    # When investigator says ai_involved=True but per-BIC verdicts are
    # UNRELATED/UNLIKELY (cross-file reasoning bug), override the display
    # verdict to match the CVE-level conclusion.
    if result.ai_involved is True and result.ai_contribution:
        for bc in bug_commits:
            v = bc.get("verification", {})
            if v and (v.get("verdict") or "").upper() in ("UNLIKELY", "UNRELATED"):
                bc["verification"] = {
                    "verdict": "CONFIRMED",
                    "confidence": 0.8,
                    "models": ["investigator-override"],
                    "agent_verdicts": [{
                        "model": "investigator-override",
                        "verdict": "CONFIRMED",
                        "reasoning": result.ai_contribution,
                        "confidence": 0.8,
                        "tool_calls_made": 0,
                        "steps_completed": ["ai_involved_override"],
                        "evidence": [],
                    }],
                }
        if not verified_by:
            verified_by = "Claude Code"
            best_verdict = "CONFIRMED"

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
        "ai_involved": result.ai_involved,
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
