#!/usr/bin/env python3
"""Smart audit queue with prioritized FP and FN candidates.

Scores and ranks CVEs by how likely they are to be false positives or
false negatives, so auditors review the most suspicious cases first.

Signal resolution mirrors BugIntroducingCommit.effective_signals() from
cve_analyzer/models.py — update _effective_signals() if that method changes.

Usage:
  audit_queue.py              # show next pick + queue summary
  audit_queue.py --top 10     # show top 10 from each queue
  audit_queue.py --fp         # show only FP queue
  audit_queue.py --fn         # show only FN queue
  audit_queue.py --json       # machine-readable output
  audit_queue.py --stats      # queue health overview
"""

import argparse
import json
import sys
from pathlib import Path

from audit_lock import load_claimed_cves

CACHE_DIR = Path.home() / ".cache/cve-analyzer/results"
AUDIT_PATH = Path.home() / ".cache/cve-analyzer/audit/findings.json"

# Ecosystems with high AI tool adoption
HIGH_AI_ECOSYSTEMS = {"npm", "PyPI", "crates.io", "Go", "NuGet"}

# AI tool adoption cutoff — commits after this date are more likely AI-assisted
AI_ADOPTION_CUTOFF = "2025-06-01"


# ── Signal resolution (mirrors models.py) ────────────────────────────────────


def _effective_signals(bic):
    """Authoritative AI signals for a BIC dict.

    Mirrors BugIntroducingCommit.effective_signals() from models.py:
    - If decomposed with culprit: culprit signals + PR signals
    - Otherwise: commit signals + PR signals
    """
    pr_sigs = bic.get("pr_signals", [])
    culprit = bic.get("culprit_sha", "")
    decomposed = bic.get("decomposed_commits", [])

    if culprit and decomposed:
        dc = next((d for d in decomposed if d.get("sha") == culprit), None)
        if dc and dc.get("touched_blamed_file") is not False:
            return list(dc.get("ai_signals", [])) + list(pr_sigs)
        return list(pr_sigs)
    return list(bic.get("commit", {}).get("ai_signals", [])) + list(pr_sigs)


def _all_ai_signals(bic):
    """ALL AI signals from any decomposed sub-commit + PR signals.

    Broader than _effective_signals — includes signals from sub-commits
    that did NOT touch the blamed file. Used for FN detection (any AI
    presence in the PR is worth investigating).
    """
    signals = []
    for dc in bic.get("decomposed_commits", []):
        signals.extend(dc.get("ai_signals", []))
    signals.extend(bic.get("pr_signals", []))
    if not bic.get("decomposed_commits"):
        signals.extend(bic.get("commit", {}).get("ai_signals", []))
    return signals


def _get_ai_bics(data):
    """Extract BICs that have effective AI signals (authoritative source)."""
    return [
        b
        for b in data.get("bug_introducing_commits", [])
        if _effective_signals(b)
    ]


def _get_deep_verdict(bic):
    """Return the best deep-verification verdict dict (new or old format).

    Normalizes deep_verification to include ``final_verdict`` key
    (it stores ``verdict`` natively) so callers can use one key.
    """
    vv = bic.get("deep_verification") or bic.get("verification_verdict")
    if vv:
        if "final_verdict" not in vv and "verdict" in vv:
            return {**vv, "final_verdict": vv["verdict"]}
        return vv
    return bic.get("tribunal_verdict")


# ── Loading ──────────────────────────────────────────────────────────────────


def load_audited():
    """Load audited CVE IDs (completed + actively claimed) and findings list."""
    findings = []
    audited = set()
    if AUDIT_PATH.exists():
        try:
            findings = json.loads(AUDIT_PATH.read_text())
            audited = {f.get("cve_id", "") for f in findings}
        except Exception:
            pass
    audited |= load_claimed_cves()
    return audited, findings


def load_results():
    if not CACHE_DIR.exists():
        return []
    results = []
    for f in CACHE_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if not data.get("error"):
                results.append(data)
        except Exception:
            continue
    return results


# ── FP scoring ───────────────────────────────────────────────────────────────


def score_fp_candidate(data, ai_bics):
    """Score a CVE with AI signals by FP likelihood. Higher = audit first."""
    score = 0
    reasons = []

    if not ai_bics:
        return None, []

    has_verified_confirmed = any(
        (_get_deep_verdict(b) or {}).get("final_verdict", "").upper()
        == "CONFIRMED"
        for b in ai_bics
    )
    has_verified_unlikely = any(
        (_get_deep_verdict(b) or {}).get("final_verdict", "").upper()
        == "UNLIKELY"
        for b in ai_bics
    )

    if has_verified_confirmed:
        score -= 20
        reasons.append("verified-confirmed")
    elif has_verified_unlikely:
        score += 40
        reasons.append("verified-unlikely")
    else:
        score += 30
        reasons.append("unverified")

    # Split votes — only applies to old tribunal format
    for b in ai_bics:
        tv = b.get("tribunal_verdict") or {}
        if tv.get("majority_count") and tv.get("agent_count"):
            if tv["majority_count"] < tv["agent_count"]:
                score += 25
                reasons.append("split-vote")
                break

    # Signals only from PR body (weaker than commit metadata)
    pr_body_only = all(
        all(s.get("origin") == "pr_body" for s in _effective_signals(b))
        for b in ai_bics
        if _effective_signals(b)
    )
    if pr_body_only:
        score += 20
        reasons.append("pr-body-only")

    # Signals from decomposed sub-commit (inherited through squash)
    has_decomp_signal = any(
        b.get("culprit_sha") and b.get("decomposed_commits")
        and any(dc.get("ai_signals") for dc in b.get("decomposed_commits", []))
        for b in ai_bics
    )
    if has_decomp_signal:
        score += 15
        reasons.append("decomposed-signal")

    # Noisy blame strategies
    noisy_strategies = {"pattern_search", "context_blame", "heuristic_blame"}
    for b in ai_bics:
        if b.get("blame_strategy") in noisy_strategies:
            score += 15
            reasons.append(f"noisy-blame({b['blame_strategy']})")
            break

    # Low blame confidence
    for b in ai_bics:
        conf = b.get("blame_confidence", 1.0)
        if conf < 0.5:
            score += 20
            reasons.append(f"low-conf({conf:.2f})")
        elif conf < 0.7:
            score += 10
            reasons.append(f"med-conf({conf:.2f})")
        break

    # Single signal is more fragile than multiple
    total_signals = sum(len(_effective_signals(b)) for b in ai_bics)
    if total_signals == 1:
        score += 10
        reasons.append("single-signal")

    # High severity — FP on CRITICAL/HIGH damages credibility more
    severity = data.get("severity", "")
    if "CRITICAL" in severity.upper() or "/AV:N/" in severity:
        score += 15
        reasons.append("high-severity")

    return score, reasons


# ── FN scoring ───────────────────────────────────────────────────────────────


def score_fn_candidate(data, tp_repos, tp_authors):
    """Score a CVE without effective AI signals by FN likelihood.

    Higher = more likely to be a false negative, audit first.
    """
    score = 0
    reasons = []

    bics = data.get("bug_introducing_commits", [])
    if not bics:
        return None, []

    # Same repo as a known true positive — most suspicious
    for fc in data.get("fix_commits", []):
        repo = fc.get("repo_url", "")
        if repo in tp_repos:
            score += 40
            reasons.append("same-repo-as-TP")
            break

    # BIC author also appears in TP commits
    for b in bics:
        author = b.get("commit", {}).get("author_email", "")
        if author and author in tp_authors:
            score += 30
            reasons.append("author-overlap")
            break

    # Recent BIC (AI adoption era)
    for b in bics:
        authored_date = b.get("commit", {}).get("authored_date", "")
        if authored_date and authored_date >= AI_ADOPTION_CUTOFF:
            score += 20
            reasons.append("recent-bic")
            break

    # High AI-adoption ecosystem
    ecosystems = set()
    for fc in data.get("fix_commits", []):
        src = fc.get("source", "")
        if src:
            ecosystems.add(src)
    eco = data.get("ecosystem", "")
    if eco:
        ecosystems.add(eco)
    if ecosystems & HIGH_AI_ECOSYSTEMS:
        score += 10
        reasons.append("high-ai-ecosystem")

    # Squash merge BIC — signals might be hidden in sub-commits
    for b in bics:
        committer = b.get("commit", {}).get("committer_email", "")
        if committer and "noreply.github.com" in committer:
            score += 15
            reasons.append("squash-merge-bic")
            break

    # AI present in PR but not on culprit (effective_signals empty,
    # but all_ai_signals non-empty — AI was there, just not attributed)
    for b in bics:
        if not _effective_signals(b) and _all_ai_signals(b):
            score += 35
            reasons.append("ai-in-pr-not-culprit")
            break

    # Repo has known AI tool usage (git log patterns, config files)
    repo_activity = data.get("repo_ai_activity", [])
    if repo_activity:
        score += 10
        tools = {a.split(":")[1] if ":" in a else a for a in repo_activity}
        reasons.append(f"repo-ai({','.join(sorted(tools)[:3])})")

    return score, reasons


# ── Queue building ───────────────────────────────────────────────────────────


def build_queues(results, audited):
    """Build and sort FP and FN queues in a single pass."""
    fp_queue = []
    fn_candidates = []
    tp_repos = set()
    tp_authors = set()

    # Single pass: collect TP metadata and stage candidates
    staged = []
    for data in results:
        cve_id = data.get("cve_id", "")
        ai_bics = _get_ai_bics(data)
        if ai_bics:
            for fc in data.get("fix_commits", []):
                tp_repos.add(fc.get("repo_url", ""))
            for b in ai_bics:
                tp_authors.add(b.get("commit", {}).get("author_email", ""))
        staged.append((cve_id, data, ai_bics))

    # Score from staged data
    for cve_id, data, ai_bics in staged:
        if cve_id in audited:
            continue
        if not data.get("fix_commits"):
            continue

        if ai_bics:
            score, reasons = score_fp_candidate(data, ai_bics)
            if score is not None:
                fp_queue.append((score, cve_id, reasons))
        else:
            bics = data.get("bug_introducing_commits", [])
            if bics:
                score, reasons = score_fn_candidate(data, tp_repos, tp_authors)
                if score is not None and score > 0:
                    fn_candidates.append((score, cve_id, reasons))

    fp_queue.sort(key=lambda x: -x[0])
    fn_candidates.sort(key=lambda x: -x[0])
    return fp_queue, fn_candidates


def _is_fn_finding(finding):
    """Heuristic: was this finding from an FN audit?

    Checks multiple signals since findings format varies across sessions.
    """
    # Explicit field (if present)
    if finding.get("audit_type") == "fn_detection":
        return True
    # Verdict suggests FN was found
    v = (finding.get("verdict") or finding.get("independent_verdict") or "").upper()
    if v == "FALSE_NEGATIVE":
        return True
    # Pipeline had no AI signals but audit found something
    pv = str(finding.get("pipeline_verdict", ""))
    if "confidence=0" in pv or "no AI" in pv.lower() or "no ai_signals" in pv.lower():
        return True
    return False


def _pick_next(fp_queue, fn_queue, findings):
    """Pick the next audit target, alternating FP/FN (every 3rd is FN)."""
    fn_audited = sum(1 for f in findings if _is_fn_finding(f))
    fp_audited = len(findings) - fn_audited

    if fn_queue and fp_audited > 0 and fp_audited % 3 == 0:
        return "fn", fn_queue[0][1], fn_queue[0][0]
    if fp_queue:
        return "fp", fp_queue[0][1], fp_queue[0][0]
    if fn_queue:
        return "fn", fn_queue[0][1], fn_queue[0][0]
    return None, None, 0


# ── CLI ──────────────────────────────────────────────────────────────────────


def print_stats(fp_queue, fn_queue, results, audited):
    """Print queue health overview."""
    total = len(results)
    with_bics = sum(1 for d in results if d.get("bug_introducing_commits"))
    with_signals = sum(1 for d in results if _get_ai_bics(d))
    print(f"=== Queue Health ===")
    print(f"Total results:     {total}")
    print(f"With BICs:         {with_bics}")
    print(f"With AI signals:   {with_signals} (effective_signals)")
    print(f"Audited:           {len(audited)}")
    print(f"FP candidates:     {len(fp_queue)}")
    print(f"FN candidates:     {len(fn_queue)}")
    print()
    if fp_queue:
        scores = [s for s, _, _ in fp_queue]
        print(f"FP score range:    {min(scores)}–{max(scores)} (median {sorted(scores)[len(scores)//2]})")
    if fn_queue:
        scores = [s for s, _, _ in fn_queue]
        print(f"FN score range:    {min(scores)}–{max(scores)} (median {sorted(scores)[len(scores)//2]})")

    # Reason distribution for top candidates
    from collections import Counter
    if fn_queue:
        fn_reasons = Counter()
        for _, _, reasons in fn_queue[:50]:
            for r in reasons:
                fn_reasons[r.split("(")[0]] += 1
        print(f"\nTop FN reasons (top 50): {dict(fn_reasons.most_common(8))}")


def main():
    parser = argparse.ArgumentParser(description="Smart audit queue")
    parser.add_argument("--top", type=int, default=5, help="Show top N from each queue")
    parser.add_argument("--fp", action="store_true", help="Show only FP queue")
    parser.add_argument("--fn", action="store_true", help="Show only FN queue")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    parser.add_argument("--stats", action="store_true", help="Queue health overview")
    args = parser.parse_args()

    if not args.fp and not args.fn and not args.stats:
        args.fp = args.fn = True

    audited, findings = load_audited()
    results = load_results()
    fp_queue, fn_queue = build_queues(results, audited)
    next_type, next_cve, next_score = _pick_next(fp_queue, fn_queue, findings)

    if args.stats:
        print_stats(fp_queue, fn_queue, results, audited)
        return

    if args.json:
        out = {}
        if args.fp:
            out["fp"] = [
                {"score": s, "cve_id": c, "reasons": r}
                for s, c, r in fp_queue[: args.top]
            ]
        if args.fn:
            out["fn"] = [
                {"score": s, "cve_id": c, "reasons": r}
                for s, c, r in fn_queue[: args.top]
            ]
        out["next"] = {"type": next_type, "cve_id": next_cve} if next_cve else None
        json.dump(out, sys.stdout, indent=2)
        print()
        return

    print(f"Audited so far: {len(audited)}")
    print()

    if args.fp:
        print(f"=== FP Queue ({len(fp_queue)} candidates) ===")
        print(f"{'#':>3s}  {'Score':>5s}  {'CVE':<25s}  Reasons")
        print("-" * 75)
        for i, (score, cve_id, reasons) in enumerate(fp_queue[: args.top], 1):
            print(f"{i:>3d}  {score:>5d}  {cve_id:<25s}  {', '.join(reasons)}")
        print()

    if args.fn:
        print(f"=== FN Queue ({len(fn_queue)} candidates) ===")
        print(f"{'#':>3s}  {'Score':>5s}  {'CVE':<25s}  Reasons")
        print("-" * 75)
        for i, (score, cve_id, reasons) in enumerate(fn_queue[: args.top], 1):
            print(f"{i:>3d}  {score:>5d}  {cve_id:<25s}  {', '.join(reasons)}")
        print()

    if not next_cve:
        print("Nothing to audit.")
        return

    cmd = "/audit-fn" if next_type == "fn" else "/audit"
    print(f"Next: {cmd} {next_cve}  (score: {next_score})")


if __name__ == "__main__":
    main()
