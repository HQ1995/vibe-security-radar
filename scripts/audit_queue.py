#!/usr/bin/env python3
"""Smart audit queue with prioritized FP and FN candidates.

Scores and ranks CVEs by how likely they are to be false positives or
false negatives, so auditors review the most suspicious cases first.

Usage:
  audit_queue.py              # show next pick + queue summary
  audit_queue.py --top 10     # show top 10 from each queue
  audit_queue.py --fp         # show only FP queue
  audit_queue.py --fn         # show only FN queue
  audit_queue.py --json       # machine-readable output
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


def _get_ai_bics(data):
    """Extract BICs that have AI signals."""
    return [
        b
        for b in data.get("bug_introducing_commits", [])
        if b.get("commit", {}).get("ai_signals")
    ]


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
    # Also exclude CVEs currently being audited by other sessions
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


def _get_deep_verdict(bic):
    """Return the best deep-verification verdict dict (new or old format).

    Normalizes verification_verdict to include ``final_verdict`` key
    (it stores ``verdict`` natively) so callers can use one key.
    """
    vv = bic.get("verification_verdict")
    if vv:
        if "final_verdict" not in vv and "verdict" in vv:
            return {**vv, "final_verdict": vv["verdict"]}
        return vv
    return bic.get("tribunal_verdict")


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
        # Already confirmed — low priority for FP audit
        score -= 20
        reasons.append("verified-confirmed")
    elif has_verified_unlikely:
        # Deep verify said UNLIKELY but we kept the signal — worth checking
        score += 40
        reasons.append("verified-unlikely")
    else:
        score += 30
        reasons.append("unverified")

    # Split votes (non-unanimous) — only applies to old tribunal format
    for b in ai_bics:
        tv = b.get("tribunal_verdict") or {}
        if tv.get("majority_count") and tv.get("agent_count"):
            if tv["majority_count"] < tv["agent_count"]:
                score += 25
                reasons.append("split-vote")
                break

    # Inherited/squash signals are more likely false
    has_squash = any(
        "squash" in sig.get("signal_type", "") or "decomposed" in sig.get("signal_type", "")
        for b in ai_bics
        for sig in b.get("commit", {}).get("ai_signals", [])
    )
    if has_squash:
        score += 20
        reasons.append("squash-signal")

    # Noisy blame strategies
    noisy_strategies = {"pattern_search", "context_blame", "heuristic_blame"}
    for b in ai_bics:
        if b.get("blame_strategy") in noisy_strategies:
            score += 15
            reasons.append(f"noisy-blame({b['blame_strategy']})")
            break

    # Low confidence
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
    total_signals = sum(
        len(b.get("commit", {}).get("ai_signals", [])) for b in ai_bics
    )
    if total_signals == 1:
        score += 10
        reasons.append("single-signal")

    # High severity — FP on CRITICAL/HIGH damages credibility more
    severity = data.get("severity", "")
    if "CRITICAL" in severity.upper() or "/AV:N/" in severity:
        score += 15
        reasons.append("high-severity")

    return score, reasons


def score_fn_candidate(data, tp_repos, tp_authors):
    """Score a CVE without AI signals by FN likelihood. Higher = audit first."""
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
        author_date = b.get("commit", {}).get("author_date", "")
        if author_date and author_date >= AI_ADOPTION_CUTOFF:
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

    return score, reasons


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

    # Score from staged data (ai_bics already computed)
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


def _pick_next(fp_queue, fn_queue, findings):
    """Pick the next audit target, alternating FP/FN (every 3rd is FN)."""
    fn_audited = sum(1 for f in findings if f.get("audit_type") == "fn_detection")
    fp_audited = len(findings) - fn_audited

    if fn_queue and fp_audited > 0 and fp_audited % 3 == 0:
        return "fn", fn_queue[0][1], fn_queue[0][0]
    if fp_queue:
        return "fp", fp_queue[0][1], fp_queue[0][0]
    if fn_queue:
        return "fn", fn_queue[0][1], fn_queue[0][0]
    return None, None, 0


def main():
    parser = argparse.ArgumentParser(description="Smart audit queue")
    parser.add_argument("--top", type=int, default=5, help="Show top N from each queue")
    parser.add_argument("--fp", action="store_true", help="Show only FP queue")
    parser.add_argument("--fn", action="store_true", help="Show only FN queue")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args()

    if not args.fp and not args.fn:
        args.fp = args.fn = True

    audited, findings = load_audited()
    results = load_results()
    fp_queue, fn_queue = build_queues(results, audited)
    next_type, next_cve, next_score = _pick_next(fp_queue, fn_queue, findings)

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
