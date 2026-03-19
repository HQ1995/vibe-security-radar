#!/usr/bin/env python3
"""Build a verified ground truth fixture by checking each expected SHA.

For each candidate from the backup cache:
1. Verify the expected SHA exists in the repo
2. Check it's not a merge/release/dep-bump/test/non-code commit
3. Verify the commit message or diff has some security relevance
4. (Optional) LLM verification: ask a strong model if the commit actually fixes the CVE
5. Save only high-confidence ground truth to a fixture file

Usage:
    uv run python scripts/build_verified_fixture.py [--max N] [--seed SEED]
    uv run python scripts/build_verified_fixture.py --llm-verify --output verified-ground-truth-v2.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cve-analyzer" / "src"))

from regression_ground_truth import (
    CLONE_DIR,
    build_candidates,
    repo_url_to_path,
    load_backup_results,
    TAG_BASED_SOURCES,
    PR_BASED_SOURCES,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
LLM_CACHE_DIR = Path.home() / ".cache" / "cve-analyzer" / "ground-truth-llm"

# Security-relevant keywords in commit messages — at least one should appear
_SECURITY_SIGNAL_RE = re.compile(
    r"\bfix\b|\bpatch\b|\bsecur|\bvuln|\bCVE-|\bGHSA-|\bOSV-|"
    r"\bsaniti[zs]|\bescap|\binject|\btravers|\bxss\b|\bcsrf\b|"
    r"\bpermission|\bbypass|\boverflow|\bunderflow|\bdenial|\bdos\b|"
    r"\bauth|\brace\b|\bbounds?\b|\bbuffer\b|\bvalidat|\brestrict|"
    r"\bprotect|\bsafe|\bverif|\bprevent|\bblock\b|\bcheck\b|"
    r"\blimit\b|\bcrash|\bsegfault|\bheap|\bstack|\buse.after.free|"
    r"\bnull.pointer|\bout.of.bounds|\bmemory|"
    r"\brce\b|\bssrf\b|\blfi\b|\brfi\b|\bpath\b|\bopen.redirect|"
    r"\bread.beyond|\bwrite.beyond|\bdouble.free|\binteger|"
    r"\bremote.code|\barbitrary|\bunauthori[zs]|\bescalat",
    re.IGNORECASE,
)

# Release/version patterns (should NOT appear in verified fixture)
_RELEASE_RE = re.compile(
    r"(?:^|\] )(?:chore\(release\)|release[:(]|bump[: ])|"
    r"(?:^|\] )v?\d+\.\d+\.\d+\b|"
    r"\bbumped?\s+version\b|"
    r"\bprepare\s+(?:for\s+)?release\b|"
    r"^(?:preparing|cut)\s+release\b|"
    r"^RELEASE[- ]NOTES|"
    r"^This is the \d+\.\d+ release|"
    r"^Changelog\s+for\s+\d+\.\d+|"
    r"^\S+\s+\d+\.\d+\.\d+$|"
    r"^go\d+\.\d+\.\d+\b|"
    r"^`?\d+\.\d+\.\d+`?\s+(?:and\s+`?\d+\.\d+|$)|"
    r"^\S+:\s+v?\d+\.\d+\.\d+\b|"
    r"^Release\s+\d+\.\d+",
    re.IGNORECASE,
)

_DEP_BUMP_RE = re.compile(
    r"^bump\s+\S+\s+from\s+\S*\d+\.\d+\S*\s+to\s+\S*\d+\.\d+\S*|"
    r"update\s+\S+\s+requirement\s+from|"
    r"^chore\(deps\)|^build\(deps\)|"
    r"^Merge\s+pull\s+request\s+#\d+\s+from\s+dependabot/|"
    r"^update\s+(?:composer|npm|pip|cargo|go)\s+dependencies\b",
    re.IGNORECASE | re.MULTILINE,
)

_TEST_MSG_RE = re.compile(
    r"^test[:(]|^spec[:(]|^fixture|"
    r"^chore\(tests?\)|"
    r"\bfix\s+(?:flaky\s+)?tests?\b|"
    r"\bupdate\s+(?:test|spec)\b",
    re.IGNORECASE,
)

_TEST_FILE_RE = re.compile(
    r"(?:^|/)(?:tests?|specs?|__tests__|fixtures)/|"
    r"(?:_test|\.test|\.spec|_spec)\.[a-z]+$|"
    r"(?:^|/)test_[a-z]|(?:^|/)spec_[a-z]",
    re.IGNORECASE,
)

_NON_CODE_RE = re.compile(
    r"(?:^|/)(?:locales?|translations?|i18n|l10n|LC_MESSAGES)/|"
    r"\.(?:po|pot|mo)$|"
    r"(?:^|/)CHANGELOG|"
    r"(?:^|/)package\.json$|(?:^|/)package-lock\.json$|"
    r"(?:^|/)yarn\.lock$|(?:^|/)Cargo\.lock$|(?:^|/)go\.sum$|"
    r"(?:^|/)\.github/|(?:^|/)\.circleci/|"
    r"(?:^|/)CODEOWNERS$|(?:^|/)composer\.json$|"
    r"(?:^|/)\.changeset/|(?:^|/)\.release-please",
    re.IGNORECASE,
)


def verify_commit(cve_id: str, sha: str, repo_path: Path, description: str) -> dict:
    """Deep-verify a single expected commit. Returns verification result."""
    result = {"cve_id": cve_id, "sha": sha, "status": "unknown", "reason": ""}

    # 1. Check commit exists and get metadata
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_path), "log", "-1", "--format=%P%n%s%n%b", sha],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            result["status"] = "reject"
            result["reason"] = "sha_not_found"
            return result
        parts = r.stdout.split("\n", 2)
        parents = parts[0].strip()
        subject = parts[1] if len(parts) > 1 else ""
        body = parts[2] if len(parts) > 2 else ""
        full_msg = f"{subject}\n{body}"
    except (subprocess.TimeoutExpired, OSError):
        result["status"] = "reject"
        result["reason"] = "git_error"
        return result

    # 2. Reject merge commits
    if len(parents.split()) >= 2:
        result["status"] = "reject"
        result["reason"] = "merge_commit"
        return result

    first_line = subject.split("\n")[0]

    # 3. Reject release/version bumps
    if _RELEASE_RE.search(first_line):
        result["status"] = "reject"
        result["reason"] = "release_bump"
        return result

    # 4. Reject dep bumps
    if _DEP_BUMP_RE.search(full_msg):
        result["status"] = "reject"
        result["reason"] = "dep_bump"
        return result

    # 5. Reject test-only by message
    if _TEST_MSG_RE.search(first_line):
        result["status"] = "reject"
        result["reason"] = "test_only_msg"
        return result

    # 6. Get changed files
    try:
        r2 = subprocess.run(
            ["git", "-C", str(repo_path), "diff-tree", "--no-commit-id", "-r", "--name-only", sha],
            capture_output=True, text=True, timeout=10,
        )
        files = [f for f in r2.stdout.strip().split("\n") if f] if r2.returncode == 0 else []
    except (subprocess.TimeoutExpired, OSError):
        files = []

    # 7. Reject test-only by files
    if files and all(_TEST_FILE_RE.search(f) for f in files):
        result["status"] = "reject"
        result["reason"] = "test_only_files"
        return result

    # 8. Reject non-code only
    if files and all(_NON_CODE_RE.search(f) for f in files):
        result["status"] = "reject"
        result["reason"] = "non_code_only"
        return result

    # 9. Check for security relevance signal in message OR description match
    has_security_signal = bool(_SECURITY_SIGNAL_RE.search(full_msg))

    # Check if CVE/GHSA ID is in commit message
    has_id_in_msg = (
        cve_id.lower() in full_msg.lower()
        if cve_id and not cve_id.startswith("OSV-")
        else False
    )

    # Check if commit touches code files (not just config)
    code_files = [f for f in files if not _NON_CODE_RE.search(f) and not _TEST_FILE_RE.search(f)]
    has_code_changes = len(code_files) > 0

    if has_id_in_msg:
        result["status"] = "verified"
        result["reason"] = "cve_id_in_message"
    elif has_security_signal and has_code_changes:
        result["status"] = "verified"
        result["reason"] = "security_signal+code"
    elif has_code_changes:
        result["status"] = "accepted"
        result["reason"] = "code_changes_only"
    else:
        result["status"] = "weak"
        result["reason"] = "no_security_signal"

    result["subject"] = first_line[:120]
    result["file_count"] = len(files)
    result["code_file_count"] = len(code_files)
    return result


# ── LLM ground truth verification ────────────────────────────────


_LLM_VERIFY_SYSTEM = """\
You are a security researcher verifying ground truth data for a CVE fix commit dataset.

Given a CVE description and a commit's message + diff summary, determine whether \
this commit actually fixes the described vulnerability.

Return JSON only (no markdown fences):
{"fixes_cve": true/false, "confidence": 0.0-1.0, "reasoning": "1-2 sentences"}

Be strict: the commit must address the specific vulnerability described, not just \
touch related code or fix a different bug in the same area."""


def _get_diff_summary(repo_path: Path, sha: str, max_chars: int = 2000) -> str:
    """Get a truncated diff for LLM verification."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_path), "diff", "--stat", f"{sha}^..{sha}"],
            capture_output=True, text=True, timeout=10,
        )
        stat = r.stdout[:500] if r.returncode == 0 else ""

        r2 = subprocess.run(
            ["git", "-C", str(repo_path), "diff", "--no-color", "-p",
             f"{sha}^..{sha}"],
            capture_output=True, text=True, timeout=30,
        )
        diff = r2.stdout[:max_chars] if r2.returncode == 0 else ""

        return f"## Diff stat\n{stat}\n\n## Diff (truncated)\n{diff}"
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _llm_cache_path(cve_id: str) -> Path:
    return LLM_CACHE_DIR / f"{cve_id}.json"


def _read_llm_cache(cve_id: str) -> dict | None:
    try:
        return json.loads(_llm_cache_path(cve_id).read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _write_llm_cache(cve_id: str, data: dict) -> None:
    LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _llm_cache_path(cve_id).write_text(json.dumps(data, indent=2) + "\n")


def llm_verify_ground_truth(
    cve_id: str,
    description: str,
    sha: str,
    repo_path: Path,
    subject: str,
    model: str = "gpt-5.4",
) -> dict:
    """Ask a strong LLM whether this commit actually fixes the CVE.

    Returns {"fixes_cve": bool, "confidence": float, "reasoning": str}.
    Uses a file-based cache to avoid redundant API calls.
    """
    # Check cache first
    cached = _read_llm_cache(cve_id)
    if cached is not None:
        return cached

    from cve_analyzer.llm_verify import call_llm

    diff_summary = _get_diff_summary(repo_path, sha)

    prompt = (
        f"## {cve_id}\n"
        f"## Description\n{description[:800]}\n\n"
        f"## Commit: {sha[:12]}\n"
        f"## Subject: {subject}\n\n"
        f"{diff_summary}\n"
    )

    result = call_llm(
        prompt, model,
        system_prompt=_LLM_VERIFY_SYSTEM,
        max_tokens=512,
    )

    if result is None:
        verdict = {"fixes_cve": None, "confidence": 0.5, "reasoning": "LLM call failed"}
    else:
        parsed, used_model = result
        verdict = {
            "fixes_cve": parsed.get("fixes_cve"),
            "confidence": float(parsed.get("confidence", 0.5)),
            "reasoning": parsed.get("reasoning", ""),
            "model": used_model,
        }

    _write_llm_cache(cve_id, verdict)
    return verdict


def main():
    parser = argparse.ArgumentParser(description="Build verified ground truth fixture")
    parser.add_argument("--max", type=int, default=0, help="Max candidates to verify (0=all)")
    parser.add_argument("--workers", type=int, default=64, help="Parallel workers")
    parser.add_argument("--output", type=str, default="verified-ground-truth.json",
                        help="Output fixture filename")
    parser.add_argument("--llm-verify", action="store_true",
                        help="Run LLM verification pass on accepted/verified entries")
    parser.add_argument("--llm-model", type=str, default="gpt-5.4",
                        help="Model for LLM verification")
    args = parser.parse_args()

    # Load ALL raw results, apply minimal filtering
    raw_results = load_backup_results()
    print(f"Loaded {len(raw_results)} cached results")

    exclude_sources = TAG_BASED_SOURCES | PR_BASED_SOURCES
    to_verify = []

    for data in raw_results:
        cve_id = data.get("cve_id", "")
        fix_commits = data.get("fix_commits", [])
        if not fix_commits:
            continue

        good_fcs = [
            fc for fc in fix_commits
            if fc.get("sha") and len(fc.get("sha", "")) >= 10
            and fc.get("source", "") not in exclude_sources
        ]
        if not good_fcs:
            continue

        repo_url = good_fcs[0].get("repo_url", "")
        if not repo_url:
            continue

        description = data.get("description", "")
        if not description or len(description) < 20:
            continue

        repo_name = repo_url_to_path(repo_url)
        repo_path = CLONE_DIR / repo_name
        if not repo_path.exists():
            continue

        to_verify.append({
            "cve_id": cve_id,
            "sha": good_fcs[0]["sha"],
            "repo_path": repo_path,
            "repo_url": repo_url,
            "description": description,
            "cwes": data.get("cwes", []),
            "expected_shas": [fc["sha"] for fc in good_fcs],
        })

    if args.max:
        to_verify = to_verify[:args.max]

    print(f"Verifying {len(to_verify)} candidates with {args.workers} workers...")

    # Parallel verification
    stats: dict[str, int] = {}
    verified = []
    accepted = []
    weak = []
    rejected: dict[str, list] = {}

    def _do_verify(item):
        return verify_commit(item["cve_id"], item["sha"], item["repo_path"], item["description"]), item

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(_do_verify, item) for item in to_verify]
        for i, future in enumerate(as_completed(futures), 1):
            result, item = future.result()
            status = result["status"]
            reason = result["reason"]
            stats[f"{status}:{reason}"] = stats.get(f"{status}:{reason}", 0) + 1

            if status == "verified":
                item["_subject"] = result.get("subject", "")
                verified.append(item)
            elif status == "accepted":
                item["_subject"] = result.get("subject", "")
                accepted.append(item)
            elif status == "weak":
                weak.append(item)
            else:
                rejected.setdefault(reason, []).append(item["cve_id"])

            if i % 500 == 0:
                print(f"  Progress: {i}/{len(to_verify)}")

    # Summary
    print(f"\n{'='*60}")
    print(f"Verification results ({len(to_verify)} candidates):")
    for key in sorted(stats.keys()):
        print(f"  {key:40s} {stats[key]:5d}")

    # Build fixture from verified + accepted (not weak/rejected)
    fixture_candidates = verified + accepted
    print(f"\nFixture: {len(verified)} verified + {len(accepted)} accepted = {len(fixture_candidates)} total")
    print(f"Rejected: {sum(len(v) for v in rejected.values())}")
    print(f"Weak (excluded): {len(weak)}")

    # ── Optional LLM verification pass ──────────────────────────
    if args.llm_verify and fixture_candidates:
        print(f"\n{'='*60}")
        print(f"LLM verification: {len(fixture_candidates)} entries with {args.workers} workers")
        print(f"Model: {args.llm_model}")

        llm_confirmed = []
        llm_rejected = []
        llm_uncertain = []
        llm_errors = 0
        start = time.time()

        def _do_llm_verify(item):
            return llm_verify_ground_truth(
                cve_id=item["cve_id"],
                description=item["description"],
                sha=item["sha"],
                repo_path=item["repo_path"],
                subject=item.get("_subject", ""),
                model=args.llm_model,
            ), item

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(_do_llm_verify, item) for item in fixture_candidates]
            for i, future in enumerate(as_completed(futures), 1):
                try:
                    verdict, item = future.result()
                except Exception:
                    llm_errors += 1
                    continue

                fixes = verdict.get("fixes_cve")
                confidence = verdict.get("confidence", 0.5)

                if fixes is True and confidence >= 0.7:
                    llm_confirmed.append(item)
                elif fixes is False and confidence >= 0.7:
                    llm_rejected.append(item)
                else:
                    # Uncertain: keep in fixture (conservative)
                    llm_uncertain.append(item)

                if i % 100 == 0:
                    elapsed = time.time() - start
                    print(f"  LLM progress: {i}/{len(fixture_candidates)} ({elapsed:.0f}s)")

        elapsed = time.time() - start
        print(f"\nLLM verification ({elapsed:.0f}s):")
        print(f"  Confirmed:  {len(llm_confirmed)}")
        print(f"  Rejected:   {len(llm_rejected)}")
        print(f"  Uncertain:  {len(llm_uncertain)} (kept)")
        print(f"  Errors:     {llm_errors}")

        if llm_rejected:
            print(f"\nLLM-rejected examples:")
            for item in llm_rejected[:10]:
                cached = _read_llm_cache(item["cve_id"])
                reasoning = cached.get("reasoning", "") if cached else ""
                print(f"  {item['cve_id']}: {reasoning[:100]}")

        # Use confirmed + uncertain (conservative: only remove high-confidence rejections)
        fixture_candidates = llm_confirmed + llm_uncertain
        print(f"\nPost-LLM fixture: {len(fixture_candidates)} entries")

    # Save fixture
    output_path = FIXTURE_DIR / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_data = [
        {
            "cve_id": c["cve_id"],
            "expected_shas": c["expected_shas"],
            "repo_url": c["repo_url"],
        }
        for c in fixture_candidates
    ]
    output_path.write_text(json.dumps(fixture_data, indent=2) + "\n")
    print(f"\nSaved: {len(fixture_data)} CVEs → {output_path}")


if __name__ == "__main__":
    main()
