"""Shared ground truth construction for regression tests.

Loads CVE results from the backup cache, filters out unreliable fix commits
(merge commits, release bumps, dependency bumps, non-code-only), and returns
clean candidates with verified expected SHAs.

Used by:
  - regression_desc_search.py  (description-based discovery)
  - regression_tag_search.py   (tag-based discovery)
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

BACKUP_DIR = Path.home() / ".cache" / "cve-analyzer" / "backup-2026-03-15" / "results"
CLONE_DIR = Path.home() / ".cache" / "cve-analyzer" / "repos"

# Sources that are themselves tag-based or AI-inferred — exclude when testing
# those algorithms to avoid circular ground truth.
TAG_BASED_SOURCES = frozenset({
    "advisory_version", "gemnasium_version", "ghsa_ref_version", "ai_inferred",
})

# PR-based sources may point to squash-merge commits not discoverable via git log
PR_BASED_SOURCES = frozenset({"github_advisory_pr"})

# -- Commit quality filters --

_RELEASE_MSG_RE = re.compile(
    r"(?:^|\] )(?:chore\(release\)|release[:(]|bump[: ])|"   # original patterns, allow [tag] prefix
    r"(?:^|\] )v?\d+\.\d+\.\d+\b|"                           # version-only messages
    r"\bbumped?\s+version\b|"                                 # "Bumped version for X release"
    r"\bprepare\s+(?:for\s+)?release\b|"                      # "prepare release" / "prepare for release"
    r"^(?:preparing|cut)\s+release\b|"                         # "Preparing release 4.0.0"
    r"^RELEASE[- ]NOTES|"                                     # RELEASE-NOTES: synced
    r"^This is the \d+\.\d+ release|"                         # prose release messages
    r"^Changelog\s+for\s+\d+\.\d+|"                           # Changelog entries
    r"^\S+\s+\d+\.\d+\.\d+$|"                                # "ProjectName 3.4.6" (version-only)
    r"^go\d+\.\d+\.\d+\b|"                                   # Go release tags: "go1.24.12"
    r"^`?\d+\.\d+\.\d+`?\s+(?:and\s+`?\d+\.\d+|$)",         # "1.4.1 and 1.4.2", "1.4.1"
    re.IGNORECASE,
)

_DEP_BUMP_MSG_RE = re.compile(
    r"^bump\s+\S+\s+from\s+\S*\d+\.\d+\S*\s+to\s+\S*\d+\.\d+\S*|"
    r"update\s+\S+\s+requirement\s+from|"
    r"^chore\(deps\)|^build\(deps\)|"
    r"^Merge\s+pull\s+request\s+#\d+\s+from\s+dependabot/|"
    r"^update\s+(?:composer|npm|pip|cargo|go)\s+dependencies\b",  # "Update Composer dependencies"
    re.IGNORECASE | re.MULTILINE,
)

_TEST_MSG_RE = re.compile(
    r"^test[:(]|^spec[:(]|^fixture|"       # test: prefix
    r"^chore\(tests?\)|"                    # chore(test): prefix
    r"\bfix\s+(?:flaky\s+)?tests?\b|"       # "fix test", "fix flaky tests"
    r"\bupdate\s+(?:test|spec)\b",          # "update test files"
    re.IGNORECASE,
)

_TEST_FILE_PATTERNS = re.compile(
    r"(?:^|/)(?:tests?|specs?|__tests__|fixtures)/|"   # test directories
    r"(?:_test|\.test|\.spec|_spec)\.[a-z]+$|"         # test file suffixes
    r"(?:^|/)test_[a-z]|(?:^|/)spec_[a-z]",            # test file prefixes
    re.IGNORECASE,
)

_NON_CODE_PATTERNS = re.compile(
    r"(?:^|/)(?:locales?|translations?|i18n|l10n|LC_MESSAGES)/|"
    r"\.(?:po|pot|mo)$|"
    r"(?:^|/)translation\.json$|"
    r"(?:^|/)CHANGELOG|"
    r"(?:^|/)package\.json$|"
    r"(?:^|/)package-lock\.json$|"
    r"(?:^|/)yarn\.lock$|"
    r"(?:^|/)Cargo\.lock$|"
    r"(?:^|/)go\.sum$|"
    r"(?:^|/)\.github/|"                    # GitHub workflows
    r"(?:^|/)\.circleci/|"                  # CI config
    r"(?:^|/)CODEOWNERS$|"                  # CODEOWNERS
    r"(?:^|/)(?:configure|Makefile)$|"      # build config
    r"(?:^|/)m4/|"                          # autoconf macros
    r"(?:^|/)composer\.json$",              # packaging metadata
    re.IGNORECASE,
)


def classify_commit(sha: str, repo_path: Path) -> str | None:
    """Return a rejection reason if the commit is unreliable ground truth, else None.

    Checks (in order):
    - sha_not_found: commit doesn't exist in the repo
    - git_error: git command failed
    - merge_commit: multi-parent (merge/squash)
    - release_bump: message matches release/version bump pattern
    - test_only: test/spec commit by message or file patterns
    - dep_bump: dependency bump by message or lockfile-only changes
    - non_code_only: all changed files are non-code (locale, changelog, lockfiles, CI, config)
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_path), "log", "-1", "--format=%P%n%s", sha],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return "sha_not_found"
        lines = r.stdout.strip().split("\n", 1)
        parents = lines[0].strip()
        message = lines[1] if len(lines) > 1 else ""
    except (subprocess.TimeoutExpired, OSError):
        return "git_error"

    # Multi-parent = merge commit
    if len(parents.split()) >= 2:
        return "merge_commit"

    # Release/version bump message
    first_line = message.split("\n")[0]
    if _RELEASE_MSG_RE.search(first_line):
        return "release_bump"

    # Test-only commit (message pattern)
    if _TEST_MSG_RE.search(first_line):
        return "test_only"

    # Dependency bump
    if _DEP_BUMP_MSG_RE.search(message):
        return "dep_bump"

    # Check changed files
    try:
        r2 = subprocess.run(
            ["git", "-C", str(repo_path), "diff-tree", "--no-commit-id",
             "-r", "--name-only", sha],
            capture_output=True, text=True, timeout=10,
        )
        if r2.returncode == 0:
            files = [f for f in r2.stdout.strip().split("\n") if f]
            # Test/spec-only files
            if files and all(_TEST_FILE_PATTERNS.search(f) for f in files):
                return "test_only"
            # Non-code only (locale, changelog, lockfiles, CI, config)
            if files and all(_NON_CODE_PATTERNS.search(f) for f in files):
                return "non_code_only"
    except (subprocess.TimeoutExpired, OSError):
        pass

    return None


def repo_url_to_path(url: str) -> str:
    """Convert repo URL to local clone directory name (owner_repo)."""
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    parts = url.split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}_{parts[-1]}"
    return parts[-1]


def load_backup_results() -> list[dict]:
    """Load all cached CVE results from the backup directory.

    Returns raw dicts — callers should apply their own source/field filters.
    """
    if not BACKUP_DIR.exists():
        raise FileNotFoundError(f"Backup directory not found: {BACKUP_DIR}")

    results: list[dict] = []
    for path in BACKUP_DIR.glob("*.json"):
        try:
            results.append(json.loads(path.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return results


def build_candidates(
    *,
    exclude_sources: frozenset[str] = TAG_BASED_SOURCES | PR_BASED_SOURCES,
    require_description: bool = True,
    require_cloned_repo: bool = True,
    validate_commits: bool = True,
) -> tuple[list[dict], dict[str, int]]:
    """Build regression test candidates from backup cache.

    Returns (candidates, filter_stats) where filter_stats counts rejected
    commits by reason.

    Each candidate dict contains:
      - cve_id: str
      - description: str
      - cwes: list[str]
      - expected_shas: list[str]  (validated, good-quality fix SHAs)
      - repo_url: str
      - repo_path: str            (local clone path)
      - raw: dict                  (full cached result for extra field access)
    """
    raw_results = load_backup_results()
    candidates: list[dict] = []
    filter_stats: dict[str, int] = {}

    for data in raw_results:
        cve_id = data.get("cve_id", "")
        fix_commits = data.get("fix_commits", [])
        if not fix_commits:
            continue

        # Filter to reliable sources
        good_fcs = [
            fc for fc in fix_commits
            if fc.get("sha") and len(fc.get("sha", "")) >= 10
            and fc.get("source", "") not in exclude_sources
        ]
        if not good_fcs:
            continue

        # Need a repo URL
        repo_url = good_fcs[0].get("repo_url", "")
        if not repo_url:
            continue

        # Need a description
        description = data.get("description", "")
        if require_description and (not description or len(description) < 20):
            continue

        # Check if repo is cloned
        repo_name = repo_url_to_path(repo_url)
        repo_path = CLONE_DIR / repo_name
        if require_cloned_repo and not repo_path.exists():
            continue

        # Validate commit quality
        expected_shas = [fc["sha"] for fc in good_fcs]
        if validate_commits:
            reason = classify_commit(expected_shas[0], repo_path)
            if reason:
                filter_stats[reason] = filter_stats.get(reason, 0) + 1
                continue

        candidates.append({
            "cve_id": cve_id,
            "description": description,
            "cwes": data.get("cwes", []),
            "expected_shas": expected_shas,
            "repo_url": repo_url,
            "repo_path": str(repo_path),
            "raw": data,
        })

    return candidates, filter_stats


def sha_matches(
    got: str,
    expected_list: list[str],
    *,
    repo_path: str | Path | None = None,
) -> bool:
    """Check if a discovered SHA matches any expected SHA.

    Supports prefix-tolerant SHA comparison.  When *repo_path* is provided,
    also accepts cherry-pick equivalence: if *got* and an expected SHA have
    the same commit subject line, they're treated as a match (backport).
    """
    for exp in expected_list:
        if got == exp or got.startswith(exp[:12]) or exp.startswith(got[:12]):
            return True

    if repo_path is None:
        return False

    # Cherry-pick equivalence: compare subjects
    try:
        got_subj = subprocess.run(
            ["git", "-C", str(repo_path), "log", "-1", "--format=%s", got],
            capture_output=True, text=True, timeout=5,
        )
        if got_subj.returncode != 0 or not got_subj.stdout.strip():
            return False
        got_subject = got_subj.stdout.strip()

        for exp in expected_list:
            exp_subj = subprocess.run(
                ["git", "-C", str(repo_path), "log", "-1", "--format=%s", exp],
                capture_output=True, text=True, timeout=5,
            )
            if exp_subj.returncode == 0 and exp_subj.stdout.strip() == got_subject:
                return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Patch-ID match: same diff content across branches (cherry-picks/backports)
    try:
        got_pid = _get_patch_id(str(repo_path), got)
        if got_pid:
            for exp in expected_list:
                exp_pid = _get_patch_id(str(repo_path), exp)
                if exp_pid and got_pid == exp_pid:
                    return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    return False


def _get_patch_id(repo_path: str, sha: str) -> str | None:
    """Get patch-id for a commit (diff fingerprint, ignores whitespace/line numbers)."""
    r = subprocess.run(
        f"git -C {repo_path} diff-tree -p {sha} | git patch-id --stable",
        shell=True, capture_output=True, text=True, timeout=10,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip().split()[0]  # patch-id is first field
    return None


# -- Shared regression stats --

import threading
from dataclasses import dataclass, field


@dataclass
class RegressionStats:
    """Thread-safe regression test statistics."""
    found: int = 0
    correct: int = 0
    correct_at_1: int = 0
    wrong_commit: int = 0
    not_found: int = 0
    errors: int = 0
    completed: int = 0
    mismatches: list[tuple[str, str, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_correct(self, cve_id: str, sha: str, *, position: int = 0) -> None:
        with self._lock:
            self.found += 1
            self.correct += 1
            if position == 0:
                self.correct_at_1 += 1
            self.completed += 1

    def record_wrong(self, cve_id: str, expected: str, got: str) -> None:
        with self._lock:
            self.found += 1
            self.wrong_commit += 1
            self.mismatches.append((cve_id, expected, got))
            self.completed += 1

    def record_not_found(self) -> None:
        with self._lock:
            self.not_found += 1
            self.completed += 1

    def record_error(self) -> None:
        with self._lock:
            self.errors += 1
            self.completed += 1

    def print_report(self, label: str, elapsed: float) -> None:
        total = self.completed
        if not total:
            print("No results.")
            return
        print(f"\n{'='*60}")
        print(f"{label}: {total} CVEs tested in {elapsed:.1f}s ({elapsed/total:.1f}s/CVE)")
        print(f"  FOUND:        {self.found:3d} ({self.found*100//total}%)")
        if self.found:
            print(f"  CORRECT:      {self.correct:3d} ({self.correct*100//self.found}% precision)")
            print(f"  CORRECT@1:    {self.correct_at_1:3d} ({self.correct_at_1*100//self.found}% first-pos accuracy)")
        else:
            print(f"  CORRECT:        0")
        print(f"  WRONG_COMMIT: {self.wrong_commit:3d}")
        print(f"  NOT_FOUND:    {self.not_found:3d}")
        print(f"  ERRORS:       {self.errors:3d}")
        print(f"  Recall:       {self.correct*100//total}%")

        if self.mismatches:
            print(f"\nMismatches ({len(self.mismatches)}):")
            for cve_id, expected, got in self.mismatches[:20]:
                print(f"  {cve_id}: expected {expected}, got {got}")
            if len(self.mismatches) > 20:
                print(f"  ... and {len(self.mismatches) - 20} more")

    def check_thresholds(self, min_recall: float = 0.2, min_precision: float = 0.4) -> bool:
        """Return True if above thresholds, False otherwise."""
        total = self.completed
        if not total:
            return False
        recall = self.correct / total
        precision = self.correct / self.found if self.found else 0
        if recall < min_recall or precision < min_precision:
            print(f"\nBELOW THRESHOLD (recall={recall:.0%}, precision={precision:.0%})")
            return False
        return True
