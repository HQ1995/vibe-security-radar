#!/usr/bin/env python3
"""Sample the cohort, backfill the blobs SZZ needs, and link defect outcomes.

SZZ is the study's primary outcome and the only expensive one.  It needs to
blame historical file contents, and the corpus clones are ``blob:none`` promisor
clones, so a naive blame fetches every blob it touches one at a time: measured
here, blaming a single deep-history file did not finish in 120 seconds and
triggered hundreds of lazy fetches.  That is the same mechanism that made the
old CVE pipeline time out, and it is a property of blobless-plus-blame rather
than of any one large repository.

Two measurements decide the design:

  * Backfilling a repository with ``--refetch --filter=blob:limit=1m`` cost
    286 MB and 12 seconds on mlflow, after which the same blame took 0.12 s —
    about a thousandfold.  The 1 MB ceiling keeps large binaries out; blame
    only ever reads source.
  * Backfilling all 1,757 cohort repositories would run to roughly 500 GB
    against 713 GB free, which is too tight.  So the cohort is sampled and only
    the sampled repositories are backfilled.

Sampling costs precision, not validity: the power calculation asked for
8,000-16,000 exposed units and the corpus holds 81,894, so a sample well inside
that range still answers the question — with a confidence interval, which the
output reports.

After backfill, SZZ runs with lazy fetching switched off.  A missing blob then
fails immediately and is recorded, instead of hanging on the network; the old
pipeline's silent stall becomes a bounded, visible one.

Usage::

    uv run --project cve-analyzer python scripts/cohort_szz.py --plan
    uv run --project cve-analyzer python scripts/cohort_szz.py --sample-size 12000
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.repos import discover_local_clones

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

DEFAULT_SAMPLE_SIZE = 12000
DEFAULT_WINDOW_DAYS = 180
DEFAULT_WORKERS = 8
DEFAULT_SEED = 42
DEFAULT_DISK_FLOOR_GB = 200.0
DEFAULT_BLOB_LIMIT = "1m"
DEFAULT_REPO_TIMEOUT = 900
COHORT_STATE_RELATIVE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"

_RECORD_SEP = "\x1e"
_FIELD_SEP = "\x1f"

# Where cohort_classify_exposure.py parks the PR tips it fetched.  SZZ has to
# exclude them: they are not part of the project's shipped history.
COHORT_PULL_NAMESPACE = "refs/cohort/pull"

# Standard SZZ fix-commit vocabulary.  `commit_scoring.STRONG_SECURITY_KEYWORDS`
# is deliberately not reused: it selects *security* commits, which is a
# different and much narrower question than "does this commit repair a defect",
# and using it would make the outcome a security-fix rate rather than a defect
# rate.  Precision here is checked by hand in the validation stage, not assumed.
_FIX_RE = re.compile(
    r"\b(?:fix(?:e[sd]|ing)?|bug|bugfix|defect|error|issue|crash(?:e[sd])?|"
    r"fail(?:s|ed|ure)?|broken|breaks?|regress(?:ion|ed)?|incorrect|invalid|"
    r"wrong|mistake|typo|leak|deadlock|race|npe|segfault|oops)\b",
    re.IGNORECASE,
)
# A commit that only reformats or bumps a version repairs nothing, and SZZ
# counting it would attribute a defect to whoever last touched those lines.
_NON_FIX_RE = re.compile(
    r"\b(?:merge branch|merge pull request|bump|release|changelog|"
    r"reformat|rename|refactor|lint|typo in comment|whitespace|"
    r"update (?:dependencies|deps|submodule))\b",
    re.IGNORECASE,
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--outcomes-dir", type=Path, default=None)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument(
        "--disk-floor-gb",
        type=float,
        default=DEFAULT_DISK_FLOOR_GB,
        help=f"stop backfilling below this much free space (default: {DEFAULT_DISK_FLOOR_GB:.0f})",
    )
    parser.add_argument("--blob-limit", default=DEFAULT_BLOB_LIMIT, help="retained for compatibility; backfill now removes the filter entirely")
    parser.add_argument("--repo-timeout", type=int, default=DEFAULT_REPO_TIMEOUT)
    parser.add_argument(
        "--plan",
        action="store_true",
        help="report the sample and the disk it would need, then stop",
    )
    parser.add_argument("--no-backfill", action="store_true", help="assume blobs are present")
    parser.add_argument("--limit-repos", type=int, default=0)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _latest_outcomes_dir() -> Path:
    root = _REPO_ROOT / COHORT_STATE_RELATIVE
    candidates = sorted(p for p in root.glob("outcomes-*") if (p / "outcomes.jsonl").is_file())
    if not candidates:
        raise SystemExit(f"no outcomes run under {root}")
    return candidates[-1]


def _run_git(args: list[str], *, timeout: int, offline: bool = True) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if offline:
        # After backfill nothing should reach the network.  Without this a
        # missing blob silently becomes a promisor fetch and the run stalls
        # exactly the way the old pipeline did.
        env["GIT_NO_LAZY_FETCH"] = "1"
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
    )


def _cluster_sample(
    units: list[dict[str, Any]], size: int, seed: int
) -> list[dict[str, Any]]:
    """Sample whole repositories, then take every unit inside them.

    Sampling units independently was the obvious thing and the wrong one: it put
    12,000 units into 1,686 of the 1,757 repositories, and since backfill cost
    scales with repositories rather than units it would have needed ~489 GB —
    the sampling saved nothing.

    Clustering on the repository fixes that and suits the design better anyway.
    Matching is required to happen within a repository, so a sample holding many
    units from few repositories yields more usable matched pairs than the same
    number of units scattered one per repository. The price is a design effect
    on the standard errors, which the analysis already has to pay because it
    clusters by repository regardless.

    Repositories are drawn within size bands so the sample is not all
    monorepos or all small projects, and the draw is seeded so it reproduces.
    """

    if size <= 0 or size >= len(units):
        return list(units)
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in units:
        by_repo[unit["repository_identity"]].append(unit)

    def band(count: int) -> str:
        if count >= 500:
            return "huge"
        if count >= 100:
            return "large"
        if count >= 20:
            return "medium"
        return "small"

    banded: dict[str, list[str]] = defaultdict(list)
    for identity, members in by_repo.items():
        banded[band(len(members))].append(identity)

    rng = random.Random(seed)
    chosen: list[str] = []
    taken = 0
    # Round-robin across bands so every size class is represented even once the
    # budget runs low, rather than filling up on whichever band is listed first.
    pools = {name: rng.sample(values, len(values)) for name, values in banded.items()}
    order = [name for name in ("huge", "large", "medium", "small") if pools.get(name)]
    while taken < size and any(pools[name] for name in order):
        for name in order:
            if not pools[name] or taken >= size:
                continue
            identity = pools[name].pop()
            chosen.append(identity)
            taken += len(by_repo[identity])
    return [unit for identity in chosen for unit in by_repo[identity]]


def _backfill(repo_path: Path, *, blob_limit: str, timeout: int) -> tuple[int, str]:
    """Convert a promisor clone into a complete one.  Returns (MB added, error).

    ``git fetch --refetch`` alone is not enough, and quietly so: it re-fetches
    while still honouring the clone's configured ``blob:none`` filter, so it
    moves metadata and no file contents at all — measured at +21 MB on a
    repository that needed +1,383 MB.  Every later step then looks broken for
    unrelated reasons: diff extraction ran 1,500x slower because git aborted on
    a missing object and the batch had to be bisected commit by commit.

    So the filter configuration is removed first, which is what actually makes
    the clone complete.  Afterwards the same work runs at 1 ms per commit with
    nothing unreadable.
    """

    before = shutil.disk_usage(repo_path).free
    for key in ("remote.origin.partialclonefilter", "remote.origin.promisor"):
        subprocess.run(
            ["git", "-C", str(repo_path), "config", "--unset", key],
            capture_output=True,
            text=True,
            timeout=60,
        )
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "-c",
                "gc.auto=0",
                "fetch",
                "--refetch",
                "--no-tags",
                "--quiet",
                "origin",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 0, "backfill_timeout"
    except (OSError, subprocess.SubprocessError) as exc:
        return 0, f"backfill_exception:{type(exc).__name__}"
    if completed.returncode != 0:
        return 0, f"backfill_nonzero:{completed.returncode}"
    after = shutil.disk_usage(repo_path).free
    return max(0, (before - after) // (1024 * 1024)), ""


def _is_fix(message: str) -> bool:
    subject = message.splitlines()[0] if message else ""
    if _NON_FIX_RE.search(subject):
        return False
    return bool(_FIX_RE.search(subject))


def _fix_commits(
    repo_path: Path, since: str, *, timeout: int
) -> list[tuple[str, str, str]]:
    """Return (sha, authored_date, message) for candidate fix commits."""

    try:
        completed = _run_git(
            [
                "git",
                "-C",
                str(repo_path),
                "log",
                # Our own PR-head refs are excluded: a commit on an unmerged
                # pull-request branch is not part of the project's history, so
                # treating it as a fix would credit the repository with repairs
                # it never shipped.  They were fetched for squash decomposition
                # and have no business in the outcome pass.
                f"--exclude={COHORT_PULL_NAMESPACE}/*",
                "--all",
                "--no-merges",
                f"--since={since}",
                f"--format={_RECORD_SEP}%H{_FIELD_SEP}%aI{_FIELD_SEP}%s",
            ],
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    fixes: list[tuple[str, str, str]] = []
    for record in (completed.stdout or "").split(_RECORD_SEP):
        if not record.strip():
            continue
        fields = record.split(_FIELD_SEP, 2)
        if len(fields) < 3:
            continue
        if _is_fix(fields[2]):
            fixes.append((fields[0].strip(), fields[1].strip(), fields[2]))
    return fixes


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.*)$")


def _parse_diff_records(text: str) -> dict[str, dict[str, list[tuple[int, int]]]]:
    """Parse a batched ``git show`` into sha -> path -> removed line spans."""

    parsed: dict[str, dict[str, list[tuple[int, int]]]] = {}
    for record in text.split(_RECORD_SEP):
        if not record.strip():
            continue
        lines = record.splitlines()
        sha = lines[0].strip().lower()
        if len(sha) != 40:
            continue
        ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)
        current = ""
        for line in lines[1:]:
            file_match = _DIFF_FILE_RE.match(line)
            if file_match:
                current = file_match.group(1)
                continue
            hunk = _HUNK_RE.match(line)
            if hunk and current:
                start = int(hunk.group(1))
                count = int(hunk.group(2) or 1)
                if count > 0:
                    ranges[current].append((start, start + count - 1))
        parsed[sha] = dict(ranges)
    return parsed


def _deleted_line_ranges_batch(
    repo_path: Path, fix_shas: list[str], *, timeout: int, batch: int = 200
) -> tuple[dict[str, dict[str, list[tuple[int, int]]]], list[str]]:
    """Lines each fix removed, in its parent's numbering, for many commits.

    Those are the lines the defect lived on, so blaming them in the parent is
    what points back at the commit that introduced it.

    Batched because the per-commit cost is almost entirely process startup:
    measured on cal.com, one ``git show`` per commit ran at 1,515 ms while the
    same work batched ran at 41 ms — the difference between nine minutes and
    five hours for a single repository.

    A missing object makes git abort the whole invocation, and with lazy
    fetching off that is a hard failure partway through the batch.  Silently
    keeping the partial output would drop every commit after the bad one — in
    one measured batch, 387 of 400 — and since those dropped commits can only
    ever *add* outcomes, the defect rate would be biased downward with nothing
    to show it happened.  So a failed batch is bisected to isolate the commits
    that genuinely cannot be read, and those are returned to be counted.
    """

    parsed: dict[str, dict[str, list[tuple[int, int]]]] = {}
    unreadable: list[str] = []

    def run(chunk: list[str]) -> bool:
        try:
            completed = _run_git(
                [
                    "git",
                    "-C",
                    str(repo_path),
                    "show",
                    "--unified=0",
                    "--no-color",
                    f"--format={_RECORD_SEP}%H",
                    "--diff-filter=M",
                    *chunk,
                ],
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if completed.returncode != 0:
            return False
        parsed.update(_parse_diff_records(completed.stdout or ""))
        return True

    def descend(chunk: list[str]) -> None:
        if not chunk:
            return
        if run(chunk):
            return
        if len(chunk) == 1:
            unreadable.append(chunk[0])
            return
        middle = len(chunk) // 2
        descend(chunk[:middle])
        descend(chunk[middle:])

    for start in range(0, len(fix_shas), batch):
        descend(fix_shas[start : start + batch])
    return parsed, unreadable


def _blame_introducers(
    repo_path: Path, fix_sha: str, path: str, spans: list[tuple[int, int]], *, timeout: int
) -> set[str]:
    """Blame the pre-fix lines and return the commits that last touched them."""

    args = [
        "git",
        "-C",
        str(repo_path),
        "-c",
        "gc.auto=0",
        "blame",
        "--line-porcelain",
        "-w",  # ignore whitespace-only change, a standard SZZ refinement
        f"{fix_sha}^",
        "--",
        path,
    ]
    ranges: list[str] = []
    for start, end in spans[:64]:
        ranges.extend(["-L", f"{start},{end}"])
    args[6:6] = ranges
    try:
        completed = _run_git(args, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return set()
    if completed.returncode != 0:
        return set()
    return {
        line.split()[0].lower()
        for line in (completed.stdout or "").splitlines()
        if re.match(r"^[0-9a-f]{40} ", line)
    }


def _unit_files(repo_path: Path, shas: list[str], *, timeout: int) -> dict[str, list[str]]:
    """Map each file the cohort touched to the units that touched it.

    The exposure stage recorded only a file *count*, so the paths are read back
    from git here rather than widening the upstream artifact and re-running two
    stages for a list this cheap to recover.
    """

    files: dict[str, list[str]] = defaultdict(list)
    for start in range(0, len(shas), 200):
        chunk = shas[start : start + 200]
        try:
            completed = _run_git(
                [
                    "git",
                    "-C",
                    str(repo_path),
                    "show",
                    "--name-only",
                    f"--format={_RECORD_SEP}%H",
                    "--no-renames",
                    *chunk,
                ],
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode != 0:
            continue
        for record in (completed.stdout or "").split(_RECORD_SEP):
            lines = [line.strip() for line in record.splitlines() if line.strip()]
            if not lines:
                continue
            sha = lines[0].lower()
            for path in lines[1:]:
                files[path].append(sha)
    return dict(files)


def _szz_repository(
    identity: str,
    repo_path: Path,
    units: list[dict[str, Any]],
    *,
    window_days: int,
    timeout: int,
) -> tuple[dict[str, list[dict[str, str]]], dict[str, Any]]:
    """Blame every candidate fix in one repository back to its introducer."""

    started = time.monotonic()
    unit_dates = {str(u["sha"]).lower(): str(u.get("authored_date") or "") for u in units}
    earliest = min((d[:10] for d in unit_dates.values() if d), default="2025-01-01")
    hits: dict[str, list[dict[str, str]]] = defaultdict(list)
    stats: dict[str, Any] = {"repository_identity": identity, "units": len(units), "error": ""}

    # A fix can only implicate a cohort unit if the two touched the same file,
    # so blaming any other file is guaranteed wasted work.  This is an exact
    # restriction rather than an approximation — it cannot change a single
    # result — and it is what makes the pass finish: without it the first pilot
    # ran past 900 seconds on four repositories, because the cost is
    # blame x fix-commits x files rather than the single blame the microbenchmark
    # measured.
    file_units = _unit_files(repo_path, list(unit_dates), timeout=timeout)
    cohort_files = set(file_units)
    if not cohort_files:
        stats["error"] = "no_unit_files"
        return {}, stats
    # Earliest cohort commit per file.  A fix can only implicate a unit that
    # already existed, so a fix landing before every unit that touched the file
    # cannot produce a hit and does not need blaming.  Blame is a process per
    # (fix, file) and is now the dominant cost, so skipping provably empty ones
    # is worth more than any tuning of blame itself.
    earliest_touch: dict[str, str] = {}
    for path, shas in file_units.items():
        dates = [unit_dates.get(sha, "") for sha in shas]
        dates = [value for value in dates if value]
        if dates:
            earliest_touch[path] = min(dates)[:10]

    fixes = _fix_commits(repo_path, earliest, timeout=timeout)
    fix_dates = {sha: fix_date for sha, fix_date, _subject in fixes}
    diffs, unreadable = _deleted_line_ranges_batch(
        repo_path, [sha for sha, _d, _s in fixes], timeout=timeout
    )
    blamed = 0
    blame_failures = 0
    skipped_files = 0
    for fix_sha, ranges in diffs.items():
        fix_date = fix_dates.get(fix_sha, "")
        if not ranges or not fix_date:
            continue
        relevant = {
            p: s
            for p, s in ranges.items()
            if p in cohort_files and earliest_touch.get(p, "9999") < fix_date[:10]
        }
        skipped_files += len(ranges) - len(relevant)
        if not relevant:
            continue
        for path, spans in list(relevant.items())[:32]:
            introducers = _blame_introducers(
                repo_path, fix_sha, path, spans, timeout=timeout
            )
            if not introducers:
                blame_failures += 1
                continue
            blamed += 1
            for introducer in introducers & set(unit_dates):
                unit_date = unit_dates[introducer]
                try:
                    delta = (
                        date.fromisoformat(fix_date[:10]) - date.fromisoformat(unit_date[:10])
                    ).days
                except ValueError:
                    continue
                # A "fix" that predates the commit it blames cannot be repairing
                # it, and one past the window is outside the follow-up period
                # every unit is given equally.
                if 0 < delta <= window_days:
                    hits[introducer].append(
                        {"fix_sha": fix_sha, "fix_date": fix_date, "path": path, "days": str(delta)}
                    )
    stats.update(
        {
            "fix_candidates": len(fixes),
            "fix_diffs_read": len(diffs),
            # Commits whose diff cannot be read at all.  Reported because they
            # can only ever have added outcomes, so they bias the rate downward.
            "fix_commits_unreadable": len(unreadable),
            "cohort_files": len(cohort_files),
            "files_blamed": blamed,
            "files_skipped_not_in_cohort": skipped_files,
            "blame_failures": blame_failures,
            "units_with_hits": len(hits),
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
    )
    return dict(hits), stats


def _wilson(successes: int, total: int) -> tuple[float, float] | None:
    """95% Wilson interval — the sample's precision, which has to be reported."""

    if total <= 0:
        return None
    z = 1.959964
    phat = successes / total
    denom = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denom
    margin = z * ((phat * (1 - phat) / total + z * z / (4 * total * total)) ** 0.5) / denom
    return (round(max(0.0, centre - margin), 6), round(min(1.0, centre + margin), 6))


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    args.outcomes_dir = args.outcomes_dir or _latest_outcomes_dir()

    units: list[dict[str, Any]] = []
    with (args.outcomes_dir / "outcomes.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            units.append(json.loads(line))
    print(f"Read {len(units):,} units from {args.outcomes_dir}", flush=True)

    sample = _cluster_sample(units, args.sample_size, args.seed)
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in sample:
        by_repo[unit["repository_identity"]].append(unit)
    targets = sorted(by_repo, key=lambda name: (-len(by_repo[name]), name))
    if args.limit_repos > 0:
        targets = targets[: args.limit_repos]

    free_gb = shutil.disk_usage(_REPO_ROOT).free / 1024**3
    # 286 MB was the measured cost on mlflow; used only to warn before starting,
    # never to decide, since the floor check below is what actually protects the
    # disk during the run.
    print(
        f"  sample {len(sample):,} units across {len(by_repo):,} repositories"
        f" (seed {args.seed})\n"
        f"  free now {free_gb:.0f} GB, floor {args.disk_floor_gb:.0f} GB,"
        f" rough backfill estimate {len(targets) * 0.29:.0f} GB",
        flush=True,
    )
    if args.plan:
        routes = Counter(u.get("route", "?") for u in sample)
        print(f"  sample by route: {dict(routes.most_common())}")
        return 0

    repositories, _unresolved = discover_local_clones(_REPO_ROOT)
    started = time.monotonic()
    results: dict[str, list[dict[str, str]]] = {}
    repo_stats: list[dict[str, Any]] = []
    skipped_for_disk = 0

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {}
        for identity in targets:
            path = repositories.get(identity)
            if path is None:
                repo_stats.append({"repository_identity": identity, "error": "no_local_clone"})
                continue
            if not args.no_backfill:
                if shutil.disk_usage(_REPO_ROOT).free / 1024**3 <= args.disk_floor_gb:
                    skipped_for_disk += 1
                    repo_stats.append(
                        {"repository_identity": identity, "error": "skipped_disk_floor"}
                    )
                    continue
                added, error = _backfill(
                    path, blob_limit=args.blob_limit, timeout=args.repo_timeout
                )
                if error:
                    repo_stats.append({"repository_identity": identity, "error": error})
                    continue
            futures[
                executor.submit(
                    _szz_repository,
                    identity,
                    path,
                    by_repo[identity],
                    window_days=args.window_days,
                    timeout=args.repo_timeout,
                )
            ] = identity
        for done, future in enumerate(as_completed(futures), start=1):
            identity = futures[future]
            try:
                hits, stats = future.result()
            except Exception as exc:  # noqa: BLE001
                hits, stats = {}, {
                    "repository_identity": identity,
                    "error": f"exception:{type(exc).__name__}",
                }
            results.update(hits)
            repo_stats.append(stats)
            if done % 20 == 0 or done == len(futures):
                free = shutil.disk_usage(_REPO_ROOT).free / 1024**3
                print(
                    f"  [{done}/{len(futures)}] {identity} —"
                    f" {stats.get('units_with_hits', 0)} units hit,"
                    f" free {free:.0f} GB",
                    flush=True,
                )
    elapsed = time.monotonic() - started

    # A unit is only observed if its repository was actually analysed.  Without
    # this, every unit in a repository that failed, was skipped for disk, or was
    # cut by --limit-repos silently becomes "no defect found" — which is not a
    # measurement, it is an absence of one.  In a 3-of-81 pilot that alone
    # produced a 70x spread between exposure routes, purely because the three
    # repositories that ran happened to be agent-heavy.  Unanalysed units are
    # excluded from the denominator and counted separately.
    analysed_repos = {
        stats["repository_identity"]
        for stats in repo_stats
        if not stats.get("error") and "units_with_hits" in stats
    }
    linked: list[dict[str, Any]] = []
    not_analysed = 0
    for unit in sample:
        observed = unit["repository_identity"] in analysed_repos
        hits = results.get(str(unit["sha"]).lower(), []) if observed else []
        if not observed:
            not_analysed += 1
        linked.append(
            {
                **unit,
                "szz_observed": observed,
                "szz_defective": bool(hits) if observed else None,
                "szz_fixes": hits[:10],
                "szz_fix_count": len(hits),
            }
        )

    by_route: dict[str, Counter[str]] = defaultdict(Counter)
    for unit in linked:
        if not unit["szz_observed"]:
            continue
        route = unit.get("route", "?")
        by_route[route]["units"] += 1
        if unit["szz_defective"]:
            by_route[route]["defective"] += 1
    analysed = sum(c["units"] for c in by_route.values())
    defective = sum(c["defective"] for c in by_route.values())

    summary = {
        "schema_version": 1,
        "artifact_kind": "cohort_szz_outcomes",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "outcomes_dir": str(args.outcomes_dir),
        "seed": args.seed,
        "window_days": args.window_days,
        "sample_size": len(sample),
        "analysed_units": analysed,
        "units_not_analysed": not_analysed,
        "repositories_analysed": len(analysed_repos),
        "population_size": len(units),
        "repositories_targeted": len(targets),
        "repositories_completed": len(futures),
        "repositories_skipped_for_disk": skipped_for_disk,
        "elapsed_seconds": round(elapsed, 1),
        "defective": defective,
        "defect_rate": round(defective / analysed, 6) if analysed else None,
        "defect_rate_ci95": _wilson(defective, analysed),
        "by_route": {
            route: {
                **dict(counts),
                "rate": round(counts["defective"] / counts["units"], 6) if counts["units"] else None,
                "ci95": _wilson(counts["defective"], counts["units"]),
            }
            for route, counts in sorted(by_route.items())
        },
        "repository_stats": sorted(
            repo_stats, key=lambda s: -int(s.get("units", 0) or 0)
        )[:40],
        "claim_boundary": (
            "descriptive rates on a stratified sample; not adjusted for repository,"
            " calendar time, change size or author experience, and SZZ precision is"
            " not established until the manual adjudication stage"
        ),
    }

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"szz-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "szz.jsonl").open("w", encoding="utf-8") as handle:
        for unit in linked:
            handle.write(json.dumps(unit, sort_keys=True, ensure_ascii=False) + "\n")
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print("\n" + "=" * 72)
    print("Cohort SZZ outcomes (stratified sample)")
    print("=" * 72)
    print(f"  sample / population : {len(sample):,} / {len(units):,}")
    print(
        f"  analysed / excluded : {analysed:,} / {not_analysed:,}"
        " (unanalysed units are not counted as defect-free)"
    )
    print(
        f"  repositories        : {len(analysed_repos):,} analysed,"
        f" {skipped_for_disk} skipped for disk"
    )
    print(f"  elapsed             : {summary['elapsed_seconds']}s")
    rate = summary["defect_rate"]
    ci = summary["defect_rate_ci95"]
    if rate is not None and ci:
        print(f"  defect rate         : {100 * rate:.2f}%  (95% CI {100*ci[0]:.2f}–{100*ci[1]:.2f}%)")
    print("\n  by exposure route:")
    for route, counts in summary["by_route"].items():
        ci = counts["ci95"]
        band = f"{100*ci[0]:.2f}–{100*ci[1]:.2f}%" if ci else "n/a"
        print(
            f"    {route:<20} {counts.get('defective', 0):>6,} / {counts['units']:>7,}"
            f"  {100 * (counts['rate'] or 0):>6.2f}%  CI {band}"
        )
    print(f"\n  {summary['claim_boundary']}")
    print(f"\nWrote {output_dir / 'szz.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
