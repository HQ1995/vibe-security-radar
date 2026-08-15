#!/usr/bin/env python3
"""Build the cohort sampling frame: repositories with a published advisory.

The frame is every repository carrying at least one advisory published since
the cutoff.  That is a *repository-level* filter, orthogonal to which commits
inside a repository were AI-assisted, so it leaves the within-repository
AI-versus-human contrast unbiased.  It does narrow what the study generalises
to — actively maintained projects with a security disclosure practice — and
that scope has to be stated in anything published from it.

The one thing this must never do is select repositories on *AI-introduced*
advisories.  That would condition on exposure and outcome jointly and turn the
result into a circular argument.  Only the advisory count matters here; the AI
side is measured afterwards, by `cohort_scan_ai_commits.py`.

Subcommands::

    enumerate   scan the local OSV bulk archives -> advisory repo index
    plan        report disk projection and what cloning would do
    clone       blobless-clone frame members until the disk budget is spent
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import statistics
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.commit_urls import parse_foreign_commit_url
from cohort.repos import clone_url, directory_size_mb, discover_local_clones

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent

COHORT_STATE = Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"
DEFAULT_CUTOFF = "2025-05-01"
DEFAULT_OSV_DIR = Path.home() / ".cache" / "cve-analyzer" / "osv-bulk"
# Leave room for the blobs that blame/SZZ will lazily fetch later.
DEFAULT_DISK_FLOOR_GB = 150.0
DEFAULT_MAX_REPO_GB = 8.0
DEFAULT_SIZE_SAMPLE = 300
_PUBLIC_ID_RE = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[0-9A-Za-z-]+)$", re.IGNORECASE)


def _index_path(state_root: Path, cutoff: str, until: str = "") -> Path:
    suffix = f"-through-{until}" if until else ""
    return state_root / f"advisory-repos-since-{cutoff}{suffix}.json"


def _public_ids(record: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(value).upper()
            for value in (record.get("id"), *(record.get("aliases") or []))
            if _PUBLIC_ID_RE.fullmatch(str(value or ""))
        }
    )


# ---------------------------------------------------------------- enumerate


def _record_repositories(record: dict[str, Any]) -> set[str]:
    """Return the source repositories an OSV record actually names.

    The two URL sources need different strictness. A GIT range's ``repo`` field
    is authoritative by OSV semantics, so it can be canonicalised directly.
    Reference URLs cannot: most of them are advisory pages, and the permissive
    canonicaliser happily turns ``nvd.nist.gov/vuln/detail/CVE-...`` into a
    "repository". Measured on the local archives, accepting references
    indiscriminately inflated the frame from 7.6k repositories to 213k, led by
    32,760 phantom repos on nvd.nist.gov alone. ``parse_repo_url`` only matches
    known code hosts and already strips browsing suffixes like ``/commit/<sha>``,
    which also collapses the 43,730 per-commit git.kernel.org URLs.
    """

    from cve_analyzer.git_url import parse_repo_url
    from cve_analyzer.models import canonical_repository_identity

    found: set[str] = set()
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for entry in affected.get("ranges") or []:
            if isinstance(entry, dict) and entry.get("type") == "GIT" and entry.get("repo"):
                identity = canonical_repository_identity(str(entry["repo"]))
                if identity:
                    found.add(identity)
    for reference in record.get("references") or []:
        if not isinstance(reference, dict) or not reference.get("url"):
            continue
        url = str(reference["url"])
        parsed = parse_repo_url(url)
        if parsed is not None:
            host, owner, repo = parsed
            found.add(f"{host}/{owner}/{repo}".casefold())
            continue
        # Linux/GNU projects usually reach OSV through distro advisories whose
        # only code pointer is a cgit/gitweb/gitiles link the analyzer's parser
        # does not know; without this they drop out of the frame entirely.
        foreign = parse_foreign_commit_url(url)
        if foreign is not None:
            found.add(foreign[0])
    return found


def cmd_enumerate(args: argparse.Namespace) -> int:
    osv_dir: Path = args.osv_dir
    if not osv_dir.is_dir():
        print(f"OSV bulk directory not found: {osv_dir}", file=sys.stderr)
        return 2
    archives = sorted(p for p in osv_dir.iterdir() if p.suffix == ".zip")
    if not archives:
        print(f"No OSV archives under {osv_dir}", file=sys.stderr)
        return 2

    repo_advisories: dict[str, set[str]] = {}
    scanned = 0
    unreadable: list[str] = []
    missing_publication_date = 0
    for archive in archives:
        try:
            handle = zipfile.ZipFile(archive)
        except (OSError, zipfile.BadZipFile) as exc:
            unreadable.append(f"{archive.name}: {type(exc).__name__}")
            continue
        with handle:
            for member in handle.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    record = json.loads(handle.read(member))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    continue
                if not isinstance(record, dict):
                    continue
                scanned += 1
                public_ids = _public_ids(record)
                if not public_ids:
                    continue
                published = str(record.get("published") or "")[:10]
                if not published:
                    missing_publication_date += 1
                    continue
                if published < args.cutoff or (args.until and published > args.until):
                    continue
                for identity in _record_repositories(record):
                    repo_advisories.setdefault(identity, set()).update(public_ids)
        print(f"  scanned {archive.name}", flush=True)

    payload = {
        "schema_version": 1,
        "artifact_kind": "cohort_advisory_repo_index",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cutoff": args.cutoff,
        "until": args.until,
        "osv_records_scanned": scanned,
        "public_records_missing_publication_date": missing_publication_date,
        "unreadable_archives": unreadable,
        "repositories": {k: sorted(v) for k, v in sorted(repo_advisories.items())},
    }
    out = _index_path(args.state_root, args.cutoff, args.until)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"\nOSV records scanned      : {scanned}")
    print(f"repos with >=1 advisory  : {len(repo_advisories)}")
    for threshold in (2, 3, 5, 10):
        n = sum(1 for v in repo_advisories.values() if len(v) >= threshold)
        print(f"  with >={threshold:>2} advisories     : {n}")
    if unreadable:
        print(f"unreadable archives      : {unreadable}")
    print(f"\nWrote {out}")
    return 0


# --------------------------------------------------------------------- plan


def _load_frame(state_root: Path, cutoff: str, until: str = "") -> dict[str, list[str]]:
    path = _index_path(state_root, cutoff, until)
    if not path.is_file():
        raise SystemExit(f"advisory index missing: {path}\nRun `enumerate` first.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["repositories"]


def _ranked_targets(
    frame: dict[str, list[str]], cloned: dict[str, Path], min_advisories: int
) -> list[tuple[str, int]]:
    """Frame members not yet cloned, most-advisories first (ties broken by name)."""

    pending = [
        (identity, len(ids))
        for identity, ids in frame.items()
        if len(ids) >= min_advisories and identity not in cloned
    ]
    pending.sort(key=lambda item: (-item[1], item[0]))
    return pending


def cmd_plan(args: argparse.Namespace) -> int:
    frame = _load_frame(args.state_root, args.cutoff, args.until)
    cloned, unresolved = discover_local_clones(_REPO_ROOT)

    # A random sample is enough to estimate median/mean size; walking every
    # clone with `du` does not scale as the corpus grows into the thousands,
    # and the disk projection only needs a stable estimate, not an exact sum.
    sample_paths = random.sample(list(cloned.values()), min(args.size_sample, len(cloned)))
    with ThreadPoolExecutor(max_workers=16) as executor:
        sizes = sorted(executor.map(directory_size_mb, sample_paths))
    median = statistics.median(sizes) if sizes else 0.0
    mean = statistics.mean(sizes) if sizes else 0.0
    usage = shutil.disk_usage(_REPO_ROOT)

    print(f"frame cutoff                 : {args.cutoff}")
    print(f"frame size (>=1 advisory)    : {len(frame)}")
    print(f"local clones                 : {len(cloned)} ({len(unresolved)} unidentifiable)")
    print(f"  already inside the frame   : {len(set(frame) & set(cloned))}")
    print(f"clone size MiB               : median {median:.0f}  mean {mean:.0f}")
    print(f"disk free                    : {usage.free / 1024**3:.0f} GB")
    print(f"disk floor                   : {args.disk_floor_gb:.0f} GB")
    print(f"\n{'min adv':>8}{'in frame':>10}{'to clone':>10}{'~GB median':>12}{'~GB mean':>10}")
    for threshold in (1, 2, 3, 5, 10):
        in_frame = sum(1 for ids in frame.values() if len(ids) >= threshold)
        todo = len(_ranked_targets(frame, cloned, threshold))
        print(
            f"{threshold:>8}{in_frame:>10}{todo:>10}"
            f"{todo * median / 1024:>12.0f}{todo * mean / 1024:>10.0f}"
        )
    return 0


# -------------------------------------------------------------------- clone


def _clone_one(identity: str, advisories: int, max_repo_gb: float) -> dict[str, Any]:
    from cve_analyzer.git_ops import clone_repo

    row: dict[str, Any] = {"repository_identity": identity, "advisories": advisories}
    try:
        # shallow_since=None: measured, --shallow-since saves ~13% on a blobless
        # clone while losing non-default-branch commits, and SZZ needs the history.
        path = clone_repo(clone_url(identity), shallow_since=None)
    except Exception as exc:  # noqa: BLE001 - one bad remote must not stop the sweep
        row.update(status="error", reason=f"{type(exc).__name__}")
        return row
    if path is None:
        row.update(status="error", reason="clone_failed")
        return row
    size_mb = directory_size_mb(path)
    row.update(status="cloned", path=str(path), size_mb=round(size_mb, 1))
    if size_mb / 1024 > max_repo_gb:
        row.update(status="oversize_kept", reason=f"{size_mb / 1024:.1f} GB > {max_repo_gb} GB")
    return row


def cmd_clone(args: argparse.Namespace) -> int:
    frame = _load_frame(args.state_root, args.cutoff, args.until)
    cloned, _unresolved = discover_local_clones(_REPO_ROOT)
    targets = _ranked_targets(frame, cloned, args.min_advisories)
    if args.limit > 0:
        targets = targets[: args.limit]
    if not targets:
        print("Nothing to clone; frame is already fully cloned.")
        return 0

    # Land new clones beside the existing project-local ones.
    cache_root = data_refresh_paths.shared_analyzer_cache_root(_REPO_ROOT)
    os.environ.setdefault("CVE_ANALYZER_REPOSITORY_CACHE_ROOT", str(cache_root))
    os.environ.setdefault("CVE_GIT_CONCURRENCY", str(max(1, args.workers)))

    print(f"cloning up to {len(targets)} repositories, floor {args.disk_floor_gb:.0f} GB")
    results: list[dict[str, Any]] = []
    stopped_for_disk = False
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        pending = iter(targets)
        futures = {}
        for identity, advisories in pending:
            free_gb = shutil.disk_usage(_REPO_ROOT).free / 1024**3
            if free_gb < args.disk_floor_gb:
                stopped_for_disk = True
                break
            futures[executor.submit(_clone_one, identity, advisories, args.max_repo_gb)] = identity
            if len(futures) < args.workers * 4:
                continue
            for future in as_completed(list(futures)):
                results.append(future.result())
                del futures[future]
                break
        for future in as_completed(futures):
            results.append(future.result())

    for index, row in enumerate(sorted(results, key=lambda r: r["repository_identity"]), start=1):
        marker = "ok" if row["status"] == "cloned" else row["status"].upper()
        detail = row.get("reason", f"{row.get('size_mb', 0)} MiB")
        print(f"  [{index}/{len(results)}] {row['repository_identity']} — {marker} ({detail})")

    remaining = len(targets) - len(results)
    manifest = {
        "schema_version": 1,
        "artifact_kind": "cohort_frame_clone_manifest",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cutoff": args.cutoff,
        "min_advisories": args.min_advisories,
        "attempted": len(results),
        "cloned": sum(1 for r in results if r["status"] in {"cloned", "oversize_kept"}),
        "errors": sum(1 for r in results if r["status"] == "error"),
        "stopped_for_disk": stopped_for_disk,
        "not_attempted": max(0, remaining),
        "disk_free_gb_after": round(shutil.disk_usage(_REPO_ROOT).free / 1024**3, 1),
        "results": sorted(results, key=lambda r: r["repository_identity"]),
    }
    out = args.state_root / f"frame-clone-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"\ncloned {manifest['cloned']} / attempted {manifest['attempted']}")
    print(f"errors {manifest['errors']}, not attempted {manifest['not_attempted']}")
    if stopped_for_disk:
        print("STOPPED: disk floor reached — rerun after freeing space to continue")
    print(f"disk free now: {manifest['disk_free_gb_after']} GB")
    print(f"Wrote {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cutoff", default=DEFAULT_CUTOFF, help="advisory publication cutoff")
    parser.add_argument("--until", default="", help="inclusive advisory publication end date")
    parser.add_argument(
        "--state-root",
        type=Path,
        default=_REPO_ROOT / COHORT_STATE,
        help="where cohort artifacts live",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_enum = sub.add_parser("enumerate", help="scan local OSV archives for advisory repos")
    p_enum.add_argument("--osv-dir", type=Path, default=DEFAULT_OSV_DIR)
    p_enum.set_defaults(func=cmd_enumerate)

    p_plan = sub.add_parser("plan", help="report disk projection without cloning")
    p_plan.add_argument("--disk-floor-gb", type=float, default=DEFAULT_DISK_FLOOR_GB)
    p_plan.add_argument("--size-sample", type=int, default=DEFAULT_SIZE_SAMPLE)
    p_plan.set_defaults(func=cmd_plan)

    p_clone = sub.add_parser("clone", help="clone frame members within the disk budget")
    p_clone.add_argument("--min-advisories", type=int, default=1)
    p_clone.add_argument("--limit", type=int, default=0, help="cap attempts (0 = no cap)")
    p_clone.add_argument("--workers", type=int, default=8)
    p_clone.add_argument("--disk-floor-gb", type=float, default=DEFAULT_DISK_FLOOR_GB)
    p_clone.add_argument("--max-repo-gb", type=float, default=DEFAULT_MAX_REPO_GB)
    p_clone.set_defaults(func=cmd_clone)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
