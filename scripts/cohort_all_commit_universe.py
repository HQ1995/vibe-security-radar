#!/usr/bin/env python3
"""Materialize every local commit for a frozen prospective advisory batch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cohort.all_commit_universe import (
    AllCommitUniverseContractError,
    build_repository_fallbacks,
    build_repository_universe,
    canonical_sha256,
)
from cohort.relations import canonical_repository_identity, normalize_repository_aliases
from cohort.repos import cache_roots, clone_identity
from cve_analyzer.git_ops import run_git


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_OUTCOMES = (
    _REPO_ROOT
    / ".ai-slop/state/cohort-v1/outcomes-20260727T032754Z/outcomes.jsonl"
)
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake-dir", type=Path, required=True)
    parser.add_argument("--outcomes", type=Path, default=DEFAULT_OUTCOMES)
    parser.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--repo-timeout", type=int, default=600)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON {path}: {exc}") from exc


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise SystemExit(f"{path}:{line_number}: row is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSONL {path}: {exc}") from exc
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _jsonl_text(rows: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    )


def _aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    rows = payload.get("aliases") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(rows, list)
    ):
        raise SystemExit("repository aliases are malformed")
    try:
        return normalize_repository_aliases(rows)
    except ValueError as exc:
        raise SystemExit(f"repository aliases are malformed: {exc}") from exc


def _selected_rows(intake_dir: Path) -> tuple[dict[str, object], list[dict[str, object]]]:
    intake = _load_json(intake_dir / "intake.json")
    rows = _load_jsonl(intake_dir / "selected.jsonl")
    if not isinstance(intake, dict):
        raise SystemExit("intake payload is not an object")
    if intake.get("gate_status") != "READY_FOR_HISTORY_ENUMERATION":
        raise SystemExit("prospective intake is not ready for history enumeration")
    if intake.get("selected") != rows:
        raise SystemExit("selected.jsonl does not match the frozen intake payload")
    if intake.get("selected_repository_count") != len(rows):
        raise SystemExit("prospective intake selected count is inconsistent")
    repositories = [str(row.get("repository_identity") or "") for row in rows]
    if len(repositories) != len(set(repositories)):
        raise SystemExit("prospective intake is not repository-disjoint")
    return intake, rows


def _fast_clone_candidates(root: Path, identity: str) -> list[Path]:
    parts = identity.split("/")
    names = {
        identity.replace("/", "_"),
        "_".join(parts[1:]),
    }
    return [root / name for name in sorted(names)]


def _selected_clone_candidates(identities: set[str]) -> dict[str, list[Path]]:
    resolved: dict[str, list[Path]] = defaultdict(list)
    for _label, root in cache_roots(_REPO_ROOT):
        if not root.is_dir():
            continue
        fast_paths: set[Path] = set()
        for identity in sorted(identities):
            for candidate in _fast_clone_candidates(root, identity):
                fast_paths.add(candidate)
                if (
                    candidate.is_dir()
                    and (candidate / ".git").exists()
                    and clone_identity(candidate) == identity
                ):
                    resolved[identity].append(candidate)
        # Opaque v2 cache names cannot be mapped without asking the clone.  Scan
        # those only; direct legacy names were handled above.
        for candidate in sorted(root.glob("v2_*")):
            if candidate in fast_paths:
                continue
            if not candidate.is_dir() or not (candidate / ".git").exists():
                continue
            identity = clone_identity(candidate)
            if identity in identities:
                resolved[identity].append(candidate)
    return {
        identity: sorted(set(paths), key=lambda path: str(path))
        for identity, paths in sorted(resolved.items())
    }


def _git_output(
    repo_path: Path,
    arguments: list[str],
    timeout: int,
    *,
    global_arguments: list[str] | None = None,
) -> tuple[str, str]:
    try:
        completed = run_git(
            [
                "git",
                "-C",
                str(repo_path),
                *(global_arguments or []),
                *arguments,
            ],
            capture_output=True,
            encoding="ascii",
            errors="replace",
            timeout=timeout,
            no_lazy_fetch=True,
        )
    except Exception as exc:  # noqa: BLE001 - becomes an auditable BLOCKED reason
        return "", f"git_{arguments[0]}_exception:{type(exc).__name__}"
    if completed.returncode != 0:
        return "", f"git_{arguments[0]}_nonzero:{completed.returncode}"
    return str(completed.stdout or ""), ""


def _enumerate_history(
    identity: str,
    repo_path: Path | None,
    *,
    timeout: int,
) -> tuple[list[dict[str, object]], str, list[str], dict[str, object]]:
    if repo_path is None:
        return [], "0" * 64, ["no_local_clone"], {"repository_identity": identity}
    reasons: list[str] = []
    shallow, error = _git_output(
        repo_path, ["rev-parse", "--is-shallow-repository"], min(timeout, 30)
    )
    shallow_marker_present = False
    if error:
        reasons.append(error)
    elif shallow.strip() != "false":
        shallow_marker_present = True

    refs, refs_error = _git_output(
        repo_path,
        ["for-each-ref", "--format=%(refname)%00%(objectname)"],
        min(timeout, 120),
    )
    if refs_error:
        reasons.append(refs_error)
    refs_lines = sorted(line for line in refs.splitlines() if line)
    refs_sha256 = canonical_sha256(refs_lines)

    history_view = "declared_repository_graph"
    history = ""
    history_error = ""
    if shallow_marker_present:
        history, history_error = _git_output(
            repo_path,
            ["rev-list", "--all", "HEAD", "--parents", "--timestamp"],
            timeout,
            global_arguments=["--shallow-file", ""],
        )
        if not history_error:
            history_view = "complete_local_object_graph_ignoring_shallow_marker"
        else:
            reasons.append("shallow_repository")
            reasons.append("complete_local_object_graph_unavailable")
            history, history_error = _git_output(
                repo_path,
                ["rev-list", "--all", "HEAD", "--parents", "--timestamp"],
                timeout,
            )
            history_view = "declared_shallow_graph"
    else:
        history, history_error = _git_output(
            repo_path,
            ["rev-list", "--all", "HEAD", "--parents", "--timestamp"],
            timeout,
        )
    if history_error:
        reasons.append(history_error)
        return [], refs_sha256, reasons, {
            "repository_identity": identity,
            "repository_path": str(repo_path),
            "ref_count": len(refs_lines),
            "shallow_marker_present": shallow_marker_present,
            "history_view": history_view,
        }
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for line in history.splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[0].isdigit():
            reasons.append("rev_list_malformed_record")
            records = []
            break
        timestamp, sha, *parents = fields
        valid = all(
            len(value) == 40
            and all(character in "0123456789abcdef" for character in value.lower())
            for value in [sha, *parents]
        )
        if not valid or sha.lower() in seen:
            reasons.append("rev_list_invalid_or_duplicate_sha")
            records = []
            break
        seen.add(sha.lower())
        records.append(
            {
                "sha": sha.lower(),
                "parents": [parent.lower() for parent in parents],
                "committer_timestamp": int(timestamp),
            }
        )
    return records, refs_sha256, sorted(set(reasons)), {
        "repository_identity": identity,
        "repository_path": str(repo_path),
        "ref_count": len(refs_lines),
        "shallow_marker_present": shallow_marker_present,
        "history_view": history_view,
    }


def _choose_enumeration(
    alternatives: list[
        tuple[list[dict[str, object]], str, list[str], dict[str, object]]
    ],
    required_ai_shas: set[str],
) -> tuple[
    tuple[list[dict[str, object]], str, list[str], dict[str, object]],
    list[dict[str, object]],
]:
    """Choose the most complete local graph without consulting advisory results."""

    ranked: list[
        tuple[
            tuple[int, int, int, int, str],
            tuple[list[dict[str, object]], str, list[str], dict[str, object]],
            dict[str, object],
        ]
    ] = []
    for alternative in alternatives:
        records, _refs, reasons, provenance = alternative
        shas = {str(row["sha"]) for row in records}
        missing_parents = {
            str(parent)
            for row in records
            for parent in row.get("parents", [])
            if str(parent) not in shas
        }
        missing_ai = required_ai_shas - shas
        complete = not reasons and not missing_parents and not missing_ai
        path = str(provenance.get("repository_path") or "")
        diagnostic = {
            "repository_path": path,
            "history_view": provenance.get("history_view", ""),
            "shallow_marker_present": provenance.get(
                "shallow_marker_present", False
            ),
            "commit_count": len(records),
            "enumeration_block_reasons": list(reasons),
            "missing_parent_count": len(missing_parents),
            "missing_ai_unit_count": len(missing_ai),
            "structurally_complete": complete,
        }
        rank = (
            0 if complete else 1,
            len(reasons),
            len(missing_parents) + len(missing_ai),
            -len(records),
            path,
        )
        ranked.append((rank, alternative, diagnostic))
    if not ranked:
        raise AllCommitUniverseContractError("no clone enumeration alternative")
    ranked.sort(key=lambda item: item[0])
    chosen = ranked[0][1]
    chosen_path = str(chosen[3].get("repository_path") or "")
    diagnostics: list[dict[str, object]] = []
    for _rank, _alternative, diagnostic in ranked:
        diagnostics.append(
            {**diagnostic, "selected": diagnostic["repository_path"] == chosen_path}
        )
    diagnostics.sort(key=lambda row: str(row["repository_path"]))
    return chosen, diagnostics


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if args.workers < 1 or args.repo_timeout < 1:
        raise SystemExit("workers and repo-timeout must be positive")
    intake, selected = _selected_rows(args.intake_dir)
    aliases = _aliases(args.repository_aliases)
    identities = {str(row["repository_identity"]) for row in selected}
    units_by_repository: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in _load_jsonl(args.outcomes):
        observed = str(row.get("repository_identity") or "").strip().lower()
        try:
            identity = canonical_repository_identity(observed, aliases)
        except ValueError:
            continue
        if identity in identities:
            normalized = dict(row)
            normalized["repository_identity"] = identity
            units_by_repository[identity].append(normalized)

    clone_candidates = _selected_clone_candidates(identities)
    missing_clones = sorted(identities - set(clone_candidates))
    enumerated_alternatives: dict[
        str,
        list[tuple[list[dict[str, object]], str, list[str], dict[str, object]]],
    ] = defaultdict(list)
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _enumerate_history,
                identity,
                path,
                timeout=args.repo_timeout,
            ): (identity, path)
            for identity in sorted(identities)
            for path in clone_candidates.get(identity, [None])
        }
        for future in as_completed(futures):
            identity, path = futures[future]
            try:
                enumerated_alternatives[identity].append(future.result())
            except Exception as exc:  # noqa: BLE001 - selected row must survive
                enumerated_alternatives[identity].append(
                    (
                        [],
                        "0" * 64,
                        [f"history_enumeration_exception:{type(exc).__name__}"],
                        {
                            "repository_identity": identity,
                            "repository_path": str(path or ""),
                        },
                    )
                )

    expected_counts = {
        str(row["repository_identity"]): int(row["ai_unit_count"])
        for row in selected
    }
    commit_rows: list[dict[str, object]] = []
    blocked_items: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    repository_provenance: list[dict[str, object]] = []
    try:
        for identity in sorted(identities):
            required_ai_shas = {
                str(row.get("sha") or "").strip().lower()
                for row in units_by_repository.get(identity, [])
            }
            chosen, alternative_diagnostics = _choose_enumeration(
                enumerated_alternatives[identity], required_ai_shas
            )
            records, refs_sha256, reasons, provenance = chosen
            built = build_repository_universe(
                identity,
                records,
                units_by_repository.get(identity, []),
                expected_ai_unit_count=expected_counts[identity],
                refs_sha256=refs_sha256,
                initial_block_reasons=reasons,
            )
            summaries.append(dict(built["summary"]))
            commit_rows.extend(dict(row) for row in built["commit_rows"])
            blocked_items.extend(dict(row) for row in built["blocked_items"])
            repository_provenance.append(
                {
                    **provenance,
                    "clone_selection_rule": (
                        "prefer a structurally complete local graph containing every "
                        "frozen AI unit; then prefer fewer structural failures, more "
                        "visible commits, and lexical path order"
                    ),
                    "clone_alternatives": alternative_diagnostics,
                }
            )
        summary_by_repository = {
            str(row["repository_identity"]): row for row in summaries
        }
        fallbacks = build_repository_fallbacks(selected, summary_by_repository)
    except AllCommitUniverseContractError as exc:
        raise SystemExit(f"all-commit universe contract failed: {exc}") from exc

    commit_rows.sort(
        key=lambda row: (str(row["repository_identity"]), str(row["sha"]))
    )
    blocked_items.sort(
        key=lambda row: (
            str(row["repository_identity"]),
            str(row["item_kind"]),
            str(row["sha"]),
        )
    )
    resolved_count = sum(row["status"] == "RESOLVED" for row in summaries)
    blocked_count = len(summaries) - resolved_count
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write(args.output_dir / "commit_universe.jsonl", _jsonl_text(commit_rows))
    _atomic_write(
        args.output_dir / "repository_universes.jsonl", _jsonl_text(summaries)
    )
    _atomic_write(
        args.output_dir / "repository_fallbacks.jsonl", _jsonl_text(fallbacks)
    )
    _atomic_write(
        args.output_dir / "blocked_items.jsonl", _jsonl_text(blocked_items)
    )
    campaign = {
        "schema_version": 1,
        "artifact_kind": "prospective_all_commit_universe_campaign",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "selection_split_id": intake["split_id"],
        "claim_boundary": (
            "Every commit reachable from all local refs plus HEAD is retained once. "
            "Legacy AI signals are overlay labels only and never filter membership. "
            "Each advisory has a source-independent repository fallback referencing "
            "the whole universe. BLOCKED histories remain unknown, never negatives."
        ),
        "repository_count": len(summaries),
        "resolved_repository_count": resolved_count,
        "blocked_repository_count": blocked_count,
        "visible_commit_count": len(commit_rows),
        "observed_ai_commit_count": sum(
            row["observed_ai_unit"] is True for row in commit_rows
        ),
        "non_ai_labeled_commit_count": sum(
            row["observed_ai_unit"] is False for row in commit_rows
        ),
        "fallback_count": len(fallbacks),
        "blocked_item_count": len(blocked_items),
        "conservation": {
            "selected_repositories_conserved": len(summaries) == len(selected),
            "fallbacks_conserved": len(fallbacks) == len(selected),
            "repository_statuses_conserved": (
                len(summaries) == resolved_count + blocked_count
            ),
            "all_visible_commits_retained": all(
                row["all_visible_commits_retained"] is True for row in summaries
            ),
        },
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
        "missing_clone_repositories": missing_clones,
        "repository_provenance": repository_provenance,
        "repository_universes_sha256": canonical_sha256(summaries),
        "commit_universe_sha256": canonical_sha256(commit_rows),
        "repository_fallbacks_sha256": canonical_sha256(fallbacks),
        "blocked_items_sha256": canonical_sha256(blocked_items),
        "input_provenance": {
            "intake_path": str((args.intake_dir / "intake.json").resolve()),
            "intake_sha256": _sha256_file(args.intake_dir / "intake.json"),
            "selected_path": str((args.intake_dir / "selected.jsonl").resolve()),
            "selected_sha256": _sha256_file(args.intake_dir / "selected.jsonl"),
            "outcomes_path": str(args.outcomes.resolve()),
            "outcomes_sha256": _sha256_file(args.outcomes),
            "repository_aliases_path": str(args.repository_aliases.resolve()),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
        },
    }
    campaign["campaign_sha256"] = canonical_sha256(campaign)
    _atomic_write(args.output_dir / "summary.json", _json_text(campaign))
    print("prospective all-commit universe materialized")
    print(f"  repositories          : {len(summaries)}")
    print(f"  visible commits       : {len(commit_rows):,}")
    print(f"  AI-overlay commits    : {campaign['observed_ai_commit_count']:,}")
    print(f"  unlabeled commits     : {campaign['non_ai_labeled_commit_count']:,}")
    print(f"  blocked repositories  : {blocked_count}")
    print(f"  fallbacks             : {len(fallbacks)}")
    print("  model calls           : 0")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
