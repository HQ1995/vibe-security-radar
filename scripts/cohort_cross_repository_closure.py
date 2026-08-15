#!/usr/bin/env python3
"""Expand candidate ancestry through explicitly declared repository imports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data_refresh_paths

from cohort.cross_repository import (
    AMBIGUOUS_SOURCE,
    DECLARED_SOURCE,
    build_declared_import_inventory,
    classify_import_source_mentions,
    expand_declared_import_candidates,
)
from cohort.relations import (
    canonical_repository_identity,
    normalize_repository_aliases,
)
from cohort.repos import discover_local_clones
from cve_analyzer.git_ops import run_git


_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
DEFAULT_ALIASES = _SCRIPT_DIR / "cohort_repository_aliases.json"
COHORT_STATE_RELATIVE = (
    Path(data_refresh_paths.PROJECT_RUNTIME_DIRECTORY) / "state" / "cohort-v1"
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--scan-dir", type=Path, required=True)
    parser.add_argument("--repository-aliases", type=Path, default=DEFAULT_ALIASES)
    parser.add_argument("--repo-timeout", type=int, default=300)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args(argv)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain an object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        handle = path.open(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    with handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise SystemExit(f"malformed {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise SystemExit(f"{path}:{line_number} is not an object")
            rows.append(row)
    return rows


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_aliases(path: Path) -> dict[str, str]:
    payload = _load_json(path)
    rows = payload.get("aliases")
    if payload.get("schema_version") != 1 or not isinstance(rows, list):
        raise SystemExit("repository aliases must use schema_version 1")
    try:
        return normalize_repository_aliases(rows)
    except ValueError as exc:
        raise SystemExit(f"invalid repository aliases: {exc}") from exc


def _canonicalize_clone_paths(
    repositories: dict[str, Path], aliases: dict[str, str]
) -> dict[str, Path]:
    resolved: dict[str, tuple[bool, Path]] = {}
    for observed, path in sorted(repositories.items()):
        canonical = canonical_repository_identity(observed, aliases)
        candidate = (observed.strip().lower() == canonical, path)
        prior = resolved.get(canonical)
        if prior is None or candidate[0] > prior[0]:
            resolved[canonical] = candidate
    return {identity: value[1] for identity, value in resolved.items()}


def _full_sha(value: object, *, field: str) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise SystemExit(f"{field} must be a full 40-hex SHA")
    return sha


def _normalize_fix_roots(
    rows: list[dict[str, Any]], aliases: dict[str, str]
) -> list[dict[str, object]]:
    normalized: dict[tuple[str, str], dict[str, object]] = {}
    for raw in rows:
        identity = canonical_repository_identity(
            str(raw.get("repository_identity") or ""), aliases
        )
        fix_sha = _full_sha(raw.get("fix_sha"), field="fix root")
        status = str(raw.get("status") or "").strip().upper()
        reason = str(raw.get("reason") or "").strip()
        if status not in {"RESOLVED", "BLOCKED"}:
            raise SystemExit("fix-root status must be RESOLVED or BLOCKED")
        if status == "BLOCKED" and not reason:
            raise SystemExit("blocked fix root requires a reason")
        advisories = raw.get("advisories")
        if not isinstance(advisories, list):
            raise SystemExit("fix root advisories must be a list")
        key = (identity, fix_sha)
        prior = normalized.get(key)
        if prior is not None and (
            prior["status"] != status or prior["reason"] != reason
        ):
            raise SystemExit("conflicting duplicate fix root")
        normalized[key] = {
            "repository_identity": identity,
            "fix_sha": fix_sha,
            "status": status,
            "reason": reason,
            "advisories": list(advisories),
        }
    return [normalized[key] for key in sorted(normalized)]


def _reachable_history(
    repo_path: Path, roots: list[str], *, timeout: int
) -> tuple[list[dict[str, object]], str]:
    try:
        completed = run_git(
            [
                "git",
                "-C",
                str(repo_path),
                "log",
                "-z",
                *roots,
                "--format=%H%x00%P%x00%B",
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            no_lazy_fetch=True,
        )
    except Exception as exc:  # noqa: BLE001 - represented as blocked target roots
        return [], f"target_history_exception:{type(exc).__name__}"
    if completed.returncode != 0:
        return [], f"target_history_nonzero:{completed.returncode}"
    records: list[dict[str, object]] = []
    fields = str(completed.stdout or "").split("\x00")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 3:
        return [], "target_history_malformed_record"
    for offset in range(0, len(fields), 3):
        sha = fields[offset].strip().lower()
        if len(sha) != 40 or any(
            character not in "0123456789abcdef" for character in sha
        ):
            return [], "target_history_malformed_sha"
        parents = fields[offset + 1].split()
        if any(
            len(parent) != 40
            or any(character not in "0123456789abcdef" for character in parent)
            for parent in parents
        ):
            return [], "target_history_malformed_parent"
        records.append(
            {"sha": sha, "parents": parents, "message": fields[offset + 2]}
        )
    return records, ""


def _reachability_masks(
    records: list[dict[str, object]], roots: list[str]
) -> tuple[dict[str, int], dict[str, str]]:
    """Walk the union parent graph once and propagate every fix-root bit."""

    by_sha = {str(record["sha"]): record for record in records}
    root_bits = {root: 1 << index for index, root in enumerate(roots)}
    masks: dict[str, int] = {}
    sent: dict[str, int] = {}
    pending: deque[str] = deque()
    errors: dict[str, str] = {}
    for root in roots:
        if root not in by_sha:
            errors[root] = "target_fix_absent_from_history"
            continue
        masks[root] = masks.get(root, 0) | root_bits[root]
        pending.append(root)

    def block(mask: int, reason: str) -> None:
        for root, bit in root_bits.items():
            if mask & bit:
                errors.setdefault(root, reason)

    while pending:
        current = pending.popleft()
        delta = masks.get(current, 0) & ~sent.get(current, 0)
        if not delta:
            continue
        sent[current] = sent.get(current, 0) | delta
        record = by_sha.get(current)
        if record is None:
            block(delta, "target_history_parent_missing")
            continue
        parents = record.get("parents")
        if not isinstance(parents, list):
            block(delta, "target_history_malformed_parent")
            continue
        for parent in parents:
            parent_sha = str(parent)
            before = masks.get(parent_sha, 0)
            after = before | delta
            if after != before:
                masks[parent_sha] = after
                pending.append(parent_sha)
    return masks, errors


def discover_import_carriers(
    fix_roots: list[dict[str, object]],
    repositories: dict[str, Path],
    aliases: dict[str, str],
    *,
    timeout: int,
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    """Scan all fix-reachable target history; a carrier need not be AI-tagged."""

    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for root in fix_roots:
        grouped[str(root["repository_identity"])].append(root)
    carriers: list[dict[str, object]] = []
    target_roots: list[dict[str, object]] = []
    ambiguities: list[dict[str, object]] = []
    for identity, roots in sorted(grouped.items()):
        resolved_roots = [row for row in roots if row["status"] == "RESOLVED"]
        for root in roots:
            if root["status"] == "BLOCKED":
                target_roots.append(
                    {
                        **root,
                        "status": "BLOCKED",
                        "reason": f"candidate_fix_root:{root['reason']}",
                        "declared_import_carrier_count": 0,
                        "ambiguous_source_mention_count": 0,
                    }
                )
        if not resolved_roots:
            continue
        repo_path = repositories.get(identity)
        if repo_path is None:
            for root in resolved_roots:
                target_roots.append(
                    {
                        **root,
                        "status": "BLOCKED",
                        "reason": "target_repository_clone_missing",
                        "declared_import_carrier_count": 0,
                        "ambiguous_source_mention_count": 0,
                    }
                )
            continue
        roots_by_sha = {str(root["fix_sha"]): root for root in resolved_roots}
        history, history_error = _reachable_history(
            repo_path, sorted(roots_by_sha), timeout=timeout
        )
        if history_error:
            for root in resolved_roots:
                target_roots.append(
                    {
                        **root,
                        "status": "BLOCKED",
                        "reason": history_error,
                        "declared_import_carrier_count": 0,
                        "ambiguous_source_mention_count": 0,
                    }
                )
            continue
        root_order = sorted(roots_by_sha)
        masks, root_errors = _reachability_masks(history, root_order)
        root_bits = {root: 1 << index for index, root in enumerate(root_order)}
        declared: set[tuple[str, str]] = set()
        ambiguous: set[tuple[str, str, str, str]] = set()
        for record in history:
            import_sha = str(record["sha"])
            for mention in classify_import_source_mentions(str(record["message"])):
                source = canonical_repository_identity(
                    mention["source_repository_identity"], aliases
                )
                if source == identity:
                    continue
                if mention["status"] == DECLARED_SOURCE:
                    declared.add((import_sha, source))
                elif mention["status"] == AMBIGUOUS_SOURCE:
                    ambiguous.add(
                        (
                            import_sha,
                            source,
                            mention["evidence_kind"],
                            mention["evidence_text"],
                        )
                    )
        root_carrier_counts: dict[str, int] = defaultdict(int)
        root_ambiguity_counts: dict[str, int] = defaultdict(int)
        staged: list[dict[str, object]] = []
        for import_sha, source in sorted(declared):
            mask = masks.get(import_sha, 0)
            for fix_sha, root in sorted(roots_by_sha.items()):
                if not mask & root_bits[fix_sha]:
                    continue
                root_carrier_counts[fix_sha] += 1
                staged.append(
                    {
                        "target_repository_identity": identity,
                        "source_repository_identity": source,
                        "import_sha": import_sha,
                        "fix_sha": fix_sha,
                        "fix_root_status": "RESOLVED",
                        "fix_root_reason": "",
                        "advisories": list(root["advisories"]),
                    }
                )
        for import_sha, source, evidence_kind, evidence_text in sorted(ambiguous):
            mask = masks.get(import_sha, 0)
            for fix_sha, root in sorted(roots_by_sha.items()):
                if not mask & root_bits[fix_sha]:
                    continue
                root_ambiguity_counts[fix_sha] += 1
                ambiguity_parts = [
                    identity,
                    import_sha,
                    source,
                    fix_sha,
                    evidence_kind,
                ]
                ambiguities.append(
                    {
                        "ambiguity_id": (
                            "source-ambiguity-" + _canonical_sha256(ambiguity_parts)
                        ),
                        "target_repository_identity": identity,
                        "candidate_source_repository_identity": source,
                        "import_sha": import_sha,
                        "fix_sha": fix_sha,
                        "status": "BLOCKED",
                        "reason": "bare_owner_repo_may_be_source_or_module_path",
                        "evidence_kind": evidence_kind,
                        "evidence_text": evidence_text,
                        "advisories": list(root["advisories"]),
                    }
                )
        for root in resolved_roots:
            fix_sha = str(root["fix_sha"])
            error = root_errors.get(fix_sha, "")
            target_roots.append(
                {
                    **root,
                    "status": "BLOCKED" if error else "RESOLVED",
                    "reason": error,
                    "declared_import_carrier_count": (
                        0 if error else root_carrier_counts[fix_sha]
                    ),
                    "ambiguous_source_mention_count": (
                        0 if error else root_ambiguity_counts[fix_sha]
                    ),
                }
            )
        carriers.extend(
            row for row in staged if str(row["fix_sha"]) not in root_errors
        )
    carriers.sort(
        key=lambda row: (
            str(row["target_repository_identity"]),
            str(row["source_repository_identity"]),
            str(row["import_sha"]),
            str(row["fix_sha"]),
        )
    )
    target_roots.sort(
        key=lambda row: (str(row["repository_identity"]), str(row["fix_sha"]))
    )
    ambiguities.sort(key=lambda row: str(row["ambiguity_id"]))
    return carriers, target_roots, ambiguities


def source_scan_inputs(
    commits: list[dict[str, Any]],
    summary: dict[str, Any],
    aliases: dict[str, str],
) -> tuple[
    dict[str, list[dict[str, object]]],
    dict[str, dict[str, object]],
]:
    """Build explicit source coverage, preserving complete zero-match scans."""

    scanned = summary.get("scanned_repository_identities")
    complete = summary.get("complete_repository_identities")
    incomplete = summary.get("incomplete_repositories")
    if not isinstance(scanned, list) or not isinstance(complete, list):
        raise SystemExit(
            "scan summary lacks explicit scanned/complete repository identities"
        )
    if not isinstance(incomplete, list):
        raise SystemExit("scan summary incomplete_repositories must be a list")
    scanned_set = {
        canonical_repository_identity(str(identity), aliases) for identity in scanned
    }
    complete_set = {
        canonical_repository_identity(str(identity), aliases) for identity in complete
    }
    if not complete_set <= scanned_set:
        raise SystemExit("complete source repositories are not a subset of scanned")
    incomplete_reasons: dict[str, str] = {}
    for row in incomplete:
        if not isinstance(row, dict):
            raise SystemExit("malformed incomplete repository row")
        identity = canonical_repository_identity(
            str(row.get("repository_identity") or ""), aliases
        )
        incomplete_reasons[identity] = str(row.get("error") or "unspecified")
    if complete_set & set(incomplete_reasons):
        raise SystemExit("source repository is both complete and incomplete")

    by_repo: dict[str, list[dict[str, object]]] = defaultdict(list)
    for raw in commits:
        identity = canonical_repository_identity(
            str(raw.get("repository_identity") or ""), aliases
        )
        if identity not in scanned_set:
            raise SystemExit("source commit belongs to a repository absent from scan ledger")
        row = dict(raw)
        row["repository_identity"] = identity
        by_repo[identity].append(row)
    for rows in by_repo.values():
        rows.sort(key=lambda row: str(row.get("sha") or ""))
    coverage = {
        identity: {
            "complete": identity in complete_set,
            "reason": "" if identity in complete_set else incomplete_reasons.get(
                identity, "scan_not_marked_complete"
            ),
        }
        for identity in sorted(scanned_set)
    }
    return dict(by_repo), coverage


def build_cross_repository_campaign(
    carriers: list[dict[str, object]],
    target_roots: list[dict[str, object]],
    ambiguities: list[dict[str, object]],
    source_commits: dict[str, list[dict[str, object]]],
    source_coverage: dict[str, dict[str, object]],
) -> dict[str, object]:
    inventory = build_declared_import_inventory(
        carriers, source_commits, source_coverage
    )
    relations = inventory["relations"]
    assert isinstance(relations, list)
    candidates = expand_declared_import_candidates(carriers, relations)
    routing = [
        {
            "edge_id": str(row["edge_id"]),
            "status": "DEFER",
            "reason": "awaiting_screening",
        }
        for row in candidates
    ]
    blocked_target_roots = sum(row["status"] == "BLOCKED" for row in target_roots)
    summary: dict[str, object] = {
        "schema_version": 1,
        "artifact_kind": "declared_cross_repository_candidate_closure",
        "target_fix_root_count": len(target_roots),
        "resolved_target_fix_root_count": len(target_roots) - blocked_target_roots,
        "blocked_target_fix_root_count": blocked_target_roots,
        "import_carrier_count": len(carriers),
        "declared_source_repository_count": len(
            {str(row["source_repository_identity"]) for row in carriers}
        ),
        "declared_import_commit_count": len(
            {
                (
                    str(row["target_repository_identity"]),
                    str(row["source_repository_identity"]),
                    str(row["import_sha"]),
                )
                for row in carriers
            }
        ),
        "import_root_count": inventory["import_root_count"],
        "resolved_import_root_count": inventory["resolved_import_root_count"],
        "blocked_import_root_count": inventory["blocked_import_root_count"],
        "ambiguous_source_mention_count": len(ambiguities),
        "declared_import_relation_count": len(relations),
        "cross_repository_candidate_edge_count": len(candidates),
        "initial_defer_count": len(routing),
        "coverage_complete": bool(inventory["coverage_complete"])
        and blocked_target_roots == 0
        and not ambiguities,
        "conservation": {
            "target_fix_roots_conserved": len(target_roots)
            == (len(target_roots) - blocked_target_roots) + blocked_target_roots,
            "candidate_edges_deferred": len(candidates) == len(routing),
            "ambiguous_mentions_conserved_as_blocked": all(
                row.get("status") == "BLOCKED" for row in ambiguities
            ),
        },
        "target_roots_sha256": _canonical_sha256(target_roots),
        "import_carriers_sha256": _canonical_sha256(carriers),
        "relations_sha256": _canonical_sha256(relations),
        "candidates_sha256": _canonical_sha256(candidates),
        "ambiguous_source_mentions_sha256": _canonical_sha256(ambiguities),
        "claim_boundary": (
            "target carrier discovery scans all fix-reachable commit messages, not"
            " only AI-tagged target commits; every AI-attributed commit from each"
            " explicitly declared and completely scanned source repository remains"
            " a candidate; bare owner/repo-shaped prose is retained in a separate"
            " BLOCKED ambiguity ledger and is neither trusted nor discarded; missing"
            " or incomplete history is BLOCKED, never negative"
        ),
        "model_api_calls": 0,
        "model_input_tokens": 0,
        "model_output_tokens": 0,
        "model_cost_usd": 0.0,
    }
    summary["summary_sha256"] = _canonical_sha256(summary)
    return {
        "summary": summary,
        "target_roots": target_roots,
        "import_carriers": carriers,
        "relations": relations,
        "import_roots": inventory["import_roots"],
        "ambiguous_source_mentions": ambiguities,
        "candidates": candidates,
        "routing": routing,
    }


def _atomic_write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_write_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.repo_timeout < 1:
        raise SystemExit("repo-timeout must be positive")
    aliases = _load_aliases(args.repository_aliases)
    fix_roots_path = args.candidate_dir / "fix_roots.jsonl"
    scan_commits_path = args.scan_dir / "commits.jsonl"
    scan_summary_path = args.scan_dir / "summary.json"
    fix_roots = _normalize_fix_roots(_load_jsonl(fix_roots_path), aliases)
    source_commits, source_coverage = source_scan_inputs(
        _load_jsonl(scan_commits_path), _load_json(scan_summary_path), aliases
    )
    repositories, unresolved = discover_local_clones(_REPO_ROOT)
    repositories = _canonicalize_clone_paths(repositories, aliases)
    carriers, target_roots, ambiguities = discover_import_carriers(
        fix_roots, repositories, aliases, timeout=args.repo_timeout
    )
    artifacts = build_cross_repository_campaign(
        carriers, target_roots, ambiguities, source_commits, source_coverage
    )
    summary = dict(artifacts["summary"])
    summary.pop("summary_sha256", None)
    summary.update(
        {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "candidate_fix_roots_path": str(fix_roots_path),
            "candidate_fix_roots_sha256": _sha256_file(fix_roots_path),
            "source_commits_path": str(scan_commits_path),
            "source_commits_sha256": _sha256_file(scan_commits_path),
            "source_scan_summary_path": str(scan_summary_path),
            "source_scan_summary_sha256": _sha256_file(scan_summary_path),
            "repository_aliases_path": str(args.repository_aliases),
            "repository_aliases_sha256": _sha256_file(args.repository_aliases),
            "unresolved_clone_directories": len(unresolved),
        }
    )
    summary["summary_sha256"] = _canonical_sha256(summary)
    artifacts["summary"] = summary

    output_dir = args.output_dir or (
        _REPO_ROOT
        / COHORT_STATE_RELATIVE
        / f"cross-repository-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    for name, filename in (
        ("target_roots", "target_roots.jsonl"),
        ("import_carriers", "import_carriers.jsonl"),
        ("ambiguous_source_mentions", "ambiguous_source_mentions.jsonl"),
        ("relations", "relations.jsonl"),
        ("import_roots", "import_roots.jsonl"),
        ("candidates", "candidates_cross_repository.jsonl"),
        ("routing", "routing.jsonl"),
    ):
        rows = artifacts[name]
        assert isinstance(rows, list)
        _atomic_write_jsonl(output_dir / filename, rows)
    _atomic_write_json(output_dir / "summary.json", summary)

    print("\nDeclared cross-repository closure")
    print(f"  target fix roots : {summary['target_fix_root_count']}")
    print(f"  import carriers  : {summary['import_carrier_count']}")
    print(f"  ambiguous sources: {summary['ambiguous_source_mention_count']} blocked")
    print(
        f"  import roots     : {summary['resolved_import_root_count']} resolved /"
        f" {summary['blocked_import_root_count']} blocked"
    )
    print(f"  upstream relations: {summary['declared_import_relation_count']}")
    print(f"  candidate edges  : {summary['cross_repository_candidate_edge_count']}")
    print(f"  blocked targets  : {summary['blocked_target_fix_root_count']}")
    print(f"  model/API cost   : ${summary['model_cost_usd']:.2f}")
    print(f"  output           : {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
