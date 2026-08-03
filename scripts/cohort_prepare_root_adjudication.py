#!/usr/bin/env python3
"""Build blinded source-root packets and a separate sealed answer map."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from cohort.root_adjudication import (
    RootAdjudicationContractError,
    build_pilot_spec,
    candidate_order_key,
    canonical_sha256,
    packet_id,
    redact_blind_text,
    target_id,
    validate_packet,
)
from cve_analyzer.git_ops import run_git


DEFAULT_BODY_CHARS = 600
DEFAULT_PATCH_CHARS = 2400
DEFAULT_CHANGED_PATHS = 40
_FULL_SHA_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.IGNORECASE)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intake-dir", type=Path, required=True)
    parser.add_argument("--universe-dir", type=Path, required=True)
    parser.add_argument("--source-replay-dir", type=Path, required=True)
    parser.add_argument(
        "--pilot-id", default="prospective-root-adjudication-20260801-v1"
    )
    parser.add_argument("--per-stratum", type=int, default=2)
    parser.add_argument("--body-chars", type=int, default=DEFAULT_BODY_CHARS)
    parser.add_argument("--patch-chars", type=int, default=DEFAULT_PATCH_CHARS)
    parser.add_argument("--changed-paths", type=int, default=DEFAULT_CHANGED_PATHS)
    parser.add_argument("--repo-timeout", type=int, default=120)
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


def _verified_cvelist_payload(
    association: dict[str, object],
) -> dict[str, object] | None:
    raw_path = str(association.get("cvelist_path") or "").strip()
    expected_sha256 = str(association.get("cvelist_sha256") or "").strip()
    if not raw_path:
        return None

    path = Path(raw_path)
    if not path.is_file():
        raise SystemExit(f"frozen CVE record is unavailable: {path}")
    if not expected_sha256 or _sha256_file(path) != expected_sha256:
        raise SystemExit(f"frozen CVE record digest mismatch: {path}")
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise SystemExit(f"frozen CVE record is malformed: {path}")
    return payload


def _advisory_context(
    association: dict[str, object],
) -> tuple[str, str]:
    """Prefer the frozen CVE description over a lossy search-query summary."""

    fallback = str(association.get("description") or "").strip()
    payload = _verified_cvelist_payload(association)
    if payload is None:
        if not fallback:
            raise SystemExit("advisory description is unavailable")
        return fallback, "description_search_fallback"
    path = Path(str(association["cvelist_path"]))
    containers = payload.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        raise SystemExit(f"frozen CVE CNA container is malformed: {path}")

    parts: list[str] = []
    title = str(cna.get("title") or "").strip()
    if title:
        parts.append(f"Title: {title}")
    raw_descriptions = cna.get("descriptions")
    if isinstance(raw_descriptions, list):
        english: list[str] = []
        other: list[str] = []
        for raw in raw_descriptions:
            if not isinstance(raw, dict):
                continue
            value = str(raw.get("value") or "").strip()
            if not value:
                continue
            destination = english if str(raw.get("lang") or "").lower().startswith("en") else other
            if value not in destination:
                destination.append(value)
        for value in english or other:
            parts.append(f"Description: {value}")
    if not parts and fallback:
        return fallback, "description_search_fallback"
    if not parts:
        raise SystemExit(f"frozen CVE description is unavailable: {path}")
    return "\n".join(parts), "cvelist_cna"


def _explicit_cvelist_commit_shas(
    association: dict[str, object],
) -> set[str]:
    """Return only commit IDs literally present in the frozen CVE record."""

    payload = _verified_cvelist_payload(association)
    if payload is None:
        return set()
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return {match.group(0).lower() for match in _FULL_SHA_RE.finditer(text)}


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


def _git_text(
    repo_path: Path,
    global_arguments: list[str],
    arguments: list[str],
    *,
    timeout: int,
) -> tuple[str, str]:
    try:
        completed = run_git(
            ["git", "-C", str(repo_path), *global_arguments, *arguments],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            no_lazy_fetch=True,
        )
    except Exception as exc:  # noqa: BLE001 - candidate remains BLOCKED
        return "", f"git_{arguments[0]}_exception:{type(exc).__name__}"
    if completed.returncode != 0:
        return "", f"git_{arguments[0]}_nonzero:{completed.returncode}"
    return str(completed.stdout or ""), ""


def _repository_views(
    universe_summary: dict[str, object],
) -> dict[str, tuple[Path, list[str]]]:
    rows = universe_summary.get("repository_provenance")
    if not isinstance(rows, list):
        raise SystemExit("universe repository provenance is malformed")
    result: dict[str, tuple[Path, list[str]]] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            raise SystemExit("universe repository provenance is malformed")
        identity = str(raw.get("repository_identity") or "")
        path = Path(str(raw.get("repository_path") or ""))
        arguments = (
            ["--shallow-file", ""]
            if raw.get("history_view")
            == "complete_local_object_graph_ignoring_shallow_marker"
            else []
        )
        if not identity or not path.is_dir():
            raise SystemExit(f"repository view is unavailable: {identity}")
        result[identity] = (path, arguments)
    return result


def _candidate_view(
    repo_path: Path,
    global_arguments: list[str],
    sha: str,
    *,
    repository_identity: str,
    advisory: str,
    body_chars: int,
    patch_chars: int,
    changed_path_limit: int,
    timeout: int,
) -> dict[str, object]:
    metadata, metadata_error = _git_text(
        repo_path,
        global_arguments,
        ["show", "--no-patch", "--format=%aI%x00%s%x00%b", sha],
        timeout=timeout,
    )
    paths_text, paths_error = _git_text(
        repo_path,
        global_arguments,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "-m", sha],
        timeout=timeout,
    )
    patch, patch_error = _git_text(
        repo_path,
        global_arguments,
        [
            "show",
            "--format=",
            "--no-color",
            "--no-ext-diff",
            "--unified=2",
            "--find-renames=40%",
            sha,
        ],
        timeout=timeout,
    )
    errors = sorted(
        {error for error in (metadata_error, paths_error, patch_error) if error}
    )
    authored = ""
    subject = ""
    body = ""
    if metadata:
        fields = metadata.rstrip("\n").split("\x00", 2)
        if len(fields) == 3:
            authored, subject, body = fields
        else:
            errors.append("metadata_malformed")
    changed_paths = sorted(
        {line.strip() for line in paths_text.splitlines() if line.strip()}
    )[:changed_path_limit]
    truncated = len(patch) > patch_chars
    return {
        "authored_date": authored.strip(),
        "subject": redact_blind_text(
            subject.strip(),
            repository_identity=repository_identity,
            advisory=advisory,
        ),
        "body_excerpt": redact_blind_text(
            body.strip()[:body_chars],
            repository_identity=repository_identity,
            advisory=advisory,
        ),
        "changed_paths": changed_paths,
        "patch_excerpt": redact_blind_text(
            patch.strip()[:patch_chars],
            repository_identity=repository_identity,
            advisory=advisory,
        ),
        "patch_truncated": truncated,
        "evidence_status": "BLOCKED" if errors else "READY",
        "evidence_reason": ",".join(sorted(set(errors))),
    }


def _public_control_closure(
    repo_path: Path,
    global_arguments: list[str],
    candidates: list[dict[str, object]],
    *,
    timeout: int,
) -> tuple[list[str], list[dict[str, str]]]:
    """Add only graph-proven merge aliases to the exact public control set."""

    exact = [row for row in candidates if row.get("public_control_seed") is True]
    accepted = {str(row["candidate_id"]) for row in exact}
    candidate_by_sha = {str(row["sha"]): row for row in candidates}
    equivalences: list[dict[str, str]] = []
    for public in exact:
        public_sha = str(public["sha"])
        public_tree, tree_error = _git_text(
            repo_path,
            global_arguments,
            ["rev-parse", f"{public_sha}^{{tree}}"],
            timeout=timeout,
        )
        parents_text, parents_error = _git_text(
            repo_path,
            global_arguments,
            ["show", "--no-patch", "--format=%P", public_sha],
            timeout=timeout,
        )
        if tree_error or parents_error:
            raise SystemExit(
                "cannot construct public control closure for "
                f"{public_sha}: {tree_error or parents_error}"
            )
        public_tree = public_tree.strip()
        parents = parents_text.strip().split()
        if len(parents) < 2:
            continue
        for parent_sha in parents:
            candidate = candidate_by_sha.get(parent_sha)
            if candidate is None:
                continue
            parent_tree, parent_error = _git_text(
                repo_path,
                global_arguments,
                ["rev-parse", f"{parent_sha}^{{tree}}"],
                timeout=timeout,
            )
            if parent_error:
                raise SystemExit(
                    "cannot construct public control closure for parent "
                    f"{parent_sha}: {parent_error}"
                )
            if parent_tree.strip() != public_tree:
                continue
            candidate_id = str(candidate["candidate_id"])
            accepted.add(candidate_id)
            equivalences.append(
                {
                    "candidate_id": candidate_id,
                    "public_exact_candidate_id": str(public["candidate_id"]),
                    "reason": "tree_identical_parent_of_public_merge",
                }
            )
    return sorted(accepted), sorted(
        equivalences,
        key=lambda row: (
            row["candidate_id"],
            row["public_exact_candidate_id"],
            row["reason"],
        ),
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    if min(
        args.per_stratum,
        args.body_chars,
        args.patch_chars,
        args.changed_paths,
        args.repo_timeout,
    ) < 1:
        raise SystemExit("packet limits must be positive")
    selected = _load_jsonl(args.intake_dir / "selected.jsonl")
    selected_by_pair = {
        (str(row["repository_identity"]), str(row["advisory"])): row
        for row in selected
    }
    associations = _load_jsonl(
        args.source_replay_dir / "repository_advisory_associations.jsonl"
    )
    association_by_pair = {
        (str(row["repository_identity"]), str(row["advisory"])): row
        for row in associations
    }
    roots = _load_jsonl(args.source_replay_dir / "source_roots.jsonl")
    roots_by_pair: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for root in roots:
        repository = str(root["repository_identity"])
        for advisory in root["advisories"]:
            roots_by_pair[(repository, str(advisory))].append(root)
    if set(selected_by_pair) != set(association_by_pair) or set(selected_by_pair) != set(
        roots_by_pair
    ):
        raise SystemExit("packet pair conservation failed")

    universe_summary = _load_json(args.universe_dir / "summary.json")
    if not isinstance(universe_summary, dict):
        raise SystemExit("universe summary is malformed")
    repository_views = _repository_views(universe_summary)
    packets: list[dict[str, object]] = []
    sealed_rows: list[dict[str, object]] = []
    packet_metadata: list[dict[str, object]] = []
    description_context_sources: defaultdict[str, int] = defaultdict(int)
    for pair in sorted(selected_by_pair):
        repository, advisory = pair
        selected_row = selected_by_pair[pair]
        association = association_by_pair[pair]
        description, description_source = _advisory_context(association)
        description_context_sources[description_source] += 1
        explicit_public_shas = _explicit_cvelist_commit_shas(association)
        identifier = packet_id(repository, advisory)
        ordered_roots = sorted(
            roots_by_pair[pair],
            key=lambda root: (
                candidate_order_key(identifier, str(root["root_sha"])),
                str(root["root_sha"]),
            ),
        )
        repo_path, global_arguments = repository_views[repository]
        blind_candidates: list[dict[str, object]] = []
        sealed_candidates: list[dict[str, object]] = []
        for index, root in enumerate(ordered_roots, start=1):
            candidate_identifier = f"C{index:02d}"
            sha = str(root["root_sha"])
            view = _candidate_view(
                repo_path,
                global_arguments,
                sha,
                repository_identity=repository,
                advisory=advisory,
                body_chars=args.body_chars,
                patch_chars=args.patch_chars,
                changed_path_limit=args.changed_paths,
                timeout=args.repo_timeout,
            )
            blind_candidates.append(
                {"candidate_id": candidate_identifier, **view}
            )
            evidence_kinds = sorted(str(value) for value in root["evidence_kinds"])
            sealed_candidates.append(
                {
                    "candidate_id": candidate_identifier,
                    "sha": sha,
                    "evidence_kinds": evidence_kinds,
                    "public_exact": "public_exact" in evidence_kinds,
                    "public_control_seed": (
                        "public_exact" in evidence_kinds
                        and sha.lower() in explicit_public_shas
                    ),
                    "root_coverage_status": root["status"],
                }
            )
        public_control_candidate_ids, public_equivalences = _public_control_closure(
            repo_path,
            global_arguments,
            sealed_candidates,
            timeout=args.repo_timeout,
        )
        packet = validate_packet(
            {
                "schema_version": 1,
                "packet_id": identifier,
                "target_id": target_id(repository, advisory),
                "vulnerability_description": redact_blind_text(
                    description,
                    repository_identity=repository,
                    advisory=advisory,
                ),
                "candidates": blind_candidates,
            }
        )
        packets.append(packet)
        source_class = str(selected_row["source_class"])
        sealed_rows.append(
            {
                "packet_id": identifier,
                "repository_identity": repository,
                "advisory": advisory,
                "source_class": source_class,
                "candidates": sealed_candidates,
                "public_exact_candidate_ids": sorted(
                    row["candidate_id"]
                    for row in sealed_candidates
                    if row["public_exact"] is True
                ),
                "public_control_candidate_ids": public_control_candidate_ids,
                "public_control_equivalences": public_equivalences,
                "public_control_eligible": bool(public_control_candidate_ids),
                "public_control_ineligible_reason": (
                    ""
                    if public_control_candidate_ids
                    else "osv_range_boundary_without_explicit_cvelist_commit"
                ),
            }
        )
        packet_metadata.append(
            {"packet_id": identifier, "source_class": source_class}
        )
    try:
        pilot = build_pilot_spec(
            packet_metadata,
            pilot_id=args.pilot_id,
            per_stratum=args.per_stratum,
        )
    except RootAdjudicationContractError as exc:
        raise SystemExit(f"root-adjudication pilot contract failed: {exc}") from exc

    packets.sort(key=lambda row: str(row["packet_id"]))
    sealed_rows.sort(key=lambda row: str(row["packet_id"]))
    total_chars = sum(
        len(json.dumps(packet, ensure_ascii=False, sort_keys=True)) for packet in packets
    )
    pilot_packet_ids = {
        str(row["packet_id"]) for row in pilot["selected"]
    }
    pilot_chars = sum(
        len(json.dumps(packet, ensure_ascii=False, sort_keys=True))
        for packet in packets
        if packet["packet_id"] in pilot_packet_ids
    )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _atomic_write(args.output_dir / "packets.jsonl", _jsonl_text(packets))
    _atomic_write(
        args.output_dir / "sealed_candidate_map.json",
        _json_text(
            {
                "schema_version": 1,
                "artifact_kind": "sealed_root_candidate_map",
                "rows": sealed_rows,
                "rows_sha256": canonical_sha256(sealed_rows),
            }
        ),
    )
    _atomic_write(args.output_dir / "pilot.json", _json_text(pilot))
    summary = {
        "schema_version": 1,
        "artifact_kind": "blinded_root_adjudication_packets",
        "packet_count": len(packets),
        "candidate_count": sum(len(row["candidates"]) for row in packets),
        "blocked_candidate_evidence_count": sum(
            candidate["evidence_status"] == "BLOCKED"
            for packet in packets
            for candidate in packet["candidates"]
        ),
        "pilot_packet_count": len(pilot_packet_ids),
        "all_packet_char_count": total_chars,
        "pilot_packet_char_count": pilot_chars,
        "rough_pilot_input_token_upper_bound": (pilot_chars + 3) // 4,
        "description_context_sources": dict(sorted(description_context_sources.items())),
        "blind_contract": (
            "packets contain no explicit repository identity, advisory ID, commit "
            "SHA, source class, evidence-kind label, or public-exact answer; free "
            "text also redacts advisory IDs, URLs, target repository strings, and "
            "full hashes. The executor reads only packets.jsonl and pilot.json; "
            "scoring reads the sealed map afterward."
        ),
        "model_api_calls": 0,
        "packets_sha256": canonical_sha256(packets),
        "pilot_sha256": canonical_sha256(pilot),
        "input_provenance": {
            "selected_sha256": _sha256_file(args.intake_dir / "selected.jsonl"),
            "universe_summary_sha256": _sha256_file(
                args.universe_dir / "summary.json"
            ),
            "associations_sha256": _sha256_file(
                args.source_replay_dir / "repository_advisory_associations.jsonl"
            ),
            "source_roots_sha256": _sha256_file(
                args.source_replay_dir / "source_roots.jsonl"
            ),
        },
    }
    _atomic_write(args.output_dir / "summary.json", _json_text(summary))
    print("blinded root-adjudication packets frozen")
    print(f"  packets               : {len(packets)}")
    print(f"  candidates            : {summary['candidate_count']}")
    print(f"  pilot calls           : {len(pilot_packet_ids)}")
    print(f"  pilot packet chars    : {pilot_chars:,}")
    print(
        "  rough input tokens    : "
        f"{summary['rough_pilot_input_token_upper_bound']:,}"
    )
    print("  model calls           : 0")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
