#!/usr/bin/env python3
"""Build a compressed, all-commit-conserving priority overlay."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from cohort.recall_queue import (
    ROOT_PRIORITY,
    RecallQueueContractError,
    build_root_priorities,
    commit_priority,
)
from cohort.root_adjudication import canonical_sha256


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--universe-dir", type=Path, required=True)
    parser.add_argument("--source-replay-dir", type=Path, required=True)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def _load_json(path: Path) -> object:
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


def _atomic_json(path: Path, value: object) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _jsonl_text(rows: list[dict[str, object]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    )


def _priority_reasons(
    score: dict[str, object], sealed: dict[str, object]
) -> tuple[dict[tuple[str, str], list[str]], set[tuple[str, str]]]:
    score_rows = score.get("rows")
    sealed_rows = sealed.get("rows")
    if not isinstance(score_rows, list) or not isinstance(sealed_rows, list):
        raise SystemExit("score or sealed candidate rows are malformed")
    sealed_by_packet = {
        str(row["packet_id"]): row for row in sealed_rows if isinstance(row, dict)
    }
    reasons: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    pairs: set[tuple[str, str]] = set()
    for raw in score_rows:
        if not isinstance(raw, dict):
            raise SystemExit("score rows are malformed")
        packet_id = str(raw.get("packet_id") or "")
        secret = sealed_by_packet.get(packet_id)
        if not isinstance(secret, dict):
            raise SystemExit("score packet is absent from sealed map")
        repository = str(secret.get("repository_identity") or "")
        advisory = str(secret.get("advisory") or "")
        pairs.add((repository, advisory))
        candidates = secret.get("candidates")
        if not isinstance(candidates, list):
            raise SystemExit("sealed candidates are malformed")
        candidate_by_id = {
            str(candidate["candidate_id"]): candidate
            for candidate in candidates
            if isinstance(candidate, dict)
        }
        decision = raw.get("decision")
        selected_ids = decision.get("selected_ids", []) if isinstance(decision, dict) else []
        for candidate_id in selected_ids:
            candidate = candidate_by_id.get(str(candidate_id))
            if not isinstance(candidate, dict):
                raise SystemExit("model selected an unknown sealed candidate")
            reasons[(repository, str(candidate["sha"]).lower())].add(
                "model_selected_root"
            )
        if raw.get("public_control_eligible") is True:
            for candidate_id in raw.get("public_control_candidate_ids", []):
                candidate = candidate_by_id.get(str(candidate_id))
                if not isinstance(candidate, dict):
                    raise SystemExit("public control references an unknown candidate")
                reasons[(repository, str(candidate["sha"]).lower())].add(
                    "explicit_public_control_root"
                )
    return {key: sorted(value) for key, value in reasons.items()}, pairs


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.output_dir.exists():
        raise SystemExit(f"output directory already exists: {args.output_dir}")
    score = _load_json(args.score)
    sealed = _load_json(args.packet_dir / "sealed_candidate_map.json")
    if (
        not isinstance(score, dict)
        or score.get("artifact_kind") != "sealed_root_adjudication_score"
        or score.get("gate_status") != "CONTINUE"
        or not isinstance(sealed, dict)
    ):
        raise SystemExit("source-qualified root adjudication has not passed")
    priority_reasons, score_pairs = _priority_reasons(score, sealed)
    source_roots = _load_jsonl(args.source_replay_dir / "source_roots.jsonl")
    try:
        root_priorities = build_root_priorities(source_roots, priority_reasons)
    except RecallQueueContractError as exc:
        raise SystemExit(f"root priority contract failed: {exc}") from exc
    root_by_repo: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for row in root_priorities:
        root_by_repo[str(row["repository_identity"])].append(row)
    root_pairs = {
        (str(root["repository_identity"]), str(advisory))
        for root in source_roots
        for advisory in root.get("advisories", [])
    }
    if root_pairs != score_pairs:
        raise SystemExit("score and source-root advisory pairs do not match")

    membership: dict[tuple[str, str], int] = {}
    for row in _load_jsonl(args.source_replay_dir / "root_membership.jsonl"):
        key = (str(row["repository_identity"]), str(row["sha"]))
        if key in membership:
            raise SystemExit("duplicate root-membership row")
        membership[key] = int(str(row["root_mask_hex"]), 16)

    fallback_rows = _load_jsonl(args.universe_dir / "repository_fallbacks.jsonl")
    fallback_by_repo = {str(row["repository_identity"]): row for row in fallback_rows}
    priority_masks: dict[str, int] = {}
    for repository, roots in root_by_repo.items():
        mask = 0
        for root in roots:
            if root["priority_class"] == ROOT_PRIORITY:
                index = root.get("bit_index")
                if not isinstance(index, int) or isinstance(index, bool) or index < 0:
                    raise SystemExit("source-root bit index is malformed")
                mask |= 1 << index
        priority_masks[repository] = mask

    args.output_dir.mkdir(parents=True, exist_ok=False)
    compressed_path = args.output_dir / "commit_priorities.jsonl.gz"
    temporary_path = args.output_dir / ".commit_priorities.jsonl.gz.tmp"
    logical_digest = hashlib.sha256()
    counts: Counter[str] = Counter()
    repository_counts: defaultdict[str, Counter[str]] = defaultdict(Counter)
    repository_totals: Counter[str] = Counter()
    seen_commits: set[tuple[str, str]] = set()
    try:
        with (
            (args.universe_dir / "commit_universe.jsonl").open(encoding="utf-8") as source,
            gzip.open(temporary_path, "wt", encoding="utf-8", compresslevel=6) as output,
        ):
            for line_number, line in enumerate(source, start=1):
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise SystemExit(f"commit universe row {line_number} is malformed")
                repository = str(raw.get("repository_identity") or "")
                sha = str(raw.get("sha") or "")
                key = (repository, sha)
                if key in seen_commits or repository not in fallback_by_repo:
                    raise SystemExit("commit universe conservation failed")
                seen_commits.add(key)
                root_mask = membership.pop(key, 0)
                priority = commit_priority(
                    observed_ai_unit=raw.get("observed_ai_unit") is True,
                    root_mask=root_mask,
                    priority_root_mask=priority_masks.get(repository, 0),
                )
                row = {
                    "repository_identity": repository,
                    "sha": sha,
                    "priority_class": priority,
                    "root_mask_hex": format(root_mask, "x"),
                    "observed_ai_unit": raw.get("observed_ai_unit") is True,
                    "repository_universe_status": fallback_by_repo[repository]["status"],
                    "retained": True,
                }
                encoded = (
                    json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n"
                ).encode("utf-8")
                logical_digest.update(encoded)
                output.write(encoded.decode("utf-8"))
                counts[priority] += 1
                repository_counts[repository][priority] += 1
                repository_totals[repository] += 1
        if membership:
            raise SystemExit("root membership references commits outside the universe")
        os.replace(temporary_path, compressed_path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass

    repository_rows = []
    for repository in sorted(fallback_by_repo):
        fallback = fallback_by_repo[repository]
        expected = int(fallback["candidate_commit_count"])
        observed = repository_totals[repository]
        if observed != expected:
            raise SystemExit(f"repository fallback count mismatch: {repository}")
        repository_rows.append(
            {
                "repository_identity": repository,
                "universe_id": fallback["universe_id"],
                "universe_status": fallback["status"],
                "commit_count": observed,
                "priority_counts": dict(sorted(repository_counts[repository].items())),
                "all_commits_retained": True,
            }
        )
    total = sum(counts.values())
    expected_total = sum(int(row["candidate_commit_count"]) for row in fallback_rows)
    if total != expected_total or total != len(seen_commits):
        raise SystemExit("campaign commit conservation failed")

    root_text = _jsonl_text(root_priorities)
    repository_text = _jsonl_text(repository_rows)
    (args.output_dir / "root_priorities.jsonl").write_text(root_text, encoding="utf-8")
    (args.output_dir / "repository_queues.jsonl").write_text(
        repository_text, encoding="utf-8"
    )
    summary = {
        "schema_version": 1,
        "artifact_kind": "recall_preserving_origin_priority_overlay",
        "gate_status": "READY_FOR_BOUNDED_ORIGIN_ROUTING",
        "commit_count": total,
        "root_count": len(root_priorities),
        "priority_root_count": sum(
            row["priority_class"] == ROOT_PRIORITY for row in root_priorities
        ),
        "commit_priority_counts": dict(sorted(counts.items())),
        "all_repository_fallbacks_retained": True,
        "model_output_used_only_for_priority": True,
        "hard_filter_count": 0,
        "blocked_repository_count": sum(
            row["status"] == "BLOCKED" for row in fallback_rows
        ),
        "claim_boundary": (
            "Priority classes schedule evidence collection only. Every commit from "
            "every frozen repository fallback occurs exactly once; an unlabeled, "
            "unreachable, or incomplete-history commit is never converted to a "
            "negative."
        ),
        "commit_priority_rows_sha256": logical_digest.hexdigest(),
        "compressed_file_sha256": _sha256_file(compressed_path),
        "root_priorities_sha256": canonical_sha256(root_priorities),
        "repository_queues_sha256": canonical_sha256(repository_rows),
        "input_provenance": {
            "commit_universe_sha256": _sha256_file(
                args.universe_dir / "commit_universe.jsonl"
            ),
            "root_membership_sha256": _sha256_file(
                args.source_replay_dir / "root_membership.jsonl"
            ),
            "source_roots_sha256": _sha256_file(
                args.source_replay_dir / "source_roots.jsonl"
            ),
            "sealed_map_sha256": _sha256_file(
                args.packet_dir / "sealed_candidate_map.json"
            ),
            "score_sha256": _sha256_file(args.score),
        },
    }
    _atomic_json(args.output_dir / "summary.json", summary)
    print("recall-preserving origin priority overlay frozen")
    print(f"  commits retained      : {total:,}")
    print(f"  source roots retained : {len(root_priorities)}")
    print(f"  priority roots        : {summary['priority_root_count']}")
    print("  hard filters          : 0")
    print(f"  compressed bytes      : {compressed_path.stat().st_size:,}")
    print(f"  output                : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
